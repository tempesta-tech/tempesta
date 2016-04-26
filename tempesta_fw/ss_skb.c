/**
 *		Tempesta FW
 *
 * Helpers for Linux socket buffers manipulation.
 *
 * Application protocol handler layers must inplement zero data copy logic
 * on top on native Linux socket buffers. The helpers provide common and
 * convenient wrappers for skb processing.
 *
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "addr.h"
#include "ss_skb.h"

/**
 * Get @skb's source address and port as a string, e.g. "127.0.0.1", "::1".
 *
 * Only the source IP address is printed to @out_buf, and the TCP/SCTP
 * port is not printed. That is done because:
 *  - Less output bytes means more chance for fast path in __hdr_add().
 *  - RFC7239 says the port is optional.
 *  - Most proxy servers don't put it to the field.
 *  - Usually you get a random port of an outbound connection there,
 *    so the value is likely useless.
 * If at some point we will need the port, then the fix should be trivial:
 * just get it with tcp_hdr(skb)->src (or sctp_hdr() for SPDY).
 */
char *
ss_skb_fmt_src_addr(const struct sk_buff *skb, char *out_buf)
{
	const struct iphdr *ih4 = ip_hdr(skb);
	const struct ipv6hdr *ih6 = ipv6_hdr(skb);

	if (ih6->version == 6)
		return tfw_addr_fmt_v6(&ih6->saddr, 0, out_buf);

	return tfw_addr_fmt_v4(ih4->saddr, 0, out_buf);
}

/**
 * Allocate a new skb that can hold @len bytes of data.
 *
 * An SKB is created complely headerless. The linear part of an SKB is
 * set apart for headers, and stream data is placed in paged fragments.
 * Lower layers will take care of prepending all required headers.
 *
 * Similar to alloc_skb_with_frags() except it doesn't allocate multi-page
 * fragments, and it sets up fragments with zero size.
 */
struct sk_buff *
ss_skb_alloc_pages(size_t len)
{
	int i, nr_frags = DIV_ROUND_UP(len, PAGE_SIZE);
	struct sk_buff *skb;

	BUG_ON(nr_frags > MAX_SKB_FRAGS);

	if ((skb = ss_skb_alloc()) == NULL)
		return NULL;

	for (i = 0; i < nr_frags; ++i) {
		struct page *page = alloc_page(GFP_ATOMIC);
		if (!page) {
			kfree_skb(skb);
			return NULL;
		}
		skb_fill_page_desc(skb, i, page, 0, 0);
		TFW_DBG3("Created new frag %d,%p for skb %p\n",
			 i, page_address(page), skb);
	}

	return skb;
}

static inline int
ss_skb_frag_len(skb_frag_t *frag)
{
	return frag->page_offset + frag->size;
}

/**
 * Scan paged fragments array for fragments placed in the same page
 * with @frag and check if the page has enough room to add @len bytes.
 * The fragments are scanned until @refcnt reaches zero. Otherwise,
 * the page is in use outside of the SKB, so give up on checking it.
 * @return pointer to the last fragment in the page.
 */
static skb_frag_t *
__check_frag_room(struct sk_buff *skb, skb_frag_t *frag, int len)
{
	int i, sz, sz2, refcnt;
	struct page *pg = skb_frag_page(frag);
	skb_frag_t *frag2, *ret = frag;

	if ((refcnt = page_count(pg)) == 1)
		return frag; /* no other users */

	sz = PAGE_SIZE - ss_skb_frag_len(frag);
	for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0 ; --i) {
		frag2 = &skb_shinfo(skb)->frags[i];
		if (frag2 == frag || pg != skb_frag_page(frag2))
			continue;
		sz2 = PAGE_SIZE - ss_skb_frag_len(frag2);
		if (sz2 < len)
			return NULL;
		if (sz2 < sz) {
			sz = sz2;
			ret = frag2;
		}
		/* Return localy referenced pages only. */
		if (--refcnt == 1)
			return ret;
	}

	/* The page is used outside of this SKB. */
	return NULL;
}

/**
 * Look up a page fragment that has room for @len bytes.
 */
static skb_frag_t *
__lookup_pgfrag_room(struct sk_buff *skb, int len)
{
	int i;

	/*
	 * Iterate in reverse order to use likely moving fragments.
	 * Thus we find free room more frequently and skb fragments
	 * utilize memory limits better.
	 */
	for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; --i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		if ((int)PAGE_SIZE - ss_skb_frag_len(frag) < len)
			continue;
		frag = __check_frag_room(skb, frag, len);
		if (frag)
			return frag;
	}

	return NULL;
}

/**
 * Somewhat like skb_shift().
 * Make room for @n fragments starting with slot @from.
 *
 * Beware: @from can be equal to MAX_SKB_FRAGS when a new fragment
 * is inserted after the last one.
 *
 * @return 0 on success, -errno on failure.
 * @return New SKB in @it->skb if new SKB is allocated.
 */
static int
__extend_pgfrags(struct sk_buff *skb, int from, int n, TfwStr *it)
{
	int i, n_shift, n_excess = 0;
	struct skb_shared_info *si = skb_shinfo(skb);

	BUG_ON(from > si->nr_frags);

	/* No room for @n extra page fragments in the SKB. */
	if (si->nr_frags + n > MAX_SKB_FRAGS) {
		skb_frag_t *f;
		struct sk_buff *nskb;

		/* Allocate a new SKB to hold @n_excess page fragments. */
		nskb = alloc_skb(0, GFP_ATOMIC);
		if (nskb == NULL)
			return -ENOMEM;

		/*
		 * The number of page fragments that don't fit in the SKB
		 * after the room is prepared for @n page fragments.
		 */
		n_excess = si->nr_frags + n - MAX_SKB_FRAGS;

		/* Shift @n_excess number of page fragments to new SKB. */
		if (from < si->nr_frags) {
			for (i = n_excess - 1; i >= 0; --i) {
				f = &si->frags[MAX_SKB_FRAGS - n + i];
				skb_shinfo(nskb)->frags[i] = *f;
				ss_skb_adjust_data_len(skb, -skb_frag_size(f));
				ss_skb_adjust_data_len(nskb, skb_frag_size(f));
			}
		}
		skb_shinfo(nskb)->nr_frags += n_excess;
		it->skb = nskb;
	}

	/* Make room for @n page fragments in the SKB. */
	n_shift = si->nr_frags - from - n_excess;
	BUG_ON(n_shift < 0);
	if (n_shift)
		memmove(&si->frags[from + n],
			&si->frags[from], n_shift * sizeof(skb_frag_t));
	si->nr_frags += n - n_excess;

	return 0;
}

/*
 * Make room for @shift fragments starting with slot @i. Then make
 * a new fragment in slot @i that can hold @size bytes, and it set up.
 */
static int
__new_pgfrag(struct sk_buff *skb, int size, int i, int shift, TfwStr *it)
{
	int off = 0;
	struct page *page = NULL;
	skb_frag_t *frag;

	BUG_ON(i > MAX_SKB_FRAGS);

	/*
	 * Try to find room for @size bytes in SKB fragments.
	 * If none found, then allocate a new page for the fragment.
	 */
	frag = __lookup_pgfrag_room(skb, size);
	if (frag) {
		page = skb_frag_page(frag);
		off = ss_skb_frag_len(frag);
		__skb_frag_ref(frag);	/* get_page(page); */
	} else {
		page = alloc_page(GFP_ATOMIC);
		if (!page)
			return -ENOMEM;
	}

	/* Make room for @shift fragments starting with slot @i. */
	if (__extend_pgfrags(skb, i, shift, it)) {
		if (frag)
			__skb_frag_unref(frag);	/* put_page(page); */
		else
			__free_page(page);
		return -ENOMEM;
	}

	/*
	 * When the requested slot is right outside the range of the
	 * array of paged fragments, then the new fragment is put as
	 * the first fragment of the next SKB.
	 */
	if (i == MAX_SKB_FRAGS) {
		i = 0;
		skb = it->skb;
	}

	/* Set up the new fragment in slot @i to hold @size bytes. */
	__skb_fill_page_desc(skb, i, page, off, size);
	ss_skb_adjust_data_len(skb, size);

	return 0;
}

/**
 * The kernel may allocate a bit more memory for an SKB than what was
 * requested (see ksize() call in __alloc_skb()). Use the extra memory
 * if it's enough to hold @n bytes. Otherwise, allocate new linear data.
 *
 * @return 0 on success, -errno on failure.
 * @return SKB in @it->skb if new SKB is allocated.
 * @return pointer to the room for new data in @it->ptr if making room.
 * @return pointer to data right after the deleted fragment in @it->ptr.
 */
static int
__split_linear_data(struct sk_buff *skb, char *pspt, int len, TfwStr *it)
{
	int alloc = len > 0;
	int tail_len = (char *)skb_tail_pointer(skb) - pspt;
	struct page *page = virt_to_head_page(skb->head);

	SS_DBG("[%d]: %s: skb [%p] pspt [%p] len [%d] tail_len [%d]\n",
		smp_processor_id(), __func__, skb, pspt, len, tail_len);
	BUG_ON(!skb->head_frag);
	BUG_ON(tail_len <= 0);
	BUG_ON(!(alloc | tail_len));
	BUG_ON(-len > tail_len);

	/*
	 * Quick and unlikely path: just advance the skb tail pointer.
	 * Note that this only works when we make room. When we remove,
	 * pspt points at the start of the data chunk to remove. In that
	 * case, tail_len can never be zero.
	 */
	if (unlikely(!tail_len && len <= ss_skb_tailroom(skb))) {
		it->ptr = ss_skb_put(skb, len);
		return 0;
	}
	/*
	 * Quick and unlikely path: just move skb tail pointer backward.
	 * Note that this only works when we remove data, and the data
	 * is located exactly at the end of the linear part of an skb.
	 */
	if (unlikely((len < 0) && (tail_len == -len))) {
		ss_skb_put(skb, len);
		if (skb_is_nonlinear(skb))
			it->ptr = skb_frag_address(&skb_shinfo(skb)->frags[0]);
		return 0;
	}

	/*
	 * Data is inserted or deleted in the middle of the linear part,
	 * or there's insufficient room in the linear part of an SKB to
	 * insert @len bytes.
	 *
	 * Don't bother with skb tail room: if the linear part is large,
	 * then it's likely that we'll do some smaller data insertions
	 * later and go by the quick path above. Otherwise, the tail size
	 * is also small.
	 *
	 * The inserted data is placed in a fragment. The tail part is
	 * moved to yet another fragment. The linear part is trimmed to
	 * exclude the deleted data and the tail part.
	 *
	 * Do all allocations before moving the fragments to avoid complex
	 * rollback.
	 */
	if (alloc) {
		if (__new_pgfrag(skb, len, 0, alloc + !!tail_len, it))
			return -EFAULT;
	} else {
		if (__extend_pgfrags(skb, 0, 1, it))
			return -EFAULT;
		tail_len += len;	/* @len is negative. */
	}

	if (tail_len) {
		int tail_off = pspt - (char *)page_address(page);

		/*
		 * Trim the linear part by |@len| bytes if data
		 * is deleted. Then trim it further to exclude
		 * the tail data. Finally, set up the fragment
		 * allotted above with the tail data.
		 */
		if (len < 0) {
			tail_off -= len;
			skb->tail += len;
			skb->len += len;
		}
		skb->tail -= tail_len;
		skb->data_len += tail_len;
		skb->truesize += tail_len;

		__skb_fill_page_desc(skb, alloc, page, tail_off, tail_len);
		skb_frag_ref(skb, alloc);	/* get_page(page); */
	}

	it->ptr = skb_frag_address(&skb_shinfo(skb)->frags[0]);
	return 0;
}

/**
 * Get room for @len bytes of data starting from offset @off
 * in fragment @i.
 *
 * The room may be found in the preceding fragment if @off is zero.
 * Otherwise, a new fragment is allocated and fragments around the
 * fragment @i are rearranged so that data is not actually split
 * and copied.
 *
 * Note: @off is always within the borders of fragment @i. It can
 * point at the start of a fragment, but it can never point at the
 * location right after the end of a fragment. In other words, @off
 * can be zero, but it can not be equal to the size of fragment @i.
 *
 * @return 0 on success, -errno on failure.
 * @return SKB in @it->skb if new SKB is allocated.
 * @return pointer to the room for new data in @it->ptr.
 * @return @it->flags is set if @it->ptr points to data in it->skb.
 */
static int
__split_pgfrag_add(struct sk_buff *skb, int i, int off, int len, TfwStr *it)
{
	int tail_len;
	struct sk_buff *skb_dst;
	skb_frag_t *frag_dst, *frag = &skb_shinfo(skb)->frags[i];

	SS_DBG("[%d]: %s: skb [%p] i [%d] off [%d] len [%d] fragsize [%d]\n",
		smp_processor_id(), __func__,
		skb, i, off, len, skb_frag_size(frag));
	/*
	 * If @off is zero and there's a preceding page fragment,
	 * then try to append data to that fragment. Go for other
	 * solutions if there's no room.
	 */
	if (!off && i) {
		frag_dst = __check_frag_room(skb, frag - 1, len);
		if (frag_dst) {
			/* Coalesce new data with the fragment. */
			off = skb_frag_size(frag_dst);
			skb_frag_size_add(frag_dst, len);
			ss_skb_adjust_data_len(skb, len);
			it->ptr = (char *)skb_frag_address(frag_dst) + off;
			return 0;
		}
	}

	/*
	 * Make a fragment that can hold @len bytes. If @off is
	 * zero, then data is added at the start of fragment @i.
	 * Make a fragment in slot @i, and the original fragment
	 * is shifted forward. If @off is not zero, then make
	 * a fragment in slot @i+1, and make an extra fragment
	 * in slot @i+2 to hold the tail data.
	 */
	if (__new_pgfrag(skb, len, i + !!off, 1 + !!off, it))
		return -EFAULT;

	/* If @off is zero, the job is done in __new_pgfrag(). */
	if (!off) {
		it->ptr = skb_frag_address(frag);
		return 0;
	}

	/*
	 * If data is added in the middle of a fragment, then split
	 * the fragment. The head of the fragment stays there, and
	 * the tail of the fragment is moved to a new fragment.
	 * The fragment for new data is placed in between.
	 * [frag @i] [frag @i+1 - new data] [frag @i+2 - tail data]
	 * If @i is close to MAX_SKB_FRAGS, then new fragments may
	 * be located in another SKB.
	 */

	/* Find the SKB for tail data. */
	skb_dst = (i < MAX_SKB_FRAGS - 2) ? skb : it->skb;

	/* Calculate the length of the tail part. */
	tail_len = skb_frag_size(frag) - off;

	/* Trim the fragment with the head part. */
	skb_frag_size_sub(frag, tail_len);

	/* Make the fragment with the tail part. */
	i = (i + 2) % MAX_SKB_FRAGS;
	__skb_fill_page_desc(skb_dst, i, skb_frag_page(frag),
			     frag->page_offset + off, tail_len);
	__skb_frag_ref(frag);

	/* Adjust SKB data lengths. */
	if (skb != skb_dst) {
		ss_skb_adjust_data_len(skb, -tail_len);
		ss_skb_adjust_data_len(skb_dst, tail_len);
	}

	/* Get the SKB and the address for new data. */
	it->flags = !(i < MAX_SKB_FRAGS - 1);
	frag_dst = it->flags ? &skb_shinfo(it->skb)->frags[0] : frag + 1;
	it->ptr = skb_frag_address(frag_dst);

	return 0;
}

/**
 * Delete @len (the value is positive now) bytes from @frag.
 *
 * @return 0 on success, -errno on failure.
 * @return SKB in @it->skb if new SKB is allocated.
 * @return pointer to data after the deleted area in @it->ptr.
 * @return @it->flags is set if @it->ptr points to data in it->skb.
 */
static int
__split_pgfrag_del(struct sk_buff *skb, int i, int off, int len, TfwStr *it)
{
	int tail_len;
	struct sk_buff *skb_dst;
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
	struct skb_shared_info *si = skb_shinfo(skb);

	SS_DBG("[%d]: %s: skb [%p] i [%d] off [%d] len [%d] fragsize [%d]\n",
		smp_processor_id(), __func__,
		skb, i, off, len, skb_frag_size(frag));

	if (unlikely(off + len > skb_frag_size(frag))) {
		SS_WARN("Attempt to delete too much\n");
		return -EFAULT;
	}

	/* Fast path: delete a full fragment. */
	if (!off && len == skb_frag_size(frag)) {
		ss_skb_adjust_data_len(skb, -len);
		__skb_frag_unref(frag);
		if (i + 1 < si->nr_frags)
			memmove(&si->frags[i], &si->frags[i + 1],
				(si->nr_frags - i - 1) * sizeof(skb_frag_t));
		--si->nr_frags;
		goto lookup_next_ptr;
	}
	/* Fast path: delete the head part of a fragment. */
	if (!off) {
		frag->page_offset += len;
		skb_frag_size_sub(frag, len);
		ss_skb_adjust_data_len(skb, -len);
		it->ptr = skb_frag_address(frag);
		return 0;
	}
	/* Fast path: delete the tail part of a fragment. */
	if (off + len == skb_frag_size(frag)) {
		skb_frag_size_sub(frag, len);
		ss_skb_adjust_data_len(skb, -len);
		++i;
		goto lookup_next_ptr;
	}

	/*
	 * Delete data in the middle of a fragment. After the data
	 * is deleted the fragment will contain only the head part,
	 * and the tail part is moved to another fragment.
	 * [frag @i] [frag @i+1 - tail data]
	 *
	 * Make room for a fragment right after the @i fragment
	 * to move the tail part of data there.
	 */
	if (__extend_pgfrags(skb, i + 1, 1, it))
		return -EFAULT;

	/* Find the SKB for tail data. */
	skb_dst = (i < MAX_SKB_FRAGS - 1) ? skb : it->skb;

	/* Calculate the length of the tail part. */
	tail_len = skb_frag_size(frag) - off - len;

	/* Trim the fragment with the head part. */
	skb_frag_size_sub(frag, len + tail_len);

	/* Make the fragment with the tail part. */
	i = (i + 1) % MAX_SKB_FRAGS;
	__skb_fill_page_desc(skb_dst, i, skb_frag_page(frag),
			     frag->page_offset + off + len, tail_len);
	__skb_frag_ref(frag);

	/* Adjust SKB data lengths. */
	ss_skb_adjust_data_len(skb, -len);
	if (skb != skb_dst) {
		ss_skb_adjust_data_len(skb, -tail_len);
		ss_skb_adjust_data_len(skb_dst, tail_len);
	}

	/* Get the SKB and the address of data after the deleted area. */
	it->flags = (skb != skb_dst);
	it->ptr = skb_frag_address(&skb_shinfo(skb_dst)->frags[i]);
	return 0;

lookup_next_ptr:
	/* Get the next fragment after the deleted fragment. */
	if (i < si->nr_frags)
		it->ptr = skb_frag_address(&si->frags[i]);
	return 0;
}

static int
__split_pgfrag(struct sk_buff *skb, int i, int off, int len, TfwStr *it)
{
	return len > 0
		? __split_pgfrag_add(skb, i, off, len, it)
		: __split_pgfrag_del(skb, i, off, -len, it);
}

/*
 * Determine the address of data in @skb.
 *
 * Note that @skb is not expected to have
 * SKB fragments without page fragments.
 */
static inline void *
ss_skb_data_address(struct sk_buff *skb)
{
	if (skb == NULL)
		return NULL;
	if (skb_headlen(skb))
		return skb->data;
	BUG_ON(!skb_is_nonlinear(skb));
	BUG_ON(!skb_shinfo(skb)->nr_frags);
	return skb_frag_address(&skb_shinfo(skb)->frags[0]);
}

/**
 * Fragment @skb to add some room if @len > 0 or delete data otherwise.
 */
static int
__skb_fragment(struct sk_buff *skb, struct sk_buff *pskb,
	       char *pspt, int len, TfwStr *it)
{
	int ret;
	unsigned int i, d_size, offset;
	struct sk_buff *f_skb, **next_fdp;

	SS_DBG("[%d]: %s: in: len [%d] pspt [%p], skb [%p]: head [%p]"
		" data [%p] tail [%p] end [%p] len [%u] data_len [%u]"
		" truesize [%u] nr_frags [%u]\n",
		smp_processor_id(), __func__, len, pspt, skb, skb->head,
		skb->data, skb_tail_pointer(skb), skb_end_pointer(skb),
		skb->len, skb->data_len, skb->truesize,
		skb_shinfo(skb)->nr_frags);
	BUG_ON(!len);

	if ((len > (int)PAGE_SIZE) || (-len > (int)PAGE_SIZE)) {
		SS_WARN("Attempt to add or delete too much data: %u\n", len);
		return -EINVAL;
	}

	/*
	 * Use @it to hold the return values from __split_pgfrag()
	 * and __split_linear_data(). @it->ptr, @it->skb, and
	 * @it->flags may be set to actual values. If a new SKB is
	 * allocated, then it is stored in @it->skb. @it->ptr holds
	 * the pointer either to data after the deleted data, or to
	 * the area for new data. @it->flags is set when @it->ptr
	 * points to data in @it->skb. Otherwise, @it->ptr points
	 * to data in @skb.
	 *
	 * Determine where the split begins within the SKB, then do
	 * the job using the right function.
	 */

	/* See if the split starts in the linear data. */
	d_size = skb_headlen(skb);
	offset = pspt - (char *)skb->data;

	if ((offset >= 0) && (offset < d_size)) {
		int t_size = d_size - offset;
		/* This affects only negative @len. */
		len = (-len <= t_size) ? len : -t_size;
		ret = __split_linear_data(skb, pspt, len, it);
		goto done;
	}

	/* See if the split starts in the page fragments data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		d_size = skb_frag_size(frag);
		offset = pspt - (char *)skb_frag_address(frag);

		if ((offset >= 0) && (offset < d_size)) {
			int t_size = d_size - offset;
			/* This affects only negative @len. */
			len = (-len <= t_size) ? len : -t_size;
			ret = __split_pgfrag(skb, i, offset, len, it);
			goto done;
		}
	}

	/* See if the split starts in the SKB fragments data. */
	skb_walk_frags(skb, f_skb) {
		ret = __skb_fragment(f_skb, skb, pspt, len, it);
		if (ret != -ENOENT)
			return ret;
	}

	/* The split is not within the SKB. */
	return -ENOENT;

done:
	SS_DBG("[%d]: %s: out: res [%p], skb [%p]: head [%p] data [%p]"
		" tail [%p] end [%p] len [%u] data_len [%u]"
		" truesize [%u] nr_frags [%u]\n",
		smp_processor_id(), __func__, it->ptr, skb, skb->head,
		skb->data, skb_tail_pointer(skb), skb_end_pointer(skb),
		skb->len, skb->data_len, skb->truesize,
		skb_shinfo(skb)->nr_frags);

	if (ret < 0)
		return ret;

	/* An indirect/double pointer to the next SKB fragment. */
	next_fdp = pskb ? &skb->next : &skb_shinfo(skb)->frag_list;
	/*
	 * If a new SKB was allocated while mangling @skb data, then
	 * insert it at the correct location in the list of fragments
	 * of the parent SKB. If @skb is one of the fragments, then
	 * insert the new SKB after @skb in the frag_list. Otherwise,
	 * insert the new SKB as the first fragment.
	 */
	if (it->skb) {
		it->skb->next = *next_fdp;
		*next_fdp = it->skb;
	}
	/*
	 * The returned SKB can be the top-level SKB, or it can be
	 * one of the SKB fragments.
	 *
	 * If the address of data has not been determined, then it
	 * is located either in the next fragment or in the next SKB.
	 * Otherwise, it's definitely in one of the SKB fragments.
	 */
	if (it->ptr == NULL) {
		BUG_ON(it->skb);
		it->skb = *next_fdp ? : ss_skb_next(pskb ? : skb);
		it->ptr = ss_skb_data_address(it->skb);
		if (it->ptr == NULL)
			return -EFAULT;
	} else if (it->flags == 0) {
		it->skb = skb;
	}
	it->len = len;
	it->flags = 0;
	BUG_ON(it->skb == NULL);

	/* Return the length of processed data. */
	return (len > 0 ? len : -len);
}

/**
 * Get room for @len bytes in @skb just before @pspt.
 *
 * SKBs that are generated locally must not be passed to the function.
 * Instead, these SKBs must be set up with complete HTTP message headers
 * without the need for further modifications.
 */
int
ss_skb_get_room(struct sk_buff *skb, char *pspt, unsigned int len, TfwStr *it)
{
	int r = __skb_fragment(skb, NULL, pspt, len, it);
	if (r == len)
		return 0;
	return r;
}

/**
 * Cut off @hdr->len data bytes from underlying skbs skipping the first
 * @skip bytes, and also cut off @tail bytes after @hdr.
 */
int
ss_skb_cutoff_data(const TfwStr *hdr, int skip, int tail)
{
	int r;
	TfwStr it;
	const TfwStr *c, *end;

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (c->len <= skip) {
			skip -= c->len;
			continue;
		}
		memset(&it, 0, sizeof(TfwStr));
		r = __skb_fragment(c->skb, NULL,
				   (char *)c->ptr + skip, skip - c->len, &it);
		if (r < 0)
			return r;
		BUG_ON(r != c->len - skip);
		skip = 0;
	}

	/* Cut off the tail. */
	while (tail) {
		void *f_ptr = it.ptr;
		struct sk_buff *f_skb = it.skb;
		BUG_ON(f_ptr == NULL);
		BUG_ON(f_skb == NULL);
		memset(&it, 0, sizeof(TfwStr));
		r = __skb_fragment(f_skb, NULL, f_ptr, -tail, &it);
		if (r < 0) {
			SS_WARN("Cannot delete hdr tail\n");
			return r;
		}
		BUG_ON(r > tail);
		tail -= r;
	}

	return 0;
}

/**
 * Process a socket buffer.
 * See standard skb_copy_datagram_iovec() implementation.
 * @return SS_OK, SS_DROP, SS_POSTPONE, or a negative value of error code.
 *
 * The function is unaware of an application layer, but it still splits
 * @skb into messages. If @actor returns POSTPONE and there is more data
 * in @skb, then the function continues to process the @skb. Otherwise
 * it returns, thus allowing an upper layer to process a full message
 * or an error code. @off is used as an iterator between function calls
 * over the same @skb.
 *
 * FIXME it seems standard skb_seq_read() does the same.
 */
int
ss_skb_process(struct sk_buff *skb, unsigned int *off,
	       ss_skb_actor_t actor, void *objdata)
{
	int i, r = SS_OK;
	int headlen = skb_headlen(skb);
	unsigned int offset = *off;

	/* Process linear data. */
	if (offset < headlen) {
		*off = headlen;
		r = actor(objdata, skb->data + offset, headlen - offset);
		if (r != SS_POSTPONE)
			return r;
		offset = 0;
	} else {
		offset -= headlen;
	}

	/*
	 * Process paged fragments. This is where GROed data is placed.
	 * See ixgbe_fetch_rx_buffer() and tcp_gro_receive().
	 */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int frag_size = skb_frag_size(frag);
		if (offset < frag_size) {
			unsigned char *frag_addr = skb_frag_address(frag);
			*off += frag_size - offset;
			r = actor(objdata, frag_addr + offset,
					   frag_size - offset);
			if (r != SS_POSTPONE)
				return r;
			offset = 0;
		} else {
			offset -= frag_size;
		}
	}

	/*
	 * If paged fragments are full, in case of GRO skb_gro_receive()
	 * adds SKBs to frag_list from gro_list. However, SKBs that have
	 * frag_list are split into separate SKBs before they get to
	 * Tempesta for processing.
	 */
	BUG_ON(skb_has_frag_list(skb));

	return r;
}
EXPORT_SYMBOL(ss_skb_process);

/*
 * Split @skb in two at a given offset. The original SKB is shrunk
 * to specified size @len, and the remaining data is put into a new SKB.
 *
 * The implementation is very much like tcp_fragment() or tso_fragment()
 * in the Linux kernel. The major difference is that these SKBs were just
 * taken out of the receive queue, and they have been orphaned. They have
 * not been out to the write queue yet.
 */
struct sk_buff *
ss_skb_split(struct sk_buff *skb, int len)
{
	struct sk_buff *buff;
	int nsize, asize, nlen;

	/* Assert that the SKB is orphaned. */
	BUG_ON(skb->destructor);

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;
	asize = ALIGN(nsize, 4);

	buff = alloc_skb_fclone(asize + MAX_TCP_HEADER, GFP_ATOMIC);
	if (buff == NULL)
		return NULL;

	skb_reserve(buff, MAX_TCP_HEADER);
	/* Make sure there's exactly asize bytes available. */
	buff->reserved_tailroom = buff->end - buff->tail - asize;

	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/*
	 * These are orphaned SKBs that are taken out of the TCP/IP
	 * stack and are completely owned by Tempesta. There is no
	 * need to correct the sequence numbers, adjust TCP flags,
	 * or recalculate the checksum.
	 */
	skb_split(skb, buff, len);

	return buff;
}
