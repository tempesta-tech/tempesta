/**
 *		Tempesta FW
 *
 * Helpers for Linux socket buffers manipulation.
 *
 * Application protocol handler layers must inplement zero data copy logic
 * on top on native Linux socket buffers. The helpers provide common and
 * convenient wrappers for skb processing.
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include <net/xfrm.h>

#include "addr.h"
#include "procfs.h"
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
 *
 * TODO #391: use less pages by allocating the skb from ss_skb_alloc()
 * with maximum page header to fully utilize the page.
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
ss_skb_frag_len(const skb_frag_t *frag)
{
	return frag->page_offset + frag->size;
}

/**
 * Find a page that has room for @len bytes.
 * Return true if the room is found, or false otherwise.
 * If the room is found, fill @f_out that describes the location of the room.
 *
 * The assumption is that there can be sufficient room available at the
 * start or at the end of a page that holds this SKB's paged fragments.
 *
 * For a group of paged fragments located in the same page the available
 * headroom and tailroom are calculated. If @len is more than both of
 * those, then the next group of fragments and the page they're located in
 * are considered. That is repeated until all paged fragments and the
 * respective pages are checked. Of pages that do have sufficient room
 * available, only those pages that don't have users outside of this SKB
 * are suitable.
 *
 * Several notes regarding the algorithm and the underlinings:
 * - If a page is still used for allocation of fragments by one of the
 *   kernel's allocators, then that page is owned by the allocator. That
 *   page's reference count will not get down to 1 until the page is released
 *   by the allocator.
 * - Tempesta's allocator has no notion of "owning" a page that is used
 *   for allocation of fragments. These fragments are used for the SKB
 *   structure itself, as well as for skb->head. The page used for these
 *   parts of an SKB may propagate to a paged fragment when a part of the
 *   linear data is mapped to a fragment. The algorithm skips those pages to
 *   avoid an unwanted memory corruption.
 * - map[] array is used to speed up the search. Once fragments that belong
 *   in the same page are checked, there's no need to check them again in the
 *   next iteration.
 */
static bool
__lookup_pgfrag_room(const struct sk_buff *skb, int len, skb_frag_t *f_out)
{
	int i, k, refcnt;
	char map[MAX_SKB_FRAGS];
	const skb_frag_t *f_base, *f_this;
	unsigned int p_size, h_room, t_room;
	struct page *p_base, *p_skb_head = virt_to_head_page(skb->head);

	memset(map, 0, sizeof(map));

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (map[i])
			continue;

		f_base = &skb_shinfo(skb)->frags[i];
		p_base = compound_head(skb_frag_page(f_base));
		if (p_base == p_skb_head)
			continue;

		refcnt = page_count(p_base) - 1;
		p_size = PAGE_SIZE << compound_order(p_base);

		h_room = f_base->page_offset;
		t_room = p_size - ss_skb_frag_len(f_base);
		map[i] = !!(len > h_room && len > t_room);

		for (k = i + 1; refcnt && (k < skb_shinfo(skb)->nr_frags); k++) {
			if (map[k])
				continue;

			f_this = &skb_shinfo(skb)->frags[k];
			if (compound_head(skb_frag_page(f_this)) != p_base)
				continue;

			--refcnt;
			map[k] = 1;
			if (map[i])
				continue;

			h_room = min(h_room, f_this->page_offset);
			t_room = min(t_room, p_size - ss_skb_frag_len(f_this));
			map[i] = !!(len > h_room && len > t_room);
		}

		if (!refcnt && !map[i])
			goto success;
	}

	TFW_INC_STAT_BH(ss.pfl_misses);
	return false;

success:
	BUG_ON(len > h_room && len > t_room);
	f_out->page.p = p_base;
	f_out->page_offset = len > h_room ? p_size - t_room : h_room - len;
	TFW_INC_STAT_BH(ss.pfl_hits);
	return true;
}

/*
 * Determine the address of data in @skb. Note that @skb is not
 * expected to have SKB fragments.
 */
static inline void *
__skb_data_address(struct sk_buff *skb)
{
	if (skb == NULL)
		return NULL;
	if (skb_headlen(skb))
		return skb->data;
	WARN_ON_ONCE(!skb_is_nonlinear(skb));
	if (skb_shinfo(skb)->nr_frags)
		return skb_frag_address(&skb_shinfo(skb)->frags[0]);
	WARN_ON_ONCE(skb_has_frag_list(skb));
	return NULL;
}

/*
 * Set @it->ptr and @it->skb to proper values. The data should
 * be located in the paged fragment @i of @skb. If the paged
 * fragment is not there, then find the next data location.
 */
static inline void
__it_next_data(struct sk_buff *skb, int i, TfwStr *it)
{
	struct skb_shared_info *si = skb_shinfo(skb);
	if (i < si->nr_frags) {
		it->ptr = skb_frag_address(&si->frags[i]);
		it->skb = skb;
	} else {
		it->skb = skb->next;
		it->ptr = __skb_data_address(it->skb);
	}
}

/*
 * Insert @nskb in the list after @skb. Note that standard
 * kernel 'skb_insert()' function does not suit here, as it
 * works with 'sk_buff_head' structure with additional fields
 * @qlen and @lock; we don't need these fields for our skb
 * list, so a custom function had been introduced.
 */
static inline void
__skb_insert_after(struct sk_buff *skb, struct sk_buff *nskb)
{
	nskb->next = skb->next;
	nskb->prev = skb;
	nskb->next->prev = skb->next = nskb;
}

/**
 * Similar to skb_shift().
 * Make room for @n fragments starting with slot @from.
 * Note that @from can be equal to MAX_SKB_FRAGS.
 *
 * @return 0 on success, -errno on failure.
 */
static int
__extend_pgfrags(struct sk_buff *skb_head, struct sk_buff *skb, int from, int n)
{
	int i, n_shift, n_excess = 0;
	struct skb_shared_info *si = skb_shinfo(skb);

	BUG_ON((n <= 0) || (n > 2));
	BUG_ON(from > si->nr_frags);

	/* No room for @n extra page fragments in the SKB. */
	if (si->nr_frags + n > MAX_SKB_FRAGS) {
		skb_frag_t *f;
		struct sk_buff *nskb;
		unsigned int e_size = 0;

		/*
		 * The number of page fragments that don't fit in the SKB
		 * after the room is prepared for @n page fragments.
		 */
		n_excess = si->nr_frags + n - MAX_SKB_FRAGS;

		/*
		 * Use the next SKB if there's room there for @n_excess
		 * page fragments. Otherwise, allocate a new SKB to hold
		 * @n_excess page fragments.
		 */
		nskb = skb->next;
		if (nskb != skb_head && !skb_headlen(nskb)
		    && (skb_shinfo(nskb)->nr_frags <= MAX_SKB_FRAGS - n_excess))
		{
			int r = __extend_pgfrags(skb_head, nskb, 0, n_excess);
			if (r)
				return r;
		} else {
			nskb = ss_skb_alloc();
			if (nskb == NULL)
				return -ENOMEM;
			__skb_insert_after(skb, nskb);
			skb_shinfo(nskb)->nr_frags = n_excess;
		}

		/* No fragments to shift. */
		if (from == si->nr_frags)
			return 0;

		/* Shift @n_excess number of page fragments to new SKB. */
		for (i = n_excess - 1; i >= 0; --i) {
			f = &si->frags[MAX_SKB_FRAGS - n + i];
			skb_shinfo(nskb)->frags[i] = *f;
			e_size += skb_frag_size(f);
		}
		ss_skb_adjust_data_len(skb, -e_size);
		ss_skb_adjust_data_len(nskb, e_size);
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
 * a new fragment in slot @i that can hold @size bytes, and set it up.
 */
static int
__new_pgfrag(struct sk_buff *skb_head, struct sk_buff *skb, int size,
	     int i, int shift)
{
	int off = 0;
	skb_frag_t frag;
	struct page *page = NULL;

	BUG_ON(i > MAX_SKB_FRAGS);

	/*
	 * Try to find room for @size bytes in paged fragments.
	 * If none found, then allocate a new page for the fragment.
	 */
	if (__lookup_pgfrag_room(skb, size, &frag)) {
		page = skb_frag_page(&frag);
		off = frag.page_offset;
		get_page(page);
	} else {
		page = alloc_page(GFP_ATOMIC);
		if (!page)
			return -ENOMEM;
	}

	/* Make room for @shift fragments starting with slot @i. */
	if (__extend_pgfrags(skb_head, skb, i, shift)) {
		put_page(page);
		return -ENOMEM;
	}

	/*
	 * When the requested slot is right outside the range of the
	 * array of paged fragments, then the new paged fragment is
	 * placed as the first fragment of the next SKB fragment.
	 */
	if (i == MAX_SKB_FRAGS) {
		i = 0;
		skb = skb->next;
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
 * @return pointer to the room for new data in @it->ptr if making room.
 * @return pointer to data right after the deleted fragment in @it->ptr.
 * @return pointer to SKB with data at @it->ptr in @it->skb.
 */
static int
__split_linear_data(struct sk_buff *skb_head, struct sk_buff *skb, char *pspt,
		    int len, TfwStr *it)
{
	int alloc = len > 0;
	struct page *page = virt_to_head_page(skb->head);
	int tail_len = (char *)skb_tail_pointer(skb) - pspt;
	int tail_off = pspt - (char *)page_address(page);

	TFW_DBG3("[%d]: %s: skb [%p] pspt [%p] len [%d] tail_len [%d]\n",
		 smp_processor_id(), __func__, skb, pspt, len, tail_len);
	BUG_ON(!skb->head_frag);
	BUG_ON(tail_len <= 0);
	BUG_ON(!(alloc | tail_len));
	BUG_ON(-len > tail_len);

	/*
	 * Fast and unlikely path: just move skb tail pointer backward.
	 * Note that this only works when we remove data, and the data
	 * is located exactly at the end of the linear part of an skb.
	 */
	if (unlikely((len < 0) && (tail_len == -len))) {
		ss_skb_put(skb, len);
		__it_next_data(skb, 0, it);
		return 0;
	}

	/*
	 * Data is inserted or deleted in the middle of the linear part,
	 * or there's insufficient room in the linear part of an SKB to
	 * insert @len bytes.
	 *
	 * The inserted data is placed in a fragment. The tail part is
	 * moved to yet another fragment. The linear part is trimmed to
	 * exclude the deleted data and the tail part.
	 *
	 * Whether the data is deleted or inserted, the tail of the
	 * linear data needs to be moved to a new fragment. The value of
	 * @alloc tells the number of the fragment that will hold the
	 * tail of the linear data.
	 *
	 * In case of data insertion @alloc equals one.  The inserted data
	 * is placed in the first fragment (number 0) which immediately
	 * follows the linear data. The tail of the linear data is placed
	 * in the next fragment (number 1, the value of @alloc).
	 *
	 * In case of data removal @alloc equals zero. Only the fragment
	 * for the tail is needed, and that is the first fragment (number
	 * 0, the value of @alloc).
	 *
	 * Do all allocations before moving the fragments to avoid complex
	 * rollback.
	 */
	if (alloc) {
		if (__new_pgfrag(skb_head, skb, len, 0, 1 + !!tail_len))
			return -EFAULT;
	} else {
		if (__extend_pgfrags(skb_head, skb, 0, 1))
			return -EFAULT;
	}

	/*
	 * Trim the linear part by |@len| bytes if data is deleted.
	 * Then trim it further to exclude the tail data.
	 */
	if (len < 0) {
		ss_skb_put(skb, len);
		tail_len += len;
		tail_off -= len;
	}
	skb->tail -= tail_len;
	skb->data_len += tail_len;

	/* Make the fragment with the tail part. */
	__skb_fill_page_desc(skb, alloc, page, tail_off, tail_len);
	get_page(page);

	/* Prevent @skb->tail from moving forward */
	skb->tail_lock = 1;

	/*
	 * Get the SKB and the address for data. It's either
	 * the area for new data, or data after the deleted data.
	 */
	it->ptr = skb_frag_address(&skb_shinfo(skb)->frags[0]);
	it->skb = skb;

	return 0;
}

/**
 * Get room for @len bytes of data starting from offset @off
 * in fragment @i.
 *
 * New fragment is allocated and fragments around the fragment @i
 * are rearranged so that data is not actually split and copied.
 *
 * Note: @off is always within the borders of fragment @i. It can
 * point at the start of a fragment, but it can never point at the
 * location right after the end of a fragment. In other words, @off
 * can be zero, but it can not be equal to the size of fragment @i.
 *
 * @return 0 on success, -errno on failure.
 * @return pointer to the room for new data in @it->ptr.
 * @return pointer to SKB with data at @it->ptr in @it->skb.
 */
static int
__split_pgfrag_add(struct sk_buff *skb_head, struct sk_buff *skb, int i, int off,
		   int len, TfwStr *it)
{
	int tail_len;
	struct sk_buff *skb_dst, *skb_new;
	skb_frag_t *frag_dst, *frag = &skb_shinfo(skb)->frags[i];

	TFW_DBG3("[%d]: %s: skb [%p] i [%d] off [%d] len [%d] fragsize [%d]\n",
		 smp_processor_id(), __func__,
		 skb, i, off, len, skb_frag_size(frag));

	/*
	 * Make a fragment that can hold @len bytes. If @off is
	 * zero, then data is added at the start of fragment @i.
	 * Make a fragment in slot @i, and the original fragment
	 * is shifted forward. If @off is not zero, then make
	 * a fragment in slot @i+1, and make an extra fragment
	 * in slot @i+2 to hold the tail data.
	 */
	if (__new_pgfrag(skb_head, skb, len, i + !!off, 1 + !!off))
		return -EFAULT;

	/* If @off is zero, the job is done in __new_pgfrag(). */
	if (!off) {
		it->ptr = skb_frag_address(frag);
		it->skb = skb;
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

	/* New SKB is the next SKB now. */
	skb_new = skb->next;

	/* Find the SKB for tail data. */
	skb_dst = (i < MAX_SKB_FRAGS - 2) ? skb : skb_new;

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
	if (i < MAX_SKB_FRAGS - 1) {
		frag_dst = frag + 1;
	} else {
		frag_dst = &skb_shinfo(skb_new)->frags[0];
		skb = skb_new;
	}
	it->ptr = skb_frag_address(frag_dst);
	it->skb = skb;

	return 0;
}

/**
 * Delete @len (the value is positive now) bytes from @frag.
 *
 * @return 0 on success, -errno on failure.
 * @return pointer to data after the deleted data in @it->ptr.
 * @return pointer to SKB with data at @it->ptr in @it->skb.
 */
static int
__split_pgfrag_del(struct sk_buff *skb_head, struct sk_buff *skb, int i, int off,
		   int len, TfwStr *it)
{
	int tail_len;
	struct sk_buff *skb_dst;
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
	struct skb_shared_info *si = skb_shinfo(skb);

	TFW_DBG3("[%d]: %s: skb [%p] i [%d] off [%d] len [%d] fragsize [%d]\n",
		 smp_processor_id(), __func__,
		 skb, i, off, len, skb_frag_size(frag));

	if (unlikely(off + len > skb_frag_size(frag))) {
		TFW_WARN("Attempt to delete too much\n");
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
		__it_next_data(skb, i, it);
		return 0;
	}
	/* Fast path: delete the head part of a fragment. */
	if (!off) {
		frag->page_offset += len;
		skb_frag_size_sub(frag, len);
		ss_skb_adjust_data_len(skb, -len);
		it->ptr = skb_frag_address(frag);
		it->skb = skb;
		return 0;
	}
	/* Fast path: delete the tail part of a fragment. */
	if (off + len == skb_frag_size(frag)) {
		skb_frag_size_sub(frag, len);
		ss_skb_adjust_data_len(skb, -len);
		__it_next_data(skb, i + 1, it);
		return 0;
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
	if (__extend_pgfrags(skb_head, skb, i + 1, 1))
		return -EFAULT;

	/* Find the SKB for tail data. */
	skb_dst = (i < MAX_SKB_FRAGS - 1) ? skb : skb->next;

	/* Calculate the length of the tail part. */
	tail_len = skb_frag_size(frag) - off - len;

	/* Make the fragment with the tail part. */
	i = (i + 1) % MAX_SKB_FRAGS;
	__skb_fill_page_desc(skb_dst, i, skb_frag_page(frag),
			     frag->page_offset + off + len, tail_len);
	__skb_frag_ref(frag);

	/* Trim the fragment with the head part. */
	skb_frag_size_sub(frag, len + tail_len);

	/* Adjust SKB data lengths. */
	if (skb != skb_dst) {
		ss_skb_adjust_data_len(skb, -tail_len);
		ss_skb_adjust_data_len(skb_dst, tail_len);
	}
	ss_skb_adjust_data_len(skb, -len);

	/* Get the SKB and the address for data after the deleted data. */
	it->ptr = skb_frag_address(&skb_shinfo(skb_dst)->frags[i]);
	it->skb = skb_dst;

	return 0;
}

static int
__split_pgfrag(struct sk_buff *skb_head, struct sk_buff *skb, int i, int off,
	       int len, TfwStr *it)
{
	return len > 0
		? __split_pgfrag_add(skb_head, skb, i, off, len, it)
		: __split_pgfrag_del(skb_head, skb, i, off, -len, it);
}

static inline int
__split_try_tailroom(struct sk_buff *skb, int len, TfwStr *it)
{
	if (len > skb_tailroom_locked(skb))
		return -ENOSPC;
	it->ptr = ss_skb_put(skb, len);
	it->skb = skb;
	return 0;
}

/**
 * Add room for data to @skb if @len > 0 or delete data otherwise.
 * Most of the time that is done by fragmenting the @skb.
 */
static int
__skb_fragment(struct sk_buff *skb_head, struct sk_buff *skb, char *pspt,
	       int len, TfwStr *it)
{
	int i = -1, ret;
	long offset;
	unsigned int d_size;
	struct skb_shared_info *si = skb_shinfo(skb);

	TFW_DBG3("[%d]: %s: in: len [%d] pspt [%p], skb [%p]: head [%p]"
		 " data [%p] tail [%p] end [%p] len [%u] data_len [%u]"
		 " truesize [%u] nr_frags [%u]\n",
		 smp_processor_id(), __func__, len, pspt, skb, skb->head,
		 skb->data, skb_tail_pointer(skb), skb_end_pointer(skb),
		 skb->len, skb->data_len, skb->truesize, si->nr_frags);
	BUG_ON(!len);

	/*
	 * Use @it to hold the return values from __split_pgfrag()
	 * and __split_linear_data(). @it->ptr and @it->skb are set
	 * to actual values. @it->ptr holds the address either of
	 * data after the deleted data, or of the area for new data.
	 * @it->skb is the SKB where @it->ptr address is located.
	 *
	 * Determine where the split starts within the SKB, then do
	 * the job using the right function.
	 */

	/* See if the split starts in the linear data. */
	d_size = skb_headlen(skb);
	offset = pspt - (char *)skb->data;
	if (offset >= 0 && offset < d_size) {
		int t_size = d_size - offset;
		len = max(len, -t_size);
		ret = __split_linear_data(skb_head, skb, pspt, len, it);
		goto done;
	}

	/*
	 * Fast path: Data is added, and the split is right between
	 * the linear data and the first paged fragment. If there's
	 * sufficient room in the linear part of the skb, then just
	 * advance the skb tail pointer.
	 */
	if (len > 0) {
		offset = unlikely(offset == d_size) ? 0 :
			pspt - (char *)skb_frag_address(&si->frags[0]);
		if (unlikely(!offset)) {
			if (!(ret = __split_try_tailroom(skb, len, it)))
				goto done;
			goto append;
		}
	}

	/* See if the split starts in the page fragments data. */
	for (i = 0; i < si->nr_frags; ++i) {
		const skb_frag_t *frag = &si->frags[i];
		d_size = skb_frag_size(frag);
		offset = pspt - (char *)skb_frag_address(frag);

		if (offset >= 0 && offset <= d_size) {
			int t_size = d_size - offset;
			if (!t_size) {
				/*
				 * @pspt is at the end of the frag (zero tail
				 * length): append if @len > 0 or move to the
				 * next frag for deletion.
				 */
				if (len > 0)
					goto append;
				continue;
			}
			len = max(len, -t_size);
			ret = __split_pgfrag(skb_head, skb, i, offset, len, it);
			goto done;
		}
	}

	/* The split is not within the SKB. */
	return -ENOENT;

append:
	/* Add new frag in case of splitting after the last chunk */
	ret = __new_pgfrag(skb_head, skb, len, i + 1, 1);
	__it_next_data(skb, i + 1, it);

done:
	TFW_DBG3("[%d]: %s: out: res [%p], skb [%p]: head [%p] data [%p]"
		 " tail [%p] end [%p] len [%u] data_len [%u]"
		 " truesize [%u] nr_frags [%u]\n",
		 smp_processor_id(), __func__, it->ptr, skb, skb->head,
		 skb->data, skb_tail_pointer(skb), skb_end_pointer(skb),
		 skb->len, skb->data_len, skb->truesize, si->nr_frags);

	if (ret < 0)
		return ret;
	if ((it->ptr == NULL) || (it->skb == NULL))
		return -EFAULT;
	it->len = max(0, len);

	/* Return the length of processed data. */
	return abs(len);
}

static inline int
skb_fragment(struct sk_buff *skb_head, struct sk_buff *skb, char *pspt,
	     int len, TfwStr *it)
{
	if (abs(len) > PAGE_SIZE) {
		TFW_WARN("Attempt to add or delete too much data: %u\n", len);
		return -EINVAL;
	}

	/* skbs with skb fragments are not expected. */
	if (skb_has_frag_list(skb)) {
		WARN_ON(skb_has_frag_list(skb));
		return -EINVAL;
	}

	return  __skb_fragment(skb_head, skb, pspt, len, it);
}

/**
 * Get room for @len bytes in @skb just before @pspt.
 *
 * SKBs that are generated locally must not be passed to the function.
 * Instead, these SKBs must be set up with complete HTTP message headers
 * without the need for further modifications.
 */
int
ss_skb_get_room(struct sk_buff *skb_head, struct sk_buff *skb, char *pspt,
		unsigned int len, TfwStr *it)
{
	int r = skb_fragment(skb_head, skb, pspt, len, it);
	if (r == len)
		return 0;
	return r;
}

/**
 * Cut off @hdr->len data bytes from underlying skbs skipping the first
 * @skip bytes, and also cut off @tail bytes after @hdr.
 */
int
ss_skb_cutoff_data(struct sk_buff *skb_head, const TfwStr *hdr, int skip,
		   int tail)
{
	int r;
	TfwStr it = {};
	const TfwStr *c, *end;

	BUG_ON(tail < 0);
	BUG_ON((skip < 0) || (skip >= hdr->len));

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (c->len <= skip) {
			skip -= c->len;
			continue;
		}
		memset(&it, 0, sizeof(TfwStr));
		r = skb_fragment(skb_head, c->skb, (char *)c->ptr + skip,
				 skip - c->len, &it);
		if (r < 0)
			return r;
		BUG_ON(r != c->len - skip);
		skip = 0;
	}

	BUG_ON(it.ptr == NULL);
	BUG_ON(it.skb == NULL);

	/* Cut off the tail. */
	while (tail) {
		void *t_ptr = it.ptr;
		struct sk_buff *t_skb = it.skb;
		memset(&it, 0, sizeof(TfwStr));
		r = skb_fragment(skb_head, t_skb, t_ptr, -tail, &it);
		if (r < 0) {
			TFW_WARN("Cannot delete hdr tail\n");
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
ss_skb_process(struct sk_buff *skb, unsigned int *off, ss_skb_actor_t actor,
	       void *objdata)
{
	int i, r = SS_OK;
	int headlen = skb_headlen(skb);
	unsigned int offset = *off;
	struct skb_shared_info *si = skb_shinfo(skb);

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
	for (i = 0; i < si->nr_frags; ++i) {
		const skb_frag_t *frag = &si->frags[i];
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
	WARN_ON_ONCE(skb->destructor);

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

static inline int
__coalesce_frag(struct sk_buff **skb_head, skb_frag_t *frag,
		const struct sk_buff *orig_skb)
{
	struct sk_buff *skb = ss_skb_peek_tail(skb_head);

	if (!skb || skb_shinfo(skb)->nr_frags == MAX_SKB_FRAGS) {
		skb = ss_skb_alloc();
		if (!skb)
			return -ENOMEM;
		ss_skb_queue_tail(skb_head, skb);
		skb->mark = orig_skb->mark;
	}

	skb_shinfo(skb)->frags[skb_shinfo(skb)->nr_frags++] = *frag;
	ss_skb_adjust_data_len(skb, frag->size);
	__skb_frag_ref(frag);

	return 0;
}

static int
ss_skb_queue_coalesce_tail(struct sk_buff **skb_head, const struct sk_buff *skb)
{
	int i;
	skb_frag_t head_frag;
	unsigned int headlen = skb_headlen(skb);

	if (headlen) {
		BUG_ON(!skb->head_frag);
		head_frag.size = headlen;
		head_frag.page.p = virt_to_page(skb->head);
		head_frag.page_offset = skb->data -
			(unsigned char *)page_address(head_frag.page.p);
		if (__coalesce_frag(skb_head, &head_frag, skb))
			return -ENOMEM;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (__coalesce_frag(skb_head, &skb_shinfo(skb)->frags[i], skb))
			return -ENOMEM;
	}

	return 0;
}

/**
 * Tempesta makes use of the source IP address that is kept in the IP
 * header of the original skb @from. Copy the needed IP header contents to
 * the new skb @to.
 */
static inline void
__copy_ip_header(struct sk_buff *to, const struct sk_buff *from)
{
	const struct iphdr *ip4 = ip_hdr(from);
	const struct ipv6hdr *ip6 = ipv6_hdr(from);

	/*
	 * Place IP header just after link layer headers,
	 * see definitions of MAX_TCP_HEADER and MAX_IP_HDR_LEN.
	 * Note that only new skbs allocated by ss_skb_alloc() are used here,
	 * so all of them have reserved MAX_TCP_HEADER areas.
	 */
	BUG_ON(skb_headroom(to) < MAX_TCP_HEADER);
	skb_set_network_header(to, -(MAX_TCP_HEADER - MAX_HEADER));
	if (ip6->version == 6)
		memcpy(skb_network_header(to), ip6, sizeof(*ip6));
	else
		memcpy(skb_network_header(to), ip4, sizeof(*ip4));
}

/**
 * Tempesta FW forwards skbs with application and transport payload as is,
 * so initialize such skbs such that TCP/IP stack won't stumble on dirty
 * data.
 */
void
ss_skb_init_for_xmit(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	__u8 pfmemalloc = skb->pfmemalloc;

	WARN_ON_ONCE(skb->next || skb->prev);
	WARN_ON_ONCE(skb->sk);
	WARN_ON_ONCE(skb->destructor);

	if (!skb_transport_header_was_set(skb)) {
		/* Quick path for new skbs. */
		skb->ip_summed = CHECKSUM_PARTIAL;
		return;
	}

	memset(&skb->skb_mstamp, 0, sizeof(skb->skb_mstamp));
	skb->dev = NULL;
	memset(skb->cb, 0, sizeof(skb->cb));
	skb_dst_drop(skb);
#ifdef CONFIG_XFRM
	secpath_put(skb->sp);
#endif
	nf_reset(skb);
	skb->mac_len = 0;
	skb->queue_mapping = 0;
	skb->peeked = 0;
	skb->xmit_more = 0;
	memset(&skb->headers_start, 0,
	       offsetof(struct sk_buff, headers_end) -
	       offsetof(struct sk_buff, headers_start));
	skb->pfmemalloc = pfmemalloc;
	skb->mac_header = (typeof(skb->mac_header))~0U;
	skb->transport_header = (typeof(skb->transport_header))~0U;

	shinfo->tx_flags = 0;
	shinfo->gso_size = 0;
	shinfo->gso_segs = 0;
	shinfo->gso_type = 0;
	memset(&shinfo->hwtstamps, 0, sizeof(shinfo->hwtstamps));
	shinfo->tskey = 0;
	shinfo->ip6_frag_id = 0;
	shinfo->destructor_arg = NULL;

	skb->ip_summed = CHECKSUM_PARTIAL;
}

/*
 * When the original SKB is a clone then its shinfo and payload cannot be
 * modified as they are shared with other SKB users. As the SKB is unrolled,
 * new SKBs are created and filled with paged fragments that refer to the
 * paged fragments of the original SKB. Also, the linear data of each SKB
 * from @frag_list is made a paged fragment and put into a new SKB that is
 * currently filled with paged fragments.
 */
static int
ss_skb_unroll_slow(struct sk_buff **skb_head, struct sk_buff *skb)
{
	struct sk_buff *f_skb;

	if (ss_skb_queue_coalesce_tail(skb_head, skb))
		goto cleanup;

	skb_walk_frags(skb, f_skb) {
		f_skb->mark = skb->mark;
		if (ss_skb_queue_coalesce_tail(skb_head, f_skb))
			goto cleanup;
	}

	/* Copy the IP header contents to the first skb in the chain. */
	if (*skb_head)
		__copy_ip_header(*skb_head, skb);

	/* TODO: Optimize skb reallocation. Consider to place clone's shinfo
	 * right after the origal's shinfo in case space to the chunk boundary
	 * is available. It can save some allocations but keep in mind that tail
	 * locking is required in such a technique. */

	consume_skb(skb);
	return 0;

cleanup:
	ss_skb_queue_purge(skb_head);
	return -ENOMEM;
}

/*
 * When GRO is used, multiple SKBs may be merged into one big SKB. These
 * SKBs are linked in via frag_list. Interpret the big SKB as a set of
 * separate smaller SKBs for processing. Make the top SKB first as @skb_head.
 *
 * The major reason for splitting a GRO SKB is that the kernel's TCP stack
 * uses skb_split() (called from tso_fragment() or tcp_fragment()) to split
 * outgoing SKBs according to MSS. The same skb_split() is used in Tempesta
 * to split SKBs with pipelined messages. However, this function can not
 * handle frag_list fragments. Such SKBs lose data in frag_list and generally
 * get malformed.
 *
 * TODO: It's conceiveable that skb_split() can be modified to handle data
 * in frag_list. However a thorough research is required to see if such SKBs
 * are handled properly in other parts of the kernel's stack.
 *
 * Note: If GRO SKBs are kept intact, then SKB modification code in this
 * module (for HTTP headers, etc) will get significantly more complex in
 * order to keep it effective. The issue is in having direct access to SKBs
 * in frag_list, rather than to the root (parent) SKB. The proper support
 * for that will require changes in multiple places in Tempesta.
 */
int
ss_skb_unroll(struct sk_buff **skb_head, struct sk_buff *skb)
{
	struct sk_buff *prev_skb, *f_skb;

	if (unlikely(skb_cloned(skb)))
		return ss_skb_unroll_slow(skb_head, skb);

	WARN_ON_ONCE(skb->next || skb->prev);
	skb->next = skb_shinfo(skb)->frag_list;
	*skb_head = prev_skb = skb;
	skb_walk_frags(skb, f_skb) {
		if (f_skb->nohdr) {
			/*
			 * skb_gro_receive() drops reference to the SKB's header
			 * via the __skb_header_release(). So, to not break the
			 * things we must take reference back.
			 */
			f_skb->nohdr = 0;
			atomic_sub(1 << SKB_DATAREF_SHIFT,
				   &skb_shinfo(f_skb)->dataref);
		}
		/*
		 * GRO procedures for ingress packets take place in network
		 * stack before Netfilter hooks; thereby Mangle table (with
		 * MARK action) is processed only in PREROUTING chain first
		 * time. So Netfilter marks are set only for the main skb,
		 * but not for the ones from 'frag_list'. This is a problem
		 * when we track whitelist requests during HTTP processing.
		 */
		f_skb->mark = skb->mark;
		ss_skb_adjust_data_len(skb, -f_skb->len);
		f_skb->prev = prev_skb;
		prev_skb = f_skb;
	}
	(*skb_head)->prev = prev_skb;
	prev_skb->next = *skb_head;
	skb_shinfo(skb)->frag_list = NULL;

	return 0;
}

/**
 * The routine helps you to dump content of any skb.
 * It's supposed to be used for debugging purpose, so non-limited printing
 * is used.
 * BEWARE: dont' call it too frequetly.
 */
void
ss_skb_dump(struct sk_buff *skb)
{
	int i;
	struct sk_buff *f_skb;
	struct skb_shared_info *si = skb_shinfo(skb);

	TFW_LOG_NL("SKB (%p) DUMP: len=%u data_len=%u truesize=%u users=%u\n",
		   skb, skb->len, skb->data_len, skb->truesize,
		   refcount_read(&skb->users));
	TFW_LOG_NL("  head=%p data=%p tail=%x end=%x\n",
		   skb->head, skb->data, skb->tail, skb->end);
	TFW_LOG_NL("  nr_frags=%u frag_list=%p next=%p prev=%p\n",
		   si->nr_frags, skb_shinfo(skb)->frag_list,
		   skb->next, skb->prev);
	TFW_LOG_NL("  head data (%u):\n", skb_headlen(skb));
	print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1,
		       skb->data, skb_headlen(skb), true);

	for (i = 0; i < si->nr_frags; ++i) {
		const skb_frag_t *f = &si->frags[i];
		TFW_LOG_NL("  frag %d (addr=%p pg_off=%u size=%u pg_ref=%d):\n",
			   i, skb_frag_address(f), f->page_offset,
			   skb_frag_size(f), page_ref_count(skb_frag_page(f)));
		print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1,
			       skb_frag_address(f), skb_frag_size(f), true);
	}

	skb_walk_frags(skb, f_skb)
		ss_skb_dump(f_skb);
}
EXPORT_SYMBOL(ss_skb_dump);
