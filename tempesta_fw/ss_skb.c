/**
 *		Tempesta FW
 *
 * Helpers for Linux socket buffers manipulation.
 *
 * Application protocol handler layers must inplement zero data copy logic
 * on top on native Linux socket buffers. The helpers provide common and
 * convenient wrappers for skb processing.
 *
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
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
 * Only the source IP address is printed to @out_buf, and the TCP/SCTP port
 * is not printed. That is done because:
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
 * Allocate a new skb that can hold data of length @len.
 *
 * An SKB is created complely headerless. The linear part of an SKB
 * is set apart for headers, and stream data is placed in paged fragments.
 * Lower layers will take care of prepending all required headers.
 */
struct sk_buff *
ss_skb_alloc_pages(size_t len)
{
	int i_frag, nr_frags = DIV_ROUND_UP(len, PAGE_SIZE);
	struct sk_buff *skb;

	BUG_ON(nr_frags > MAX_SKB_FRAGS);

	skb = ss_skb_alloc();
	if (!skb)
		return NULL;

	for (i_frag = 0; i_frag < nr_frags; ++i_frag) {
		struct page *page = alloc_page(GFP_ATOMIC);
		if (!page) {
			kfree_skb(skb);
			return NULL;
		}
		/* See __skb_alloc_page() in include/linux/skbuff.h. */
		if (page->pfmemalloc)
			skb->pfmemalloc = true;

		__skb_fill_page_desc(skb, i_frag, page, 0, 0);
		skb_shinfo(skb)->nr_frags++;
	}

	return skb;
}

static inline int
ss_skb_frag_len(skb_frag_t *frag)
{
	return frag->page_offset + frag->size;
}

/**
 * Scan page fragments list for fragments placed at the same page with
 * @frag and check if the page has enough room to add @len bytes more.
 * All fragments are scanned when @refcnt reaches 0, otherwise the page
 * is also used by someone else - give up on checking it.
 * @return pointer to the last fragment from the page.
 */
static skb_frag_t *
__check_frag_room(struct sk_buff *skb, skb_frag_t *frag, int len)
{
	int i, sz1, sz2, refcnt;
	struct page *pg = skb_frag_page(frag);
	skb_frag_t *frag2, *ret = frag;

	refcnt = page_count(pg);
	if (refcnt == 1)
		return frag; /* no other users */

	sz1 = PAGE_SIZE - ss_skb_frag_len(frag);
	for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0 ; --i) {
		frag2 = &skb_shinfo(skb)->frags[i];
		if (frag2 == frag || pg != skb_frag_page(frag2))
			continue;
		sz2 = PAGE_SIZE - ss_skb_frag_len(frag2);
		if (sz2 < len)
			return NULL;
		if (sz2 < sz1) {
			sz1 = sz2;
			ret = frag2;
		}
		/* Return localy referenced pages only. */
		if (--refcnt == 1)
			return ret;
	}

	/* The page is used somewhere else. */
	return NULL;
}

/**
 * Look up a page fragment that has @len bytes of room.
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
		if (PAGE_SIZE - ss_skb_frag_len(frag) < len)
			continue;
		frag = __check_frag_room(skb, frag, len);
		if (frag)
			return frag;
	}

	return NULL;
}

/**
 * Somewhat like skb_shift().
 *
 * Beware: @from can be equal to MAX_SKB_FRAGS if we need to insert a new
 * fragment after the last one.
 */
static int
__extend_pgfrags(struct sk_buff *skb, struct sk_buff *pskb, int from, int n)
{
	int i, n_frag = 0;
	struct skb_shared_info *psi, *si = skb_shinfo(skb);

	if (skb_shinfo(skb)->nr_frags > MAX_SKB_FRAGS - n) {
		skb_frag_t *f;
		struct sk_buff *skb_frag;

		psi = pskb ? skb_shinfo(pskb) : si;
		skb_frag = psi->frag_list;
		n_frag = skb_shinfo(skb)->nr_frags + n - MAX_SKB_FRAGS;

		if (skb_frag && !skb_headlen(skb_frag)
		    && skb_shinfo(skb_frag)->nr_frags <= MAX_SKB_FRAGS - n_frag)
		{
			int r = __extend_pgfrags(skb_frag, NULL, 0, n_frag);
			if (r)
				return r;
		} else {
			skb_frag = alloc_skb(0, GFP_ATOMIC);
			if (!skb_frag)
				return -ENOMEM;
			skb_frag->next = psi->frag_list;
			psi->frag_list = skb_frag;
		}

		for (i = n_frag - 1;
		     i >= 0 && MAX_SKB_FRAGS - n + i >= from; --i)
		{
			f = &si->frags[MAX_SKB_FRAGS - n + i];
			skb_shinfo(skb_frag)->frags[i] = *f;
			ss_skb_adjust_data_len(skb, -skb_frag_size(f));
			ss_skb_adjust_data_len(skb_frag, skb_frag_size(f));
		}
		skb_shinfo(skb_frag)->nr_frags += n_frag;
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_frag->ip_summed = CHECKSUM_PARTIAL;
	}

	memmove(&si->frags[from + n], &si->frags[from],
		(si->nr_frags - from - n_frag) * sizeof(skb_frag_t));
	si->nr_frags += n - n_frag;

	return 0;
}

static int
__new_pgfrag(struct sk_buff *skb, struct sk_buff *pskb, int size, int i,
	     int shift)
{
	int off = 0;
	struct page *page = NULL;
	skb_frag_t *frag;

	BUG_ON(i > MAX_SKB_FRAGS);

	frag = __lookup_pgfrag_room(skb, size);
	if (frag) {
		page = skb_frag_page(frag);
		off = ss_skb_frag_len(frag);
		__skb_frag_ref(frag);
	} else {
		page = alloc_page(GFP_ATOMIC);
		if (!page)
			return -ENOMEM;
	}

	if (__extend_pgfrags(skb, pskb, i, shift)) {
		if (!frag)
			__free_page(page);
		return -ENOMEM;
	}

	if (i == MAX_SKB_FRAGS) {
		/*
		 * Insert a new paged fragment right after the last one
		 * in @skb, i.e. as the first fragment of the next skb.
		 */
		skb = skb_shinfo(pskb ? : skb)->frag_list;
		i = 0;
	}

	__skb_fill_page_desc(skb, i, page, off, size);

	ss_skb_adjust_data_len(skb, size);

	return 0;
}

/**
 * Sometimes kernel gives bit more memory for skb than was requested
 * (see ksize() call in __alloc_skb()) - use the extra memory if it's enough
 * to place @n bytes or allocate new linear data.
 *
 * @return pointer to the new data room or just after the deleted fragment.
 * @return NULL on failure.
 */
static void *
__split_linear_data(struct sk_buff *skb, struct sk_buff *pskb,
		    char *pspt, int len)
{
	int alloc = len > 0, tail_len = (char *)skb_tail_pointer(skb) - pspt;
	struct page *page = virt_to_head_page(skb->head);

	BUG_ON(!(alloc | tail_len));

	/*
	 * Quick and unlikely path: just advance skb tail pointer.
	 * Note that this only works when we add space. When we remove,
	 * pspt points at the start of a data chunk to remove. In that
	 * case, tail_len can never be zero.
	 */
	if (unlikely(!tail_len && len <= ss_skb_tailroom(skb))) {
		return ss_skb_put(skb, len);
	}
	/*
	 * Quick and unlikely path: just move skb tail pointer backward.
	 * Note that this only works when we remove data, and the data
	 * is located exactly at the end of the linear part of an skb.
	 */
	if (unlikely((len < 0) && (tail_len == -len))) {
		ss_skb_put(skb, len);
		if (skb_is_nonlinear(skb))
			return skb_frag_address(&skb_shinfo(skb)->frags[0]);
		/* Not found. Return invalid address, and try next skb. */
		return (void *)1;
	}
	/*
	 * Not enough room in the linear part - put data in a page fragment.
	 *
	 * Don't bother with skb tail: if the linear part is large, then
	 * it's likely that we'll do some smaller data insertions and go
	 * by the quick path above, otherwise the tail size is also small.
	 *
	 * Do all allocations before moving the fragments to avoid
	 * complex rollback.
	 */

	if (alloc) {
		if (__new_pgfrag(skb, pskb, len, 0, alloc + !!tail_len))
			return NULL;
	} else {
		/*
		 * Probably we should delete the whole second part
		 * of the linear data or move it to page fragment.
		 */
		tail_len += len;
		BUG_ON(tail_len < 0);
		if (tail_len && __extend_pgfrags(skb, pskb, 0, 1))
			return NULL;
	}

	if (tail_len) {
		int tail_off = pspt - (char *)page_address(page);

		if (len < 0) {
			/* Remove |@len| data bytes. */
			tail_off -= len;
			skb->tail += len;
			skb->len += len;
		}
		skb->tail -= tail_len;
		skb->data_len += tail_len;
		skb->truesize += tail_len;

		__skb_fill_page_desc(skb, alloc, page, tail_off, tail_len);
		skb_frag_ref(skb, alloc);
	}

	return skb_frag_address(&skb_shinfo(skb)->frags[0]);
}

/**
 * Actually just get or allocate a free page fragment and arrange fragments
 * array w/o real data splitting.
 *
 * @return pointer to the new data room or NULL on failure.
 */
static void *
__split_pgfrag_add(struct sk_buff *skb, struct sk_buff *pskb, int i, int off,
		   int len)
{
	int split, dst_i = i + !!off;
	skb_frag_t *frag_dst, *frag = &skb_shinfo(skb)->frags[i];
	struct sk_buff *skb_dst;

	BUG_ON((off < 0) || (off >= skb_frag_size(frag)));
	split = off && off < skb_frag_size(frag);

	/*
	 * Try to append data to a page fragment. If 'off' is zero,
	 * then try to append data to a preceding page fragment
	 * if there's any. Go for other solutions if there's no room.
	 */
	if (!split && (off || i)) {
		frag_dst = (!off && i) ? frag - 1 : frag;
		frag_dst = __check_frag_room(skb, frag_dst, len);
		if (frag_dst) {
			/* Coalesce new data with the fragment. */
			int new_off = skb_frag_size(frag_dst);
			skb_frag_size_add(frag_dst, len);
			ss_skb_adjust_data_len(skb, len);
			return (char *)skb_frag_address(frag_dst) + new_off;
		}
	}

	/*
	 * Get a fragment at position @dst_i that can hold @len bytes.
	 * Get a place for a fragment holding tail data in split case.
	 */
	if (__new_pgfrag(skb, pskb, len, dst_i, 1 + split))
		return NULL;

	skb_dst = (dst_i >= MAX_SKB_FRAGS - 1 - !!split)
		  ? skb_shinfo(pskb ? : skb)->frag_list
		  : skb;
	frag_dst = (dst_i == MAX_SKB_FRAGS)
		   ? &skb_shinfo(skb_dst)->frags[0]
		   : &skb_shinfo(skb)->frags[dst_i];

	if (!off) {
		/*
		 * Need to add data at the start of a fragment.
		 * Move the fragment forward and put the new
		 * fragment in its place instead. In other words,
		 * swap the fragments.
		 */
		swap(*frag, *frag_dst);
		if (dst_i == MAX_SKB_FRAGS) {
			int d = skb_frag_size(frag) - skb_frag_size(frag_dst);
			ss_skb_adjust_data_len(skb, d);
			ss_skb_adjust_data_len(skb_dst, -d);
		}
		return skb_frag_address(frag);
	}

	if (split) {
		/*
		 * Need to add data in the middle of a fragment.
		 * Split the fragment. The head of the fragment
		 * stays there, the tail of the fragment is moved
		 * to a new fragment. The fragment for new data
		 * is placed in between.
		 */
		int tail_len = skb_frag_size(frag) - off;
		int tail_i = (dst_i + 1) % MAX_SKB_FRAGS;
		skb_frag_size_sub(frag, tail_len);
		__skb_fill_page_desc(skb_dst, tail_i,
				     skb_frag_page(frag),
				     frag->page_offset + off, tail_len);
		skb_frag_ref(skb, i);
		if (skb != skb_dst) {
			ss_skb_adjust_data_len(skb, -tail_len);
			ss_skb_adjust_data_len(skb_dst, tail_len);
		}
	}

	return skb_frag_address(frag_dst);
}

/**
 * Delete @len (the value is postive now) bytes from @frag.
 * @return pointer just after deleted fragment.
 */
static void *
__split_pgfrag_del(struct sk_buff *skb, struct sk_buff *pskb, int i, int off,
		   int len)
{
	int tail_len;
	struct sk_buff *skb_dst;
	skb_frag_t *frag_dst, *frag = &skb_shinfo(skb)->frags[i];
	struct skb_shared_info *si = skb_shinfo(skb);

	BUG_ON((off < 0) || (off >= skb_frag_size(frag)));
	if (unlikely(off + len > skb_frag_size(frag))) {
		SS_WARN("Try to delete too much\n");
		return NULL;
	}

	/* Quick paths: no fragmentation. */
	if (!off && len == skb_frag_size(frag)) {
		ss_skb_adjust_data_len(skb, -len);
		__skb_frag_unref(frag);
		if (i + 1 < si->nr_frags)
			memmove(&si->frags[i], &si->frags[i + 1],
				(si->nr_frags - i - 1) * sizeof(skb_frag_t));
		--si->nr_frags;
		goto lookup_next_ptr;
	}
	if (off + len == skb_frag_size(frag)) {
		skb_frag_size_sub(frag, len);
		ss_skb_adjust_data_len(skb, -len);
		++i;
		goto lookup_next_ptr;
	}
	if (!off) {
		frag->page_offset += len;
		skb_frag_size_sub(frag, len);
		ss_skb_adjust_data_len(skb, -len);
		return skb_frag_address(frag);
	}

	if (__extend_pgfrags(skb, pskb, i + 1, 1))
		return NULL;

	if (i == MAX_SKB_FRAGS) {
		skb_dst = skb_shinfo(pskb ? : skb)->frag_list;
		frag_dst = &skb_shinfo(skb_dst)->frags[0];
	} else {
		skb_dst = skb;
		frag_dst = &skb_shinfo(skb)->frags[i];
	}

	i = (i + 1) % MAX_SKB_FRAGS;
	tail_len = skb_frag_size(frag) - off - len;
	skb_frag_size_sub(frag, len + tail_len);
	__skb_fill_page_desc(skb_dst, i, skb_frag_page(frag),
			     frag->page_offset + off + len, tail_len);
	skb_frag_ref(skb, i);
	ss_skb_adjust_data_len(skb, -len);
	if (skb != skb_dst) {
		ss_skb_adjust_data_len(skb, -tail_len);
		ss_skb_adjust_data_len(skb_dst, tail_len);
	}

	return skb_frag_address(&skb_shinfo(skb_dst)->frags[i]);
lookup_next_ptr:
	/* Try to find next data chunk after deleted fragment. */
	if (i < si->nr_frags)
		return skb_frag_address(&si->frags[i]);
	skb_dst = skb_shinfo(pskb ? : skb)->frag_list;
	if (skb_headlen(skb_dst))
		return skb_dst->data;
	if (skb_shinfo(skb_dst)->nr_frags)
		return skb_frag_address(&skb_shinfo(skb_dst)->frags[0]);
	/* ...not found, return invalid address try next skb. */
	return (void *)1;
}

static void *
__split_pgfrag(struct sk_buff *skb, struct sk_buff *pskb, int i, int off,
	       int len)
{
	return len > 0
		? __split_pgfrag_add(skb, pskb, i, off, len)
		: __split_pgfrag_del(skb, pskb, i, off, -len);
}

/**
 * Fragment @skb to add some room if @len > 0 or delete data otherwise.
 */
static int
__skb_fragment(struct sk_buff *skb, struct sk_buff *pskb, char *pspt,
	       int len, TfwStr *it)
{
	int i, dlen;
	char *vaddr;
	struct sk_buff *frag_i;

	BUG_ON(!len);
	/* We can't modify data of shared or cloned skb. */
	BUG_ON(skb_shared(skb) || skb_cloned(skb));

	/* Determine where @split begins within socket buffer. */
	dlen = skb_headlen(skb);
	vaddr = skb->data;

	SS_DBG("skb fragmentation (len=%d pspt=%p, skb: head=%p data=%p"
	       " tail=%p end=%p len=%u data_len=%u truesize=%u"
	       " nr_frags=%u frag_list=%p)...\n",
	       len, pspt, skb->head, skb->data,
	       skb_tail_pointer(skb), skb_end_pointer(skb),
	       skb->len, skb->data_len, skb->truesize,
	       skb_shinfo(skb)->nr_frags, skb_shinfo(skb)->frag_list);

	if (pspt >= vaddr && pspt < vaddr + dlen) {
		it->ptr = __split_linear_data(skb, pskb, pspt, len);
		goto done;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = skb_frag_address(frag);
		dlen = skb_frag_size(frag);

		if (pspt >= vaddr && pspt < vaddr + dlen) {
			it->ptr = __split_pgfrag(skb, pskb, i, pspt - vaddr,
						 len);
			goto done;
		}
	}

	skb_walk_frags(skb, frag_i) {
		int r = __skb_fragment(frag_i, skb, pspt, len, it);
		if (r != -ENOENT)
			return r;
	}

	return -ENOENT;
done:
	SS_DBG("%s: res=%p, skb: head=%p data=%p tail=%p end=%p"
	       " len=%u data_len=%u truesize=%u"
	       " nr_frags=%u frag_list=%p)\n", __func__, it->ptr,
	       skb->head, skb->data,
	       skb_tail_pointer(skb), skb_end_pointer(skb),
	       skb->len, skb->data_len, skb->truesize,
	       skb_shinfo(skb)->nr_frags, skb_shinfo(skb)->frag_list);

	if (!it->ptr)
		return SS_DROP;
	it->len = len;
	it->skb = skb;
	return 0;
}

/**
 * Get room in @skb just before @pspt.
 *
 * The skb is received at some network interface.
 * Locally generated skbs must not be passed to the function, rather local data
 * generators must adjust all application layer message in-place during filling
 * in skb data. See skb processing notes in ss_skb_process().
 *
 * Chunks of compound string @it are dynamically allocated,
 * so use kfree() to release memory.
 */
int
ss_skb_get_room(struct sk_buff *skb, char *pspt, unsigned int len, TfwStr *it)
{
	if (unlikely(len > PAGE_SIZE)) {
		SS_WARN("Trying to get too large skb room, size=%u\n", len);
		return -E2BIG;
	}

	return __skb_fragment(skb, NULL, pspt, len, it);
}

/**
 * Cut off @hdr->len data bytes from underlying skbs skipping first @skip bytes
 * and also cut off @tail bytes after @hdr.
 */
int
ss_skb_cutoff_data(SsSkbList *head, const TfwStr *hdr, int skip, int tail)
{
	int r;
	struct sk_buff *skb = NULL;
	const TfwStr *c, *end;
	TfwStr it;

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (c->len <= skip) {
			skip -= c->len;
			continue;
		}

		skb = c->skb;
		r = __skb_fragment(skb, NULL, (char *)c->ptr + skip,
				   skip - c->len, &it);
		if (r)
			return r;

		skip = 0;
	}
	BUG_ON(!skb);

	/* Cut off the tail. */
	if (tail) {
		char *p = it.ptr;
		r = __skb_fragment(skb, NULL, p, -tail, &it);
		if (r != -ENOENT)
			return 0;
		skb = ss_skb_next(head, skb);
		if (skb)
			return __skb_fragment(skb, NULL, p, -tail, &it);
		SS_WARN("Cannot delete hdr tail\n");
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
	struct sk_buff *skb_frag;

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
	 * Process paged data.
	 * This is the common place for GROed data,
	 * see ixgbe_fetch_rx_buffer() and tcp_gro_receive().
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
	 * Process packet fragments.
	 * GRO skb fragments from gro_list - skb_gro_receive() adds skbs to the
	 * list if page fragments is full.
	 */
	skb_walk_frags(skb, skb_frag) {
		if (offset < skb_frag->len) {
			*off += skb_frag->len - offset;
			r = ss_skb_process(skb_frag, &offset, actor, objdata);
			if (r != SS_POSTPONE)
				return r;
			offset = 0;
		} else {
			offset -= skb_frag->len;
		}
	}

	return r;
}

/*
 * Split an SKB in two at a given offset. The original SKB is shrunk
 * to specified 'len', and the remaining data is put into a new SKB.
 *
 * The implementation is very much like tcp_fragment() or tso_fragment()
 * in the Linux kernel. One major difference is that these SKBs were just
 * taken out of the receive queue, so they have not been out to the write
 * queue yet. The socket is unlocked when this function runs, which means
 * that we can't adjust socket accounting. The SKBs must come orphaned.
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
	 * Correct the sequence numbers. There's no need to adjust
	 * TCP flags as the lower layer knows the original SKB only.
	 * Checksum is also irrelevant at this stage.
	 */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	skb_split(skb, buff, len);

	return buff;
}
