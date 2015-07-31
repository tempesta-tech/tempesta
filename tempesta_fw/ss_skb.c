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
#include <net/sock.h>
#include <net/tcp.h>
#include "ss_skb.h"

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
	/* Process paged data. */
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
	/* Process packet fragments. */
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
	int nsize, nlen;

	/* Assert that the SKB is orphaned. */
	BUG_ON(skb->destructor);

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;
	nsize = ALIGN(nsize, 4);

	buff = alloc_skb_fclone(nsize + MAX_TCP_HEADER, GFP_ATOMIC);
	if (buff == NULL)
		return NULL;

	skb_reserve(buff, MAX_TCP_HEADER);
	buff->reserved_tailroom = buff->end - buff->tail - nsize;

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
