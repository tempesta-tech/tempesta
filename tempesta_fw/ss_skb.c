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
#include "ss_skb.h"

/**
 * Process a socket buffer.
 * See standard skb_copy_datagram_iovec() implementation.
 * @return SS_OK, SS_DROP or negative value of error code.
 *
 * The function is anaware about application layer, but it still chops
 * @skb to messages: if @proc_actor returns POSTPONE code and there is more
 * data in @skb, then function continues to process @skb, otherwise it
 * returns allowing higher layer to process the full message.
 * @off is used as an iterator among the function calls over the same @skb.
 */
int
ss_skb_process(struct sk_buff *skb, unsigned int *off,
	       ss_skb_proc_actor_t proc_actor, void *data)
{
	int i, r = SS_OK;
	int lin_len = skb_headlen(skb);
	unsigned int o = *off;
	struct sk_buff *frag_i;

	/* Process linear data. */
	if (o < lin_len) {
		*off = lin_len;
		r = proc_actor(data, skb->data + o, lin_len - o);
		if (r != SS_POSTPONE)
			return r;
		o = 0;
	} else
		o -= lin_len;

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int f_sz = skb_frag_size(frag);
		if (f_sz > o) {
			unsigned char *f_addr = skb_frag_address(frag);
			*off += f_sz - o;
			r = ss_tcp_process_proto_skb(sk, f_addr + o,
						     f_sz - o, skb);
			if (r != SS_POSTPONE)
				return r;
			o = 0;
		} else
			o -= f_sz;
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		if (frag_i->len > o) {
			*off += frag_i->len - o;
			r = ss_skb_process(frag_i, o, proc_actor, data);
			if (r != SS_POSTPONE)
				return r;
			o = 0;
		} else
			o -= frag_i->len;
	}

	return r;
}
