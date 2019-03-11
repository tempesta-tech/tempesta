/**
 *		Tempesta FW
 *
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#include "lib/str.h"
#include "msg.h"

/**
 * Fill up an HTTP message by iterator @it with data from string @data.
 * This is a quick message creator which doesn't maintain properly
 * parts of the message structure like headers table. So the HTTP message
 * cannot be used where HTTP message transformations are required.
 *
 * An iterator @it is used to support multiple calls to this function
 * after the set up. This function can only be called after a call to
 * tfw_http_msg_setup(). It works only with empty SKB space prepared
 * by the function.
 */
int
tfw_msg_write(TfwMsgIter *it, const TfwStr *data)
{
	const TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(data));
	if (WARN_ON_ONCE(it->frag >= skb_shinfo(it->skb)->nr_frags))
		return -E2BIG;

	TFW_STR_FOR_EACH_CHUNK(c, data, end) {
		char *p;
		unsigned int c_off = 0, c_size, f_room, n_copy;
this_chunk:

		c_size = c->len - c_off;
		if (it->frag >= 0) {
			unsigned int f_size;
			skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];

			f_size = skb_frag_size(frag);
			f_room = PAGE_SIZE - frag->page_offset - f_size;
			p = (char *)skb_frag_address(frag) + f_size;
			n_copy = min(c_size, f_room);
			skb_frag_size_add(frag, n_copy);
			ss_skb_adjust_data_len(it->skb, n_copy);
		} else {
			f_room = skb_tailroom(it->skb);
			n_copy = min(c_size, f_room);
			p = skb_put(it->skb, n_copy);
		}

		memcpy_fast(p, c->data + c_off, n_copy);

		/*
		 * The chunk occupied all the spare space in the SKB fragment,
		 * switch to the next fragment.
		 */
		if (c_size >= f_room) {
			if (WARN_ON_ONCE(tfw_msg_iter_next_data_frag(it)
					 && ((c_size != f_room)
					     || (c + 1 < end))))
			{
				return -E2BIG;
			}
			/*
			 * Not all data from the chunk has been copied,
			 * stay in the current chunk and copy the rest to the
			 * next fragment.
			 */
			if (c_size != f_room) {
				c_off += n_copy;
				goto this_chunk;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(tfw_msg_write);

int
tfw_msg_iter_setup(TfwMsgIter *it, struct sk_buff **skb_head, size_t data_len)
{
	int r;

	if ((r = ss_skb_alloc_data(skb_head, data_len)))
		return r;
	it->skb = it->skb_head = *skb_head;
	it->frag = data_len ? -1 /* first 'frag' is the skb head */ : 0;

	BUG_ON(!it->skb);

	return 0;
}
