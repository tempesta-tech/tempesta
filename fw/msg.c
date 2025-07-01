/**
 *		Tempesta FW
 *
 * Copyright (C) 2018-2023 Tempesta Technologies, Inc.
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
#include "http_msg.h"
#include "ss_skb.h"

/**
 * Allocate list of skbs to store data with given length @data_len and
 * initialise the iterator it. Shouldn't be called against previously used
 * iterator, since its current state is to be rewritten.
 */
int
tfw_msg_iter_setup(TfwMsgIter *it, void *owner, struct sk_buff **skb_head,
		   size_t data_len)
{
	int r;

	if ((r = ss_skb_alloc_data(skb_head, owner, data_len)))
		return r;
	it->skb = it->skb_head = *skb_head;
	it->frag = -1;

	BUG_ON(!it->skb);

	return 0;
}

static inline int
tfw_msg_iter_next_data_frag(TfwMsgIter *it)
{
	if (skb_shinfo(it->skb)->nr_frags > it->frag + 1) {
		++it->frag;
		return 0;
	}

	it->skb = it->skb->next;
	if (it->skb == it->skb_head || !skb_shinfo(it->skb)->nr_frags) {
		it->frag = MAX_SKB_FRAGS;
		return -EINVAL;
	}
	it->frag = -1;
	skb_shinfo(it->skb)->flags = skb_shinfo(it->skb->prev)->flags;

	return 0;
}

/**
 * Fill up an HTTP message by iterator @it with data from string @data.
 * Properly maintain @hm header @field, so that @hm can be used in regular
 * transformations. However, the header name and the value are not split into
 * different chunks, so advanced headers matching is not available for @hm.
 */
static int
tfw_msg_iter_add_data(TfwMsgIter *it, const TfwStr *data)
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
			f_room = PAGE_SIZE - skb_frag_off(frag) - f_size;
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
tfw_msg_iter_write(TfwMsgIter *it, const TfwStr *data)
{
	return tfw_msg_iter_add_data(it, data);
}
EXPORT_SYMBOL(tfw_msg_iter_write);

/**
 * Move message iterator from @data pointer by @sz symbols right.
 * @sz must be less than remaining message size, otherwise an error will be
 * returned.
 */
int
tfw_msg_iter_move(TfwMsgIter *it, unsigned char **data, unsigned long sz)
{
	unsigned char *addr = *data;

	while (true) {
		unsigned long f_sz_rem, len;

		/* Linear skb part. */
		if (it->frag < 0) {
			f_sz_rem = skb_headlen(it->skb) + it->skb->data - addr;
		}
		else {
			skb_frag_t *f = &skb_shinfo(it->skb)->frags[it->frag];
			f_sz_rem = skb_frag_size(f) +
				(unsigned char *)skb_frag_address(f) - addr;
		}

		len = min(sz, f_sz_rem);
		addr += len;
		sz -= len;

		if (len < f_sz_rem) {
			*data = addr;
			return 0;
		}
		if (skb_shinfo(it->skb)->nr_frags > it->frag + 1) {
			skb_frag_t *frag;

			++it->frag;
			frag = &skb_shinfo(it->skb)->frags[it->frag];
			addr = skb_frag_address(frag);
		}
		else {
			if (WARN_ON_ONCE(it->skb_head == it->skb->next))
				return -EINVAL;

			it->skb = it->skb->next;
			it->frag = -1;
			addr = it->skb->data;
		}

		/*
		 * Message iterator is set to point a new fragment or linear
		 * skb part. Stop here if we have no more data to skip: the
		 * function is called at message modification context and
		 * new insertions into message usually take place at that empty
		 * fragments. Don't skip and stop on the next fragment.
		 */
		if (!sz) {
			*data = addr;
			return 0;
		}
	}

	return 0;
}
