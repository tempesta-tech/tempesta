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
	return tfw_http_msg_add_data(it, NULL, NULL, data);
}
EXPORT_SYMBOL(tfw_msg_write);

/**
 * Allocate list of skbs to store data with given length @data_len and
 * initialise the iterator it. Shouldn't be called against previously used
 * iterator, since its current state is to be rewritten.
 */
int
tfw_msg_iter_setup(TfwMsgIter *it, struct sk_buff **skb_head, size_t data_len,
		   unsigned int tx_flags)
{
	int r;

	if ((r = ss_skb_alloc_data(skb_head, data_len, tx_flags)))
		return r;
	it->skb = it->skb_head = *skb_head;
	it->frag = -1;

	BUG_ON(!it->skb);

	return 0;
}

/**
 * Allocate and add a single empty skb (with a place for TCP headers though)
 * to the iterator. The allocated skb has no space for the data, user is
 * expected to add new paged fragments.
 */
int
tfw_msg_iter_append_skb(TfwMsgIter *it)
{
	int r;

	if ((r = ss_skb_alloc_data(&it->skb_head, 0, 0)))
		return r;
	it->skb = ss_skb_peek_tail(&it->skb_head);
	it->frag = -1;

	skb_shinfo(it->skb)->tx_flags = skb_shinfo(it->skb->prev)->tx_flags;

	return 0;
}

/**
 * Find origin fragment of data @off and set it as active message iterator
 * fragment.
 */
int tfw_http_iter_set_at(TfwMsgIter *it, char *off)
{
	do {
		if (!ss_skb_find_frag_by_offset(it->skb, off, &it->frag))
			return 0;
		it->skb = it->skb->next;

	} while (it->skb != it->skb_head);

	return -E2BIG;
}

char *
tfw_http_iter_set_at_skb(TfwMsgIter *it, struct sk_buff *skb,
			 unsigned long off)
{
	char *begin, *end;
	unsigned long d;
	unsigned char i;

	if (skb_headlen(it->skb)) {
		begin = it->skb->data;
		end = begin + skb_headlen(it->skb);

		if (begin + off <= end) {
			it->frag = -1;
			return begin + off;
		}
		off -= skb_headlen(it->skb);
	}

	for (i = 0; i < skb_shinfo(it->skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(it->skb)->frags[i];

		begin = skb_frag_address(f);
		end = begin + skb_frag_size(f);
		d = end - begin;
		if (off >= d) {
			off -= d;
			continue;
		}
		it->frag = i;
		return begin + off;
	}

	return NULL;
}

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
