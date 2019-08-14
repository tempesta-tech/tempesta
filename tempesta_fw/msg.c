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
#include "http_msg.h"

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
	it->frag = data_len ? -1 /* first 'frag' is the skb head */ : 0;

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
	it->frag = 0;

	skb_shinfo(it->skb)->tx_flags = skb_shinfo(it->skb->prev)->tx_flags;

	return 0;
}
