/**
 *		Tempesta FW
 *
 * Generic protocol message.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2023 Tempesta Technologies, Inc.
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
#ifndef __TFW_MSG_H__
#define __TFW_MSG_H__

#include <linux/skbuff.h>

#include "sync_socket.h"

/**
 * @seq_list	- member in the ordered queue of messages;
 * @skb_head	- head of the list of sk_buff that belong to the message;
 * @ss_flags	- message processing flags;
 * @len		- total message length;
 *
 * TODO: Currently seq_list is used only in requests. Responses are not
 * put in any queues, they are simply attached to requests as req->resp.
 * However, a queue for responses may also be needed to mitigate sending
 * of responses and improve the distribution of load in Tempesta. Please
 * refer to issues #391 and #488.
 * After these issues are resolved, it may well be that seq_list is more
 * suitable to stay in TfwHttpReq{} rather than here in TfwMsg{}.
 */
typedef struct {
	struct list_head	seq_list;
	struct sk_buff		*skb_head;
	int			ss_flags;
	size_t			len;
} TfwMsg;

/**
 * Iterator for @skb fragments.
 *
 * @frag	- current fragment index or @skb->head if -1;
 * @skb		- current skb to process;
 * @skb_head	- head of the skb list.
 */
typedef struct {
	int		frag;
	struct sk_buff	*skb;
	struct sk_buff	*skb_head;
} TfwMsgIter;

/**
 * Iterator for HTTP/2 message processing.
 *
 * @pool	- allocation pool for target buffer of decoded headers;
 * @parsed_hdr	- pointer to the message header which is currently processed;
 * @hdrs_len	- accumulated length of message's decoded and parsed headers;
 * @hdrs_cnt	- count of all headers from message headers block;
 * @__off	- offset for iterator reinitializing before next processing
 *		  stage;
 * @hdr		- descriptor of currently decoded header in target buffer;
 * @pos		- pointer to the currently allocated chunk of decoded headers'
 *		  buffer;
 * @rspace	- space remained in the allocated chunk;
 * @next	- pointer to the decoded header part (name/value) to be
 *		- parsed next;
 * @nm_len	- length of the decoded header's name;
 * @nm_num	- chunks number of the decoded header's name;
 * @hdr_tag	- tag of currently processed decoded header.
 */
typedef struct {
	TfwPool		*pool;
	TfwStr		*parsed_hdr;
	unsigned long	hdrs_len;
	unsigned int	hdrs_cnt;
	char		__off[0];
	TfwStr		hdr;
	char		*pos;
	unsigned long	rspace;
	TfwStr		*next;
	unsigned long	nm_len;
	unsigned int	nm_num;
	unsigned int	tag;
} TfwMsgParseIter;

int tfw_msg_write(TfwMsgIter *it, const TfwStr *data);
int tfw_msg_iter_setup(TfwMsgIter *it, struct sk_buff **skb_head,
		       size_t data_len, unsigned int tx_flags);
int tfw_msg_iter_append_skb(TfwMsgIter *it);
int tfw_http_iter_set_at(TfwMsgIter *it, char *off);
char *tfw_http_iter_set_at_skb(TfwMsgIter *it, struct sk_buff *skb,
		               unsigned long off);
int tfw_msg_iter_move(TfwMsgIter *it, unsigned char **data, unsigned long sz);

static inline void
tfw_msg_iter_set_skb_priv(TfwMsgIter *it, unsigned int priv,
                          unsigned short flags)
{
        struct sk_buff *skb = it->skb;
        do {
                if (flags)
                        skb_set_tfw_flags(skb, flags);
                if (priv)
                        skb_set_tfw_cb(skb, priv);
                skb = skb->next;
        } while (skb != it->skb_head);
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

	return 0;
}

#endif /* __TFW_MSG_H__ */
