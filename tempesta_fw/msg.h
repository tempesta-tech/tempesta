/**
 *		Tempesta FW
 *
 * Generic protocol message.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_MSG_H__
#define __TFW_MSG_H__

#include <linux/skbuff.h>

#include "gfsm.h"

#include "sync_socket.h"

/**
 * @seq_list	- member in the ordered queue of incoming requests;
 * @fwd_list	- member in the queue of forwarded/backlogged requests;
 * @skb_list	- list of sk_buff that belong to the message;
 * @ss_flags	- message processing flags;
 * @len		- total message length;
 */
typedef struct {
	struct list_head	seq_list;
	struct list_head	fwd_list;
	int			ss_flags;
	SsSkbList		skb_list;
	size_t			len;
} TfwMsg;

#endif /* __TFW_MSG_H__ */
