/**
 *		Tempesta FW
 *
 * Generic protocol message.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

typedef struct tfw_msg {
	struct tfw_msg		*prev;		/* sibling messages */
	TfwGState		state;		/* message processing state. */
	struct sk_buff_head	skb_list;	/* list of sk_buff's belonging
						   to the message. */
	int			len;
} TfwMsg;

#endif /* __TFW_MSG_H__ */
