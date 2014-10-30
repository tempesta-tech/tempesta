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

#include "sync_socket.h"

#include "gfsm.h"

typedef struct tfw_msg TfwMsg;
typedef void (*tfw_msg_destructor_t)(TfwMsg *msg);

typedef struct tfw_msg {
	struct tfw_msg	*prev;		/* sibling messages */
	size_t		len;		/* total body length */
	TfwGState	state;		/* message processing state. */
	SsSkbList	skb_list;	/* list of sk_buff's belonging
					   to the message. */
	struct list_head pl_list;	/* Element of a pipeline list. */
	tfw_msg_destructor_t destructor;
} TfwMsg;


/**
 * Invoke TfwMsg destructor.
 * Also the macro sets given @msg_ptr to NULL because the destructor is supposed
 * to free some allocated memory, so the pointer becomes invalid after the call.
 */
#define tfw_msg_destruct(msg_ptr) 	\
do { 					\
	BUG_ON(!msg_ptr->destructor); 	\
	msg_ptr->destructor(msg_ptr);	\
	msg_ptr = NULL;			\
} while (0)

#endif /* __TFW_MSG_H__ */
