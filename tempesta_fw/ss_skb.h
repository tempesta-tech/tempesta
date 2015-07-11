/**
 *		Tempesta FW
 *
 * Synchronous Sockets API for Linux socket buffers manipulation.
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
#include <linux/skbuff.h>

/**
 * Responses from socket hook functions.
 */
enum {
	/* The packet must be dropped. */
	SS_DROP		= -2,

	/* The packet should be stashed (made by callback). */
	SS_POSTPONE	= -1,

	/* The packet looks good and we can safely pass it. */
	SS_OK		= 0,
};

typedef int (*ss_skb_proc_actor_t)(void *conn, unsigned char *data,
				   size_t len);

int ss_skb_process(struct sk_buff *skb, unsigned int *off,
		   ss_skb_proc_actor_t proc_actor, void *data);
