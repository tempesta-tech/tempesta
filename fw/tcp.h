/**
 *		TCP Socket API.
 *
 * Copyright (C) 2015-2023 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_TCP_H__
#define __TFW_TCP_H__

#include <linux/skbuff.h>

void tfw_tcp_propagate_dseq(struct sock *sk, struct sk_buff *skb);
void tfw_tcp_setup_new_skb(struct sock *sk, struct sk_buff *skb,
                           struct sk_buff *nskb, unsigned int mss_now);

#endif /* __TFW_TCP_H__ */
