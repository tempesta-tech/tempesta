/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_FILTER_H__
#define __TFW_FILTER_H__

#include <linux/in6.h>

#include "tempesta_fw.h"

/*
 * Filtering module handler.
 *
 * TODO:
 * -- possibility to change TCP options (window and timers) and send or not ACKs
 *    to be able to provice different QoS to the clients.
 */
typedef struct {
	/*
	 * @return netfilter response constant depending on internal filter
	 * 	   logic for specified skb.
	 */
	int	(*block)(struct sk_buff *skb);
	/*
	 * Add new blocking rule for the particular IP.
	 */
#if IS_ENABLED(CONFIG_IPV6)
	void	(*add_rule)(__be32 addr4, struct in6_addr *addr6);
#else
	void	(*add_rule)(__be32 addr4);
#endif
} TfwFilter;

void tfw_filter_set_inports(__be16 *ports, unsigned int n);

/* Filter actions. */
void tfw_filter_add_rule(struct sock *sk);

int tfw_filter_register(TfwFilter *mod);
void tfw_filter_unregister(void);

int tfw_filter_init(void);
void tfw_filter_exit(void);

#endif /* __TFW_FILTER_H__ */
