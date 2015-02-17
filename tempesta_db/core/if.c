/**
 *		Tempesta DB
 *
 * User-space communication routines.
 *
 * Copyright (C) 2015 Tempesta Technologies.
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
#include <net/netlink.h>
#include <net/net_namespace.h>

#include "tdb.h"
#include "tdb_if.h"

static struct sock *nls;

static int
tdb_if_proc_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	TDB_ERR("%s called!\n", __FUNCTION__);
	return 0;
}

static void
tdb_if_rcv(struct sk_buff *skb)
{
	TDB_ERR("%s called!\n", __FUNCTION__);
	netlink_rcv_skb(skb, &tdb_if_proc_msg);
}

static struct netlink_kernel_cfg tdb_if_nlcfg = {
	.input	= tdb_if_rcv,
};

int __init
tdb_if_init(void)
{
	nls = netlink_kernel_create(&init_net, NETLINK_FIREWALL, &tdb_if_nlcfg);
	if (!nls) {
		TDB_ERR("Failed to create netlink socket\n");
		return -ENOMEM;
	}
	TDB_ERR("%s success, nls=%p input=%p net=%p\n", __FUNCTION__, nls, tdb_if_rcv, &init_net);

	return 0;
}

void __exit
tdb_if_exit(void)
{
	netlink_kernel_release(nls);
}
