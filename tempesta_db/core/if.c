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
static DEFINE_MUTEX(tdb_if_mtx);

#define TDB_NLMSG_MAXSZ		(NL_FR_SZ / 2 - NLMSG_HDRLEN - sizeof(TdbMsg) \
				 - sizeof(TdbMsgRec))

static int
tdb_if_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	TdbMsg *m;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, TDB_NLMSG_MAXSZ, 0);
	if (!nlh)
		return -EMSGSIZE;

	m = nlmsg_data(nlh);

	/* Fill in response. */
	memcpy(m, cb->data, sizeof(*m));
	m->rec_n = 1;
	m->recs[0].klen = 0;
	m->recs[0].dlen = tdb_info(m->recs[0].data, TDB_NLMSG_MAXSZ);
	if (m->recs[0].dlen <= 0) {
		nlmsg_cancel(skb, nlh);
		return m->recs[0].dlen;
	}

	return 0; /* end transfer */
}

static int
tdb_if_create(struct sk_buff *skb, struct netlink_callback *cb)
{
	return 0;
}

static int
tdb_if_insert(struct sk_buff *skb, struct netlink_callback *cb)
{
	return 0;
}

static int
tdb_if_select(struct sk_buff *skb, struct netlink_callback *cb)
{
	return 0;
}

static const struct {
	int (*dump)(struct sk_buff *, struct netlink_callback *);
} tdb_if_call_tbl[__TDB_MSG_TYPE_MAX] = {
	[TDB_MSG_INFO - __TDB_MSG_BASE]		= { .dump = tdb_if_info },
	[TDB_MSG_CREATE - __TDB_MSG_BASE]	= { .dump = tdb_if_create },
	[TDB_MSG_INSERT - __TDB_MSG_BASE]	= { .dump = tdb_if_insert },
	[TDB_MSG_SELECT - __TDB_MSG_BASE]	= { .dump = tdb_if_select },
};

static int
tdb_if_proc_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	TdbMsg *m;

	if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg)) {
		TDB_ERR("too short netlink msg\n");
		return -EINVAL;
	}

	m = nlmsg_data(nlh);

	/* Type specific consistency checking. */
	switch (m->type) {
	case TDB_MSG_INFO:
		if (m->rec_n || m->t_name[0] != '*' || m->t_name[1] != 0) {
			TDB_ERR("Bad info netlink msg: rec_n=%u t_name=%x%x\n",
				m->rec_n, m->t_name[0], m->t_name[1]);
			return -EINVAL;
		}
		break;
	case TDB_MSG_CREATE:
		break;
	case TDB_MSG_INSERT:
		break;
	case TDB_MSG_SELECT:
		break;
	default:
		TDB_ERR("bad netlink msg type %u\n", m->type);
		return -EINVAL;
	}

	{
		struct netlink_dump_control c = {
			.dump = tdb_if_call_tbl[m->type - __TDB_MSG_BASE].dump,
			.data = m,
			.min_dump_alloc = NL_FR_SZ / 2,
		};
		return netlink_dump_start(nls, skb, nlh, &c);
	}
}

static void
tdb_if_rcv(struct sk_buff *skb)
{
	mutex_lock(&tdb_if_mtx);
	netlink_rcv_skb(skb, &tdb_if_proc_msg);
	mutex_unlock(&tdb_if_mtx);
}

static struct netlink_kernel_cfg tdb_if_nlcfg = {
	.input	= tdb_if_rcv,
};

int __init
tdb_if_init(void)
{
	nls = netlink_kernel_create(&init_net, NETLINK_TEMPESTA, &tdb_if_nlcfg);
	if (!nls) {
		TDB_ERR("Failed to create netlink socket\n");
		return -ENOMEM;
	}

	return 0;
}

void __exit
tdb_if_exit(void)
{
	netlink_kernel_release(nls);
}
