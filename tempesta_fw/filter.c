/**
 *		Tempesta FW
 *
 * We split traditional filtering logic to two separate pieces:
 * - packet classification (e.g. should we pass or block a packet);
 * - packet action (e.g. drop the packet or close whole TCP connection).
 * Tempesta classifiers are responsible for the first task while filtering
 * modules are responsible for the second one. Different classifiers can imply
 * different policies to service/block packets (e.g. QoS), so typically
 * filtering actions are called by classifiers.
 *
 * The rules work only on 3 and 4 network layers, since only they are managed
 * by current filtering routines. Blocking on all higher layers are provided
 * by GFSM, so classifier can play role of blocking logic: it makes a decision
 * and GFSM is responsible to pass or block a message. This is the way how
 * application level filters must be implemented.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/tcp.h>

#include "tdb.h"

#include "lib/str.h"
#include "tempesta_fw.h"
#include "http_limits.h"
#include "filter.h"
#include "log.h"

enum {
	TFW_F_DROP,
};

typedef struct {
	struct in6_addr	addr;
	int		action;
} TfwFRule;

static struct {
	unsigned int	db_size;
	const char	*db_path;
} filter_cfg __read_mostly;

static TDB *ip_filter_db;

static unsigned long
tfw_ipv6_hash(const struct in6_addr *addr)
{
	return ((unsigned long)addr->s6_addr32[0] << 32)
	       ^ ((unsigned long)addr->s6_addr32[1] << 24)
	       ^ ((unsigned long)addr->s6_addr32[2] << 8)
	       ^ addr->s6_addr32[3];
}

void
tfw_filter_block_ip(const TfwAddr *addr)
{
	TfwFRule rule = {
		.addr	= addr->sin6_addr,
		.action	= TFW_F_DROP,
	};
	unsigned long key = tfw_ipv6_hash(&addr->sin6_addr);
	size_t len = sizeof(rule);

	T_DBG_ADDR("filter: block", addr, TFW_NO_PORT);

	/* TODO create records on all NUMA nodes. */
	if (!tdb_entry_create(ip_filter_db, key, &rule, &len)) {
		T_WARN_ADDR("cannot create blocking rule", addr, TFW_NO_PORT);
	} else {
		T_DBG_ADDR("block client", addr, TFW_NO_PORT);
	}
}
EXPORT_SYMBOL(tfw_filter_block_ip);

/**
 * Drop early IP layer filtering.
 * The check is run against each ingress packet - if application layer filter
 * blocks a client, then the client is totally blocked and can't send us any
 * traffic.
 */
static int
tfw_filter_check_ip(struct in6_addr *addr)
{
	TdbIter iter;

	iter = tdb_rec_get(ip_filter_db, tfw_ipv6_hash(addr));
	while (!TDB_ITER_BAD(iter)) {
		const TfwFRule *rule = (TfwFRule *)iter.rec->data;
		if (!memcmp_fast(&rule->addr, addr, sizeof(*addr))) {
			tdb_rec_put(iter.rec);
			return rule->action == TFW_F_DROP ? TFW_BLOCK : TFW_PASS;
		}
		tdb_rec_next(ip_filter_db, &iter);
	}

	return TFW_PASS;
}

/*
 * Make sure we're dealing with an IPv4 packet. While at that, make sure
 * that the full IPv4 header is in the linear part. This is similar to what
 * ip_rcv() does in the Linux network stack (linux/net/ipv4/ip_input.c).
 */
static struct iphdr *
__ipv4_hdr_check(struct sk_buff *skb)
{
	u32 pkt_len;
	struct iphdr *ih;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NULL;

	ih = ip_hdr(skb);
	if (unlikely((ih->ihl < 5) || (ih->version != 4)))
		return NULL;

	if (!pskb_may_pull(skb, ih->ihl * 4))
		return NULL;

	ih = ip_hdr(skb);
	pkt_len = ntohs(ih->tot_len);
	if (unlikely((pkt_len > skb->len) || (pkt_len < ih->ihl * 4)))
		return NULL;

	return ih;
}

static unsigned int
tfw_ipv4_nf_hook(void *priv, struct sk_buff *skb,
		 const struct nf_hook_state *state)
{
	int r;
	const struct iphdr *ih;
	struct in6_addr addr6;

	ih = __ipv4_hdr_check(skb);
	if (!ih)
		return NF_DROP;

	ipv6_addr_set_v4mapped(ih->saddr, &addr6);

	if (tfw_filter_check_ip(&addr6) == TFW_BLOCK)
		return NF_DROP;

	/* Check classifiers for Layer 3. */
	r = tfw_classify_ipv4(skb);
	switch (r) {
	case TFW_PASS:
		return NF_ACCEPT;
	case TFW_POSTPONE:
		return NF_STOLEN;
	}

	return NF_DROP;
}

static u8 *
__ipv6_opt_ptr(struct sk_buff *skb, size_t off)
{
	if (!pskb_may_pull(skb, off + 8)) /* ext headers are 8-byte aligned */
		return NULL;

	return (u8 *)(ipv6_hdr(skb) + 1);
}

static struct ipv6hdr *
__ipv6_hdr_check(struct sk_buff *skb)
{
	u32 len;
	size_t off = 0;
	struct ipv6hdr *ih;
	u8 next, *buf;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return NULL;

	ih = ipv6_hdr(skb);
	if (unlikely(ih->version != 6))
		return NULL;

	len = ntohs(ih->payload_len);
	if (unlikely(len + sizeof(struct ipv6hdr) > skb->len))
		return NULL;

	/* Check options. */
	next = ih->nexthdr;
	buf = __ipv6_opt_ptr(skb, 0);
	while (next != IPPROTO_TCP) {
		if (!buf)
			return NULL;

		switch(next) {
		case 0 : /* hop-by-hop */
		case 60 : /* destination options */
		case 43 : /* routing */
			next = buf[0];
			len = (buf[1] + 1) * 8;

			off += len;
			buf = __ipv6_opt_ptr(skb, off);

			break;
		case 44 : /* fragment */
			/* TODO we do not support fragmented IPv6 yet. */
		default: /* unknown or unsupported ext. header, skipping */
			return NULL;
		}
	}

	return ih;
}

static unsigned int
tfw_ipv6_nf_hook(void *priv, struct sk_buff *skb,
		 const struct nf_hook_state *state)
{
	int r;
	struct ipv6hdr *ih;

	ih = __ipv6_hdr_check(skb);
	if (!ih)
		return NF_DROP;

	if (tfw_filter_check_ip(&ih->saddr) == TFW_BLOCK)
		return NF_DROP;

	/* Check classifiers for Layer 3. */
	r = tfw_classify_ipv6(skb);
	switch (r) {
	case TFW_PASS:
		return NF_ACCEPT;
	case TFW_POSTPONE:
		return NF_STOLEN;
	}

	return NF_DROP;
}

static struct nf_hook_ops tfw_nf_ops[] __read_mostly = {
	{
		.hook		= tfw_ipv4_nf_hook,
		.pf		= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
	{
		.hook		= tfw_ipv6_nf_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_CONNTRACK_DEFRAG + 1,
	},
};

static int
tfw_nf_register(struct net *net)
{
	return nf_register_net_hooks(net, tfw_nf_ops, ARRAY_SIZE(tfw_nf_ops));
}

static void
tfw_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, tfw_nf_ops, ARRAY_SIZE(tfw_nf_ops));
}

static struct pernet_operations tfw_net_ops = {
	.init = tfw_nf_register,
	.exit = tfw_nf_unregister,
};

static int
tfw_filter_start(void)
{
	int r;

	if (tfw_runstate_is_reconfig())
		return 0;

	ip_filter_db = tdb_open(filter_cfg.db_path, filter_cfg.db_size,
				sizeof(TfwFRule), numa_node_id());
	if (!ip_filter_db)
		return -EINVAL;

	if ((r = register_pernet_subsys(&tfw_net_ops)))	{
		T_ERR_NL("can't register netfilter hooks\n");
		tdb_close(ip_filter_db);
		return r;
	}

	return 0;
}

static void
tfw_filter_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	if (ip_filter_db) {
		unregister_pernet_subsys(&tfw_net_ops);
		tdb_close(ip_filter_db);
	}
}

static TfwCfgSpec tfw_filter_specs[] = {
	{
		.name = "filter_tbl_size",
		.deflt = "16777216",
		.handler = tfw_cfg_set_int,
		.dest = &filter_cfg.db_size,
		.spec_ext = &(TfwCfgSpecInt) {
			.multiple_of = PAGE_SIZE,
			.range = { PAGE_SIZE, (1 << 30) },
		}
	},
	{
		.name = "filter_db",
		.deflt = "/opt/tempesta/db/filter.tdb",
		.handler = tfw_cfg_set_str,
		.dest = &filter_cfg.db_path,
		.spec_ext = &(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{ 0 }
};

TfwMod tfw_filter_mod = {
	.name 	= "filter",
	.start	= tfw_filter_start,
	.stop	= tfw_filter_stop,
	.specs	= tfw_filter_specs,
};

int
tfw_filter_init(void)
{
	tfw_mod_register(&tfw_filter_mod);
	return 0;
}

void
tfw_filter_exit(void)
{
	tfw_mod_unregister(&tfw_filter_mod);
}
