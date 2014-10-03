/**
 *		Tempesta FW
 *
 * We split traditional filtering logic to two separate pieces:
 * - packet classification (e.g. should we pass or block a packet);
 * - packet action (e.g. drop the packet or close whole TCP connection).
 * Tempesta classifiers are responsible for the first task while filtering
 * modules are responsible for the second one. Different classifiers can emply
 * different policies to service/block packets (e.g. QoS), so typically
 * filtering actions are called by classifiers.
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
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/tcp.h>

#include "tempesta.h"
#include "classifier.h"
#include "filter.h"
#include "log.h"

static TfwFilter *filter = NULL;
static rwlock_t	tfw_fmod_lock = __RW_LOCK_UNLOCKED(tfw_fmod_lock);

static struct {
	__be16		ports[DEF_MAX_PORTS];
	unsigned int	count;
} tfw_inports __read_mostly;

/**
 * Add new blocking rule for the particular IP.
 *
 * The rules work only on 3 and 4 network layers, since only they are managed
 * by current filtering routines. Blocking on all higher layers are provided
 * by GFSM, so classifier can play role of blocking logic: it makes a decision
 * and GFSM is responsible to pass or block a message. This is the way how
 * application level filters must be implemented.
 *
 * XXX Nobody still uses is. Do we need it?
 */
void
tfw_filter_add_rule(struct sock *sk)
{
	struct inet_sock *isk = (struct inet_sock *)sk;

	if (!filter)
		return;

#if IS_ENABLED(CONFIG_IPV6)
		filter->add_rule(isk->inet_saddr,
				 isk->pinet6 ? &isk->pinet6->saddr : NULL);
#else
		filter->add_rule(isk->inet_saddr);
#endif
}

void
tfw_filter_set_inports(__be16 *ports, unsigned int n)
{
	memset(&tfw_inports, 0, sizeof(tfw_inports));
	memcpy(tfw_inports.ports, ports, sizeof(__be16) * n);
	tfw_inports.count = n;
}

/**
 * Check that the incoming packet should be serviced by Tempesta.
 * @return true if it's our packet, false otherwise.
 */
static bool
tfw_our_packet(struct tcphdr *th)
{
	int i;

	for (i = 0; i < tfw_inports.count; ++i)
		if (th->dest == tfw_inports.ports[i])
			return true;
	return false;
}

/**
 * TODO: filter only on front-end interface.
 */
static unsigned int
tfw_nf_hook(struct sk_buff *skb, int ip_ver)
{
	int r;

	/* L3 layer classification. */
	r = (ip_ver == 4) ? tfw_classify_ipv4(skb) : tfw_classify_ipv6(skb);
	switch (r) {
	case TFW_PASS:
		return NF_ACCEPT;
	case TFW_BLOCK:
		return filter ? filter->block(skb) : NF_DROP;
	case TFW_POSTPONE:
		return NF_STOLEN;
	}
	return NF_DROP;
}

static unsigned int
tfw_ipv4_nf_hook(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return tfw_nf_hook(skb, 4);
}

static unsigned int
tfw_ipv6_nf_hook(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return tfw_nf_hook(skb, 6);
}

static struct nf_hook_ops tfw_nf_ops[] __read_mostly = {
	{
		.hook		= tfw_ipv4_nf_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
	{
		.hook		= tfw_ipv6_nf_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_CONNTRACK_DEFRAG + 1,
	},
};

/**
 * Called from sk_filter() called from tcp_v4_rcv() and tcp_v6_rcv(),
 * i.e. when IP fragments are already assembled and we can process TCP.
 */
static int
tfw_sock_tcp_rcv(struct sock *sk, struct sk_buff *skb)
{
	int r;
	struct tcphdr *th = tcp_hdr(skb);

	/* Pass the packet if it's not for us. */
	if (!tfw_our_packet(th))
		return 0;

	/* Call L4 layer classification. */
	r = tfw_classify_tcp(th);
	if (r == TFW_BLOCK)
		return filter ? filter->block(skb) : -EPERM;

	return 0;
}

static TempestaOps tempesta_ops = {
	.sock_tcp_rcv = tfw_sock_tcp_rcv,
};

int
tfw_filter_register(TfwFilter *mod)
{
	write_lock(&tfw_fmod_lock);
	if (filter) {
		write_unlock(&tfw_fmod_lock);
		TFW_ERR("can't register a filter - there is already one"
		        " registered\n");
		return -1;
	}
	filter = mod;
	write_unlock(&tfw_fmod_lock);

	return 0;
}

void
tfw_filter_unregister(void)
{
	write_lock(&tfw_fmod_lock);
	filter = NULL;
	write_unlock(&tfw_fmod_lock);
}

int __init
tfw_filter_init(void)
{
	int r;

	r = nf_register_hooks(tfw_nf_ops, ARRAY_SIZE(tfw_nf_ops));
	if (r) {
		TFW_ERR("can't register netfilter hooks\n");
		return r;
	}

	tempesta_register_ops(&tempesta_ops);

	return r;
}

void __exit
tfw_filter_exit(void)
{
	tempesta_unregister_ops(&tempesta_ops);
	nf_unregister_hooks(tfw_nf_ops, ARRAY_SIZE(tfw_nf_ops));
}
