/**
 *		Tempesta FW
 *
 * Interface to classification modules.
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
/*
 * TODO:
 * -- add socket/connection options adjusting to change client QoS
 */
#include "tempesta_fw.h"
#include "addr.h"
#include "classifier.h"
#include "log.h"

static struct {
	__be16		ports[DEF_MAX_PORTS];
	unsigned int	count;
} tfw_inports __read_mostly;

static TfwClassifier __rcu *classifier = NULL;

/**
 * Shrink client connections hash and/or reduce QoS for blocked clients to
 * lower back-end servers or local system load.
 */
void
tfw_classify_shrink(void)
{
	/* TODO: delete a connection from the LRU */
}

int
tfw_classify_ipv4(struct sk_buff *skb)
{
	int r;
	TfwClassifier *clfr;

	rcu_read_lock();

	clfr = rcu_dereference(classifier);
	r = (clfr && clfr->classify_ipv4)
	    ? clfr->classify_ipv4(skb)
	    : TFW_PASS;

	rcu_read_unlock();

	return r;
}

int
tfw_classify_ipv6(struct sk_buff *skb)
{
	int r;
	TfwClassifier *clfr;

	rcu_read_lock();

	clfr = rcu_dereference(classifier);
	r = (clfr && clfr->classify_ipv6)
	    ? clfr->classify_ipv6(skb)
	    : TFW_PASS;

	rcu_read_unlock();

	return r;
}

void
tfw_classifier_add_inport(__be16 port)
{
	BUG_ON(tfw_inports.count == DEF_MAX_PORTS - 1);

	tfw_inports.ports[tfw_inports.count++] = port;
}

void
tfw_classifier_cleanup_inport(void)
{
	memset(&tfw_inports, 0, sizeof(tfw_inports));
}

static int
tfw_classify_conn_estab(struct sock *sk)
{
	int i;
	unsigned short sport = tfw_addr_get_sk_sport(sk);
	TfwClassifier *clfr;

	/* Pass the packet if it's not for us. */
	for (i = 0; i < tfw_inports.count; ++i)
		if (sport == tfw_inports.ports[i])
			goto ours;
	return TFW_PASS;

ours:
	rcu_read_lock();

	clfr = rcu_dereference(classifier);
	i = (clfr && clfr->classify_conn_estab)
	    ? clfr->classify_conn_estab(sk)
	    : TFW_PASS;

	rcu_read_unlock();

	return i;
}

static void
tfw_classify_conn_close(struct sock *sk)
{
	TfwClassifier *clfr = rcu_dereference(classifier);

	if (clfr && clfr->classify_conn_close)
		clfr->classify_conn_close(sk);
}

/**
 * Called from sk_filter() called from tcp_v4_rcv() and tcp_v6_rcv(),
 * i.e. when IP fragments are already assembled and we can process TCP.
 */
static int
tfw_classify_tcp(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	TfwClassifier *clfr = rcu_dereference(classifier);

	return clfr && clfr->classify_tcp ? clfr->classify_tcp(th) : TFW_PASS;
}

/*
 * tfw_classifier_register() and tfw_classifier_unregister()
 * are called at Tempesta start/stop time. The execution is
 * serialized with a mutex. There's no need for additional
 * protection of rcu_assign_pointer() from concurrent use.
 */
void
tfw_classifier_register(TfwClassifier *mod)
{
	TFW_LOG("Registering new classifier: %s\n", mod->name);

	BUG_ON(classifier);
	rcu_assign_pointer(classifier, mod);
}
EXPORT_SYMBOL(tfw_classifier_register);

void
tfw_classifier_unregister(void)
{
	TFW_LOG("Unregistering classifier: %s\n", classifier->name);

	rcu_assign_pointer(classifier, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(tfw_classifier_unregister);

static TempestaOps tempesta_ops = {
	.sk_alloc	= tfw_classify_conn_estab,
	.sk_free	= tfw_classify_conn_close,
	.sock_tcp_rcv	= tfw_classify_tcp,
};

int __init
tfw_classifier_init(void)
{
	tempesta_register_ops(&tempesta_ops);

	return 0;
}

void
tfw_classifier_exit(void)
{
	tempesta_unregister_ops(&tempesta_ops);
}
