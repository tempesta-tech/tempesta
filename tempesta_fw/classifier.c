/**
 *		Tempesta FW
 *
 * Interface to classification modules.
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

/*
 * TODO:
 * -- add socket/connection options adjusting to change client QoS
 */

#include "tempesta.h"
#include "classifier.h"
#include "lib/log.h"

static TfwClassifier *classifier = NULL;
static rwlock_t	tfw_class_lock = __RW_LOCK_UNLOCKED(tfw_class_lock);

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
	return (classifier && classifier->classify_ipv4)
		? classifier->classify_ipv4(skb)
		: TFW_PASS;
}

int
tfw_classify_ipv6(struct sk_buff *skb)
{
	return (classifier && classifier->classify_ipv6)
		? classifier->classify_ipv6(skb)
		: TFW_PASS;
}

int
tfw_classify_tcp(struct tcphdr *th)
{
	return (classifier && classifier->classify_tcp)
		? classifier->classify_tcp(th)
		: TFW_PASS;
}

int
tfw_classify_conn_estab(struct sock *sk)
{
	return (classifier && classifier->classify_conn_estab)
		? classifier->classify_conn_estab(sk)
		: TFW_PASS;
}

int
tfw_classify_conn_close(struct sock *sk)
{
	return (classifier && classifier->classify_conn_close)
		? classifier->classify_conn_close(sk)
		: TFW_PASS;
}

int
tfw_classifier_register(TfwClassifier *mod)
{
	write_lock(&tfw_class_lock);
	if (classifier) {
		write_unlock(&tfw_class_lock);
		TFW_ERR("can't register a classifier - there is already one"
		        " registered\n");
		return -1;
	}
	classifier = mod;
	write_unlock(&tfw_class_lock);

	return 0;
}
EXPORT_SYMBOL(tfw_classifier_register);

void
tfw_classifier_unregister(void)
{
	write_lock(&tfw_class_lock);
	classifier = NULL;
	write_unlock(&tfw_class_lock);
}
EXPORT_SYMBOL(tfw_classifier_unregister);
