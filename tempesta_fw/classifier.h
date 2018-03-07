/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#ifndef __TFW_CLASSIFIER__
#define __TFW_CLASSIFIER__

#include <linux/in6.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tempesta_fw.h"
#include "connection.h"

/* Size of classifier private cliet accounting data. */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
#define TFW_CLASSIFIER_ACCSZ	512
#else
#define TFW_CLASSIFIER_ACCSZ	256
#endif

typedef struct { char _[TFW_CLASSIFIER_ACCSZ]; } TfwClassifierPrvt;

/*
 * Classification module handler.
 *
 * TODO:
 * -- modules should have possibility to register number of classifier callbacks,
 *    so store the callback in fixed size array, so we can quickly determine which
 *    callbacks (if either) we need to call.
 */
typedef struct {
	char	*name;
	/*
	 * Classify a client on network L3 layer.
	 */
	int	(*classify_ipv4)(struct sk_buff *skb);
	int	(*classify_ipv6)(struct sk_buff *skb);
	/*
	 * Classify TCP segments.
	 */
	int	(*classify_tcp)(struct tcphdr *th);
	/*
	 * Called when a new client connection is established (many TCP SYNs
	 * can precede an established connection, so it's more efficient to
	 * handle events for established and closed.
	 */
	int	(*classify_conn_estab)(struct sock *sk);
	/*
	 * Called when a client connection closed.
	 */
	void	(*classify_conn_close)(struct sock *sk);
	/*
	 * TODO called on retransmits to client (e.g. SYN+ACK or data).
	 */
	int	(*classify_tcp_timer_retrans)(void);
	/*
	 * TODO called on sending TCP keep alive segments.
	 */
	int	(*classify_tcp_timer_keepalive)(void);
	/*
	 * TODO called when we choose our window size to report to client.
	 */
	int	(*classify_tcp_window)(void);
	/*
	 * TODO called when peer reported zero window, so we can't send data
	 * and must send TCP zero window probing segments.
	 */
	int	(*classify_tcp_zwp)(void);
} TfwClassifier;

void tfw_classifier_add_inport(__be16 port);
void tfw_classifier_cleanup_inport(void);

void tfw_classify_shrink(void);

int tfw_classify_ipv4(struct sk_buff *skb);
int tfw_classify_ipv6(struct sk_buff *skb);

extern void tfw_classifier_register(TfwClassifier *mod);
extern void tfw_classifier_unregister(void);

#endif /* __TFW_CLASSIFIER__ */
