/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#include <net/tcp.h>

#include "tcp.h"
#include "log.h"

/**
 * Propagate TCP correct sequence numbers from the current @skb to the next one
 * on TCP write queue. So that tcp_send_head() always point to an skb with the
 * right sequence numbers.
 */
void
tfw_tcp_propagate_dseq(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff *next;
	struct tcp_skb_cb *tcb_next, *tcb = TCP_SKB_CB(skb);

	if (tcp_skb_is_last(sk, skb))
		return;

	next = skb_queue_next(&sk->sk_write_queue, skb);
	tcb_next = TCP_SKB_CB(next);

	WARN_ON_ONCE((tcb_next->seq || tcb_next->end_seq)
		     && tcb_next->seq + next->len
			+ !!(tcb_next->tcp_flags & TCPHDR_FIN)
			!= tcb_next->end_seq);

	tcb_next->seq = tcb->end_seq;
	tcb_next->end_seq = tcb_next->seq + next->len;
	if (tcb_next->tcp_flags & TCPHDR_FIN)
		tcb_next->end_seq++;
}

/*
 * Setup all necessary fields for a new skb and insert it in the
 * sk write queue. There is a case when we allocate new skb during
 * processing skb in `xmit` callback. We should setup this new skb
 * and insert it into skb write queue in right way. Most of code
 * below was taken from `tso_fragment/tcp_fragment` functions,
 * besides using `tfw_tcp_propagate_dseq`.
 */
void
tfw_tcp_setup_new_skb(struct sock *sk, struct sk_buff *skb,
		      struct sk_buff *nskb, unsigned int mss_now)
{
	struct tcp_skb_cb *tcb_nskb = TCP_SKB_CB(nskb), *tcb = TCP_SKB_CB(skb);
	int old_factor;
	u8 flags;
	const bool tcp_fragment = skb->len != skb->data_len;

	INIT_LIST_HEAD(&nskb->tcp_tsorted_anchor);
	skb_shinfo(nskb)->flags = 0;
	memset(TCP_SKB_CB(nskb), 0, sizeof(struct tcp_skb_cb));

	/* PSH and FIN should only be set in the second packet. */
	flags = tcb->tcp_flags;
	tcb->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	tcb_nskb->tcp_flags = flags;

	/* Correct the sequence numbers. */
	tcb_nskb->seq = tcb->end_seq;
	tcb_nskb->end_seq = tcb_nskb->seq + nskb->len;
	if (tcb_nskb->tcp_flags & TCPHDR_FIN)
		tcb_nskb->end_seq++;

	tcb_nskb->sacked = tcp_fragment ? TCP_SKB_CB(skb)->sacked : 0;

	tcp_skb_fragment_eor(skb, nskb);
		
	nskb->ip_summed = CHECKSUM_PARTIAL;
	if (tcp_fragment)
		nskb->tstamp = skb->tstamp;
	tcp_fragment_tstamp(skb, nskb);

	old_factor = tcp_skb_pcount(skb);
	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(nskb, mss_now);

	if (tcp_fragment) {
		struct tcp_sock *tp = tcp_sk(sk);

		tcb_nskb->tx = tcb->tx;
		/*
		 * If this packet has been sent out already, we must
		 * adjust the various packet counters.
		 */
		if (!before(tp->snd_nxt, tcb_nskb->end_seq)) {
			int diff = old_factor - tcp_skb_pcount(skb) -
				tcp_skb_pcount(nskb);
			if (diff)
				tcp_adjust_pcount(sk, skb, diff);
		}
	}

	/* Link nskb into the send queue. */
	__skb_header_release(nskb);
	__skb_queue_after(&sk->sk_write_queue, skb, nskb);
}
