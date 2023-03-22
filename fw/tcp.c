/**
 *		Tempesta FW
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

void
tfw_tcp_setup_new_skb(struct sock *sk, struct sk_buff *skb,
		      unsigned int mss_now, bool tcp_fragment)
{
	struct sk_buff *next;
	struct tcp_skb_cb *tcb_next, *tcb = TCP_SKB_CB(skb);
	int old_factor;
	u8 flags;

	if (tcp_skb_is_last(sk, skb))
		return;

	next = skb_queue_next(&sk->sk_write_queue, skb);
	tcb_next = TCP_SKB_CB(next);

	/*
	 * All code below was taken from `tso_fragment/tcp_fragment`
	 * functions, besides using `tfw_tcp_propagate_dseq`.
	 */
	tfw_tcp_propagate_dseq(sk, skb);

	/* PSH and FIN should only be set in the second packet. */
	flags = tcb->tcp_flags;
	tcb->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	tcb_next->tcp_flags = flags;

	tcb_next->sacked = tcp_fragment ? TCP_SKB_CB(skb)->sacked : 0;

	tcp_skb_fragment_eor(skb, next);
		
	next->ip_summed = CHECKSUM_PARTIAL;
	if (tcp_fragment)
		next->tstamp = skb->tstamp;
	tcp_fragment_tstamp(skb, next);

	old_factor = tcp_skb_pcount(skb);
	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(next, mss_now);

	if (tcp_fragment) {
		struct tcp_sock *tp = tcp_sk(sk);

		tcb_next->tx = tcb->tx;
		/*
		 * If this packet has been sent out already, we must
		 * adjust the various packet counters.
		 */
		if (!before(tp->snd_nxt, tcb_next->end_seq)) {
			int diff = old_factor - tcp_skb_pcount(skb) -
				tcp_skb_pcount(next);
			if (diff)
				tcp_adjust_pcount(sk, skb, diff);
		}
	}
}
