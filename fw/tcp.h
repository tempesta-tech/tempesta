/**
 *		TCP Socket API.
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
#ifndef __TFW_TCP_H__
#define __TFW_TCP_H__

#include <linux/skbuff.h>

void tfw_tcp_propagate_dseq(struct sock *sk, struct sk_buff *skb);
void tfw_tcp_setup_new_skb(struct sock *sk, struct sk_buff *skb,
			   struct sk_buff *nskb, unsigned int mss_now);

/*
 * Calculate window size to send in bytes. We calculate the sender
 * and receiver window and select the smallest of them.
 * We ajust also @not_account_in_flight counf of skbs, which were
 * previously pushed to socket write queue. In `tcp_write_xmit`
 * main loop cong_win is calculated on each loop iteration and
 * if we calculate `cong_win` for making frames without taking
 * into account previously pushed skbs we push more data into
 * socket write queue then we can send.
 */
static inline unsigned long
tfw_tcp_calc_snd_wnd(struct sock *sk, unsigned int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int in_flight = tcp_packets_in_flight(tp);
	unsigned int qlen =  skb_queue_len(&sk->sk_write_queue);
	unsigned int send_win, cong_win;

	if (in_flight + qlen >= tp->snd_cwnd)
		return 0;

	if (after(tp->write_seq, tcp_wnd_end(tp)))
		return 0;

	cong_win = (tp->snd_cwnd - in_flight - qlen) * mss_now;
	send_win = tcp_wnd_end(tp) - tp->write_seq;
	return min(cong_win, send_win);
}

#endif /* __TFW_TCP_H__ */
