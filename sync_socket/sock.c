/**
 *		Synchronous Socket API.
 *
 * Generic socket routines.
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
 * -- Read cache objects by 64KB and use GSO?
 */
#include <linux/highmem.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <net/inet_common.h>

#include "log.h"
#include "sync_socket.h"

MODULE_AUTHOR("NatSys Lab. (http://natsys-lab.com)");
MODULE_DESCRIPTION("Linux Kernel Synchronous Sockets");
MODULE_VERSION("0.4.3");
MODULE_LICENSE("GPL");

static SsHooks *ss_hooks __read_mostly;

#define SS_CALL(f, ...)		(ss_hooks->f ? ss_hooks->f(__VA_ARGS__) : 0)

/*
 * ------------------------------------------------------------------------
 *  	Server and client connections handling
 * ------------------------------------------------------------------------
 */
/**
 * Directly insert all skbs from @skb_list into @sk TCP write queue regardless
 * write buffer size. This allows directly forward modified packets without
 * copying.
 * See do_tcp_sendpages() and tcp_sendmsg() in linux/net/ipv4/tcp.c.
 *
 * Called in softirq context.
 *
 * TODO use MSG_MORE untill we reach end of message.
 */
void
ss_send(struct sock *sk, const SsSkbList *skb_list)
{
	struct sk_buff *skb;
	struct tcp_skb_cb *tcb;
	struct tcp_sock *tp = tcp_sk(sk);
	int flags = MSG_DONTWAIT; /* we can't sleep */
	int size_goal, mss_now;

	bh_lock_sock_nested(sk);

	mss_now = tcp_send_mss(sk, &size_goal, flags);

	BUG_ON(ss_skb_queue_empty(skb_list));
	for (skb = ss_skb_peek(skb_list), tcb = TCP_SKB_CB(skb);
	     skb; skb = ss_skb_next(skb_list, skb))
	{
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_shinfo(skb)->gso_segs = 0;

		/*
		 * TODO
		 * Mark all data with PUSH to force receiver to consume
		 * the data. Currently we do this in debugging purpose.
		 * We need to do this only for complete messages/skbs.
		 * (Actually tcp_push() already does it for the last skb.)
		 */
		tcp_mark_push(tp, skb);

		SS_DBG("%s:%d entail skb=%p data_len=%u len=%u\n",
		       __FUNCTION__, __LINE__, skb, skb->data_len, skb->len);

		skb_entail(sk, skb);

		tcb->end_seq += skb->len;
		tp->write_seq += skb->len;
	}

	SS_DBG("%s:%d sk=%p is_queue_empty=%d tcp_send_head(sk)=%p"
	       " sk->sk_state=%d\n", __FUNCTION__, __LINE__,
	       sk, tcp_write_queue_empty(sk), tcp_send_head(sk), sk->sk_state);

	tcp_push(sk, flags, mss_now, TCP_NAGLE_OFF|TCP_NAGLE_PUSH);

	bh_unlock_sock(sk);
}
EXPORT_SYMBOL(ss_send);

static int
ss_tcp_process_proto_skb(struct sock *sk, unsigned char *data, size_t len,
			 struct sk_buff *skb)
{
	int r = SS_CALL(put_skb_to_msg, sk->sk_user_data, skb);
	if (r != SS_OK)
		return r;

	r = SS_CALL(connection_recv, sk, data, len);
	if (r == SS_POSTPONE) {
		SS_CALL(postpone_skb, sk->sk_user_data, skb);
		r = SS_OK;
	}

	return r;
}

/**
 * Process a socket buffer.
 * See standard skb_copy_datagram_iovec() implementation.
 * @return SS_OK, SS_DROP or negative value of error code.
 *
 * In any case returns with @skb passed to application layer.
 * We don't manege the skb any more.
 */
static int
ss_tcp_process_skb(struct sk_buff *skb, struct sock *sk, unsigned int off,
		   int *count)
{
	int i, r = SS_OK;
	int lin_len = skb_headlen(skb);
	struct sk_buff *frag_i;

	/* Process linear data. */
	if (off < lin_len) {
		r = ss_tcp_process_proto_skb(sk, skb->data + off,
					     lin_len - off, skb);
		if (r < 0)
			return r;
		*count += lin_len - off;
		off = 0;
	} else
		off -= lin_len;

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int frag_size = skb_frag_size(frag);
		if (frag_size > off) {
			unsigned char *frag_addr = skb_frag_address(frag);

			r = ss_tcp_process_proto_skb(sk, frag_addr + off,
						     frag_size - off, skb);
			if (r < 0)
				return r;
			*count += frag_size - off;
			off = 0;
		} else
			off -= frag_size;
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		if (frag_i->len > off) {
			r = ss_tcp_process_skb(frag_i, sk, off, count);
			if (r < 0)
				return r;
			off = 0;
		} else
			off -= frag_i->len;
	}

	return r;
}

/**
 * inet_release() can sleep (as well as tcp_close()), so we make our own
 * non-sleepable socket closing.
 *
 * This function must be used only for data sockets.
 * Use standard sock_release() for listening sockets.
 *
 * In most cases it's called from softirq and from softirqd which processes data
 * from the socket (RSS and RPS distributes packets in such way).
 * However, it also can be called from process context,
 * e.g. on module unloading.
 *
 * TODO In some cases we need to close socket agresively w/o FIN_WAIT_2 state,
 * e.g. by sending RST. So we need to add second parameter to the function
 * which says how to close the socket.
 * One of the examples is rcl_req_limit() (it should reset connections).
 * See tcp_sk(sk)->linger2 processing in standard tcp_close().
 */
static void
ss_do_close(struct sock *sk)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	SS_DBG("Close socket %p (account=%d)\n",
		sk, sk_has_account(sk));

	if (unlikely(!sk))
		return;

	BUG_ON(sk->sk_state == TCP_LISTEN);
	/* Don't try to close unassigned socket. */
	BUG_ON(!sk->sk_user_data);

	SS_CALL(connection_drop, sk);

	sock_rps_reset_flow(sk);

	/*
	 * Sanity checks.
	 */
	/* We must return immediately, so LINGER option is meaningless. */
	WARN_ON(sock_flag(sk, SOCK_LINGER));
	/* We don't support virtual containers, so TCP_REPAIR is prohibited. */
	WARN_ON(tcp_sk(sk)->repair);
	/* The socket must have atomic allocation mask. */
	WARN_ON(!(sk->sk_allocation & GFP_ATOMIC));

	/*
	 * The below is mostly copy-paste from tcp_close().
	 */
	sk->sk_shutdown = SHUTDOWN_MASK;

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		SS_DBG("free rcv skb %p\n", skb);
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	if (data_was_unread) {
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, sk->sk_allocation);
	}
	else if (tcp_close_state(sk)) {
		/* The code below is taken from tcp_send_fin(). */
		struct tcp_sock *tp = tcp_sk(sk);
		int mss_now = tcp_current_mss(sk);

		skb = tcp_write_queue_tail(sk);

		if (tcp_send_head(sk) != NULL) {
			/* Send FIN with data if we have any. */
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
			TCP_SKB_CB(skb)->end_seq++;
			tp->write_seq++;
		}
		else {
			/* No data to send in the socket, allocate new skb. */
			skb = alloc_skb_fclone(MAX_TCP_HEADER,
					       sk->sk_allocation);
			if (!skb) {
				SS_WARN("can't send FIN due to bad alloc");
			} else {
				skb_reserve(skb, MAX_TCP_HEADER);
				tcp_init_nondata_skb(skb, tp->write_seq,
						     TCPHDR_ACK | TCPHDR_FIN);
				tcp_queue_skb(sk, skb);
			}
		}
		__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);
	}

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	/*
	 * release_sock(sk) w/o sleeping.
	 *
	 * We're in softirq and there is no other socket users,
	 * so don't acquire sk->sk_lock.
	 */
	if (sk->sk_backlog.tail) {
		skb = sk->sk_backlog.head;
		do {
			sk->sk_backlog.head = sk->sk_backlog.tail = NULL;
			do {
				struct sk_buff *next = skb->next;
				prefetch(next);
				WARN_ON_ONCE(skb_dst_is_noref(skb));
				/*
				 * We're in active closing state,
				 * so there is nobody interesting in receiving
				 * data.
				 */
				SS_DBG("free backlog skb %p\n", skb);
				__kfree_skb(skb);
				skb = next;
			} while (skb != NULL);
		} while ((skb = sk->sk_backlog.head) != NULL);
	}
	sk->sk_backlog.len = 0;
	if (sk->sk_prot->release_cb)
		sk->sk_prot->release_cb(sk);
	sk->sk_lock.owned = 0;

	percpu_counter_inc(sk->sk_prot->orphan_count);

	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		return;

	if (sk->sk_state == TCP_FIN_WAIT2) {
		const int tmo = tcp_fin_time(sk);
		if (tmo > TCP_TIMEWAIT_LEN) {
			inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
		} else {
			tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
			return;
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_check_oom(sk, 0)) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					 LINUX_MIB_TCPABORTONMEMORY);
		}
	}
	if (sk->sk_state == TCP_CLOSE) {
		struct request_sock *req = tcp_sk(sk)->fastopen_rsk;
		if (req != NULL)
			reqsk_fastopen_remove(sk, req, false);
		inet_csk_destroy_sock(sk);
	}
}

void
ss_close(struct sock *sk)
{
	local_bh_disable();
	bh_lock_sock_nested(sk);

	ss_do_close(sk);

	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}
EXPORT_SYMBOL(ss_close);

/**
 * Receive data on TCP socket. Very similar to standard tcp_recvmsg().
 *
 * We can't use standard tcp_read_sock() with our actor callback, because
 * tcp_read_sock() calls __kfree_skb() through sk_eat_skb() which is good
 * for copying data from skb, but we need to manage skb's ourselves.
 *
 * TODO:
 * -- process URG
 */
static void
ss_tcp_process_data(struct sock *sk)
{
	int processed = 0;
	unsigned int off;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			SS_WARN("recvmsg bug: TCP sequence gap at seq %X"
				" recvnxt %X\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq);
			ss_do_close(sk);
			return;
		}

		__skb_unlink(skb, &sk->sk_receive_queue);

		off = tp->copied_seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			off--;
		if (off < skb->len) {
			int count = 0;
			int r = ss_tcp_process_skb(skb, sk, off, &count);
			if (r < 0) {
				SS_WARN("can't process app data on socket %p\n",
					sk);
				/*
				 * Drop connection on internal errors as well as
				 * on banned packets.
				 *
				 * ss_do_close() is responsible for calling
				 * application layer connection closing callback
				 * which will free all the passed and linked
				 * with currently processed message skbs.
				 */
				__kfree_skb(skb);
				ss_do_close(sk);
				goto out; /* connection dropped */
			}
			tp->copied_seq += count;
			processed += count;
		}
		else if (tcp_hdr(skb)->fin) {
			SS_DBG("received FIN, do active close\n");
			++tp->copied_seq;
			ss_do_close(sk);
			__kfree_skb(skb);
		}
		else {
			SS_WARN("recvmsg bug: overlapping TCP segment at %X"
				" seq %X rcvnxt %X len %x\n",
			       tp->copied_seq, TCP_SKB_CB(skb)->seq,
			       tp->rcv_nxt, skb->len);
			__kfree_skb(skb);
		}
	}
out:
	/*
	 * Recalculate the appropriate TCP receive buffer space and
	 * send ACK to the client with new window.
	 */
	tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);
}

/**
 * Just drain accept queue of listening socket &lsk.
 * See implementation of standard inet_csk_accept().
 */
static void
ss_drain_accept_queue(struct sock *lsk, struct sock *nsk)
{
	struct inet_connection_sock *icsk = inet_csk(lsk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
#if 0
	struct request_sock *prev_r, *req;
#else
	struct request_sock *req;
#endif

	/* Currently we process TCP only. */
	BUG_ON(lsk->sk_protocol != IPPROTO_TCP);

	WARN(reqsk_queue_empty(queue),
	     "drain empty accept queue for socket %p", lsk);

#if 0
	/* TODO it works to slowly, need to patch Linux kernel to make it faster. */
	for (prev_r = NULL, req = queue->rskq_accept_head; req;
	     prev_r = req, req = req->dl_next)
	{
		if (req->sk != nsk)
			continue;
		/* We found the socket, remove it. */
		if (prev_r) {
			/* There are some items before @req in the queue. */
			prev_r->dl_next = req->dl_next;
			if (queue->rskq_accept_tail == req)
				/* @req is the last item. */
				queue->rskq_accept_tail = prev_r;
		} else {
			/* @req is the first item in the queue. */
			queue->rskq_accept_head = req->dl_next;
			if (queue->rskq_accept_head == NULL)
				/* The queue contained only this one item. */
				queue->rskq_accept_tail = NULL;
		}
		break;
	}
#else
	/*
	 * FIXME push any request from the queue,
	 * doesn't matter which exactly.
	 */
	req = reqsk_queue_remove(queue);
#endif
	BUG_ON(!req);
	sk_acceptq_removed(lsk);

	/*
	 * @nsk is in ESTABLISHED state, so 3WHS has completed and
	 * we can safely remove the request socket from accept queue of @lsk.
	 */
	__reqsk_free(req);
}

/*
 * ------------------------------------------------------------------------
 *  	Socket callbacks
 * ------------------------------------------------------------------------
 */
static void ss_tcp_state_change(struct sock *sk);

/*
 * Called when a new data received on the socket.
 * Called under bh_lock_sock_nested(sk) (see tcp_v4_rcv()).
 *
 * XXX ./net/ipv4/tcp_* call sk_data_ready() with 0 as the value of @bytes.
 * This seems wrong.
 */
static void
ss_tcp_data_ready(struct sock *sk, int bytes)
{
	if (!skb_queue_empty(&sk->sk_error_queue)) {
		/*
		 * Error packet received.
		 * See sock_queue_err_skb() in linux/net/core/skbuff.c.
		 */
		SS_ERR("error data on socket %p\n", sk);
	}
	else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		ss_tcp_process_data(sk);
	}
	else {
		/*
		 * Check for URG data.
		 * TODO shouldn't we do it in th_tcp_process_data()?
		 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->urg_data & TCP_URG_VALID) {
			tp->urg_data = 0;
			SS_DBG("urgent data on socket %p\n", sk);
		}
	}
}

/**
 * Socket failover.
 */
static void
ss_tcp_error(struct sock *sk)
{
	SS_DBG("process error on socket %p\n", sk);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);
}

/**
 * We're working with the sockets in softirq, so set allocations atomic.
 */
static void
ss_set_sock_atomic_alloc(struct sock *sk)
{
	sk->sk_allocation = GFP_ATOMIC;
}

/**
 * Make the data socket serviced by synchronous sockets.
 */
void
ss_set_callbacks(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);

	ss_set_sock_atomic_alloc(sk);

	sk->sk_data_ready = ss_tcp_data_ready;
	sk->sk_state_change = ss_tcp_state_change;
	sk->sk_error_report = ss_tcp_error;

	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_set_callbacks);

/**
 * Socket state change callback.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED) {
		/* Process the new TCP connection. */

		SsProto *proto = sk->sk_user_data;
		struct socket *lsk = proto->listener;
		int r;

		BUG_ON(!lsk);

		/* The callback is called from tcp_rcv_state_process(). */
		r = SS_CALL(connection_new, sk);
		if (r) {
			ss_do_close(sk);
			return;
		}

		ss_set_callbacks(sk);

		/*
		 * We know which socket is just accepted, so we just
		 * drain listening socket accept queue and don't care
		 * about returned socket.
		 */
		assert_spin_locked(&lsk->sk->sk_lock.slock);
		ss_drain_accept_queue(lsk->sk, sk);
	}
	else if (sk->sk_state == TCP_CLOSE_WAIT) {
		/*
		 * Connection has received FIN.
		 *
		 * FIXME it seems we should to do things below on TCP_CLOSE
		 * instead of TCP_CLOSE_WAIT.
		 */
		ss_do_close(sk);
	}
}

/**
 * Set protocol handler and initialize first callbacks.
 */
void
ss_tcp_set_listen(struct socket *sock, SsProto *handler)
{
	struct sock *sk = sock->sk;

	write_lock_bh(&sk->sk_callback_lock);

	BUG_ON(sk->sk_user_data);

	ss_set_sock_atomic_alloc(sk);

	sk->sk_state_change = ss_tcp_state_change;
	sk->sk_user_data = handler;
	handler->listener = sock;

	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_tcp_set_listen);

/*
 * ------------------------------------------------------------------------
 *  	Sockets initialization
 * ------------------------------------------------------------------------
 */

/*
 * FIXME Only one user for now, don't care about registration races.
 */
int
ss_hooks_register(SsHooks* hooks)
{
	if (ss_hooks)
		return -EEXIST;

	ss_hooks = hooks;

	return 0;
}
EXPORT_SYMBOL(ss_hooks_register);

void
ss_hooks_unregister(SsHooks* hooks)
{
	BUG_ON(hooks != ss_hooks);
	ss_hooks = NULL;
}
EXPORT_SYMBOL(ss_hooks_unregister);

int __init
ss_init(void)
{
	return 0;
}

void __exit
ss_exit(void)
{
}

module_init(ss_init);
module_exit(ss_exit);
