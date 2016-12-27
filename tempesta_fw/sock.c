/**
 *		Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include <linux/irq_work.h>
#include <linux/module.h>
#include <linux/tempesta.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/ip6_route.h>

#include "addr.h"
#include "log.h"
#include "sync_socket.h"
#include "work_queue.h"

typedef enum {
	SS_SEND,
	SS_CLOSE,
} SsAction;

typedef struct {
	struct sock	*sk;
	SsSkbList	skb_list;
	int		flags;
	SsAction	action;
} SsWork;

#if defined(DEBUG) && (DEBUG >= 2)
static const char *ss_statename[] = {
	"Unused",	"Established",	"Syn Sent",	"Syn Recv",
	"Fin Wait 1",	"Fin Wait 2",	"Time Wait",	"Close",
	"Close Wait",	"Last ACK",	"Listen",	"Closing"
};
#endif

static DEFINE_PER_CPU(TfwRBQueue, si_wq);
static DEFINE_PER_CPU(struct irq_work, ipi_work);

#define SS_CALL(f, ...)							\
	(sk->sk_user_data && ((SsProto *)(sk)->sk_user_data)->hooks->f	\
	? ((SsProto *)(sk)->sk_user_data)->hooks->f(__VA_ARGS__)	\
	: 0)

static void
ss_sock_cpu_check(struct sock *sk, const char *op)
{
	if (unlikely(sk->sk_incoming_cpu != TFW_SK_CPU_INIT
		     && sk->sk_incoming_cpu != smp_processor_id()))
	{
		SS_WARN("Bad socket cpu locality on <%s>:"
			" sk=%p old_cpu=%d curr_cpu=%d\n",
			op, sk, sk->sk_incoming_cpu, smp_processor_id());
	}
}

static void
ss_ipi(struct irq_work *work)
{
	raise_softirq(NET_TX_SOFTIRQ);
}

static int
ss_wq_push(SsWork *sw, bool sync)
{
	int r, cpu = sw->sk->sk_incoming_cpu;
	TfwRBQueue *wq = &per_cpu(si_wq, cpu);
	struct irq_work *iw = &per_cpu(ipi_work, cpu);

	/*
	 * It may happen that there are multiple action requests on
	 * the same socket. Also, a request to close may be started
	 * by the other side of a connection and executed outside
	 * of this work queue. Hold the socket. That way the socket
	 * won't be reused until the scheduled action is completed.
	 * See ss_tx_action().
	 */
	sock_hold(sw->sk);
	if ((r = tfw_wq_push(wq, sw, cpu, iw, ss_ipi, sync))) {
		TFW_WARN("Socket work queue overrun: [%d]\n", sw->action);
		sock_put(sw->sk);
	}
	return r;
}

/*
 * Socket is in a usable state that allows processing
 * and sending of HTTP messages. This function must
 * be used consistently across all involved functions.
 */
static bool
ss_sock_active(struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT);
}

static inline void
ss_skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->tcp_flags = TCPHDR_ACK;
	tcb->sacked  = 0;
	__skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH;
}

/*
 * ------------------------------------------------------------------------
 *  	Server and client connections handling
 * ------------------------------------------------------------------------
 */
/**
 * @skb_list can be invalid after the function call, don't try to use it.
 */
static void
ss_do_send(struct sock *sk, SsSkbList *skb_list, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int size, mss = tcp_send_mss(sk, &size, MSG_DONTWAIT);

	SS_DBG("[%d]: %s: sk=%p queue_empty=%d send_head=%p"
	       " sk_state=%d mss=%d size=%d\n",
	       smp_processor_id(), __func__,
	       sk, tcp_write_queue_empty(sk), tcp_send_head(sk),
	       sk->sk_state, mss, size);

	/* If the socket is inactive, there's no recourse. Drop the data. */
	if (unlikely(!ss_sock_active(sk))) {
		ss_skb_queue_purge(skb_list);
		return;
	}

	ss_sock_cpu_check(sk, "send");

	while ((skb = ss_skb_dequeue(skb_list))) {
		/*
		 * Zero-sized SKBs may appear when the message headers (or any
		 * other contents) are modified or deleted by Tempesta. Drop
		 * these SKBs.
		 */
		if (!skb->len) {
			SS_DBG("[%d]: %s: drop skb=%p data_len=%u len=%u\n",
			       smp_processor_id(), __func__,
			       skb, skb->data_len, skb->len);
			kfree_skb(skb);
			continue;
		}

		skb->ip_summed = CHECKSUM_PARTIAL;
		tcp_skb_pcount_set(skb, 0);

		/* @skb should be rerouted on forwarding. */
		skb_dst_drop(skb);
		/* Clear sender_cpu so flow_disscector can set it properly. */
		skb_sender_cpu_clear(skb);

		SS_DBG("[%d]: %s: entail skb=%p data_len=%u len=%u\n",
		       smp_processor_id(), __func__,
		       skb, skb->data_len, skb->len);

		ss_skb_entail(sk, skb);

		tp->write_seq += skb->len;
		TCP_SKB_CB(skb)->end_seq += skb->len;
	}

	SS_DBG("[%d]: %s: sk=%p send_head=%p sk_state=%d\n",
	       smp_processor_id(), __func__,
	       sk, tcp_send_head(sk), sk->sk_state);

	/*
	 * If connection close flag is specified, then @ss_do_close is used to
	 * set FIN on final SKB and push all pending frames to the stack.
	 */
	if (flags & SS_F_CONN_CLOSE)
		return;

	tcp_push(sk, MSG_DONTWAIT, mss, TCP_NAGLE_OFF|TCP_NAGLE_PUSH, size);
}

/**
 * Directly insert all skbs from @skb_list into @sk TCP write queue regardless
 * write buffer size. This allows directly forward modified packets without
 * copying. See do_tcp_sendpages() and tcp_sendmsg() in linux/net/ipv4/tcp.c.
 *
 * Can be called in softirq context as well as from kernel thread.
 */
int
ss_send(struct sock *sk, SsSkbList *skb_list, int flags)
{
	int r = 0;
	struct sk_buff *skb, *twin_skb;
	SsWork sw = {
		.sk	= sk,
		.flags  = flags,
		.action	= SS_SEND,
	};

	BUG_ON(!sk);
	BUG_ON(ss_skb_queue_empty(skb_list));
	SS_DBG("[%d]: %s: sk=%p (cpu=%d) state=%s\n",
	       smp_processor_id(), __func__,
	       sk, sk->sk_incoming_cpu, ss_statename[sk->sk_state]);
	/*
	 * This isn't reliable check, but rather just an optimization to
	 * avoid expensive work queue operations.
	 */
	if (unlikely(!ss_sock_active(sk)))
		return 0;

	/*
	 * Remove the skbs from Tempesta lists if we won't use them,
	 * or copy them if they're going to be used by Tempesta during
	 * and after the transmission.
	 */
	if (flags & SS_F_KEEP_SKB) {
		ss_skb_queue_head_init(&sw.skb_list);
		for (skb = ss_skb_peek(skb_list); skb; skb = ss_skb_next(skb)) {
			/* tcp_transmit_skb() will clone the skb. */
			twin_skb = pskb_copy_for_clone(skb, GFP_ATOMIC);
			if (!twin_skb) {
				SS_WARN("Unable to copy an egress SKB.\n");
				r = -ENOMEM;
				goto err;
			}
			ss_skb_queue_tail(&sw.skb_list, twin_skb);
		}
	} else {
		sw.skb_list = *skb_list;
		ss_skb_queue_head_init(skb_list);
	}

	/*
	 * Schedule the socket for TX softirq processing.
	 * Only part of @skb_list could be passed to send queue.
	 *
	 * We can't transmit the data escaping the queueing because we have to
	 * order transmissions and other CPUs can push data to transmit for
	 * the socket while current CPU was servicing other sockets.
	 */
	if (ss_wq_push(&sw, flags & SS_F_SYNC)) {
		SS_WARN("Cannot schedule socket %p for transmission\n", sk);
		r = -EBUSY;
		goto err;
	}

	return 0;
err:
	ss_skb_queue_purge(&sw.skb_list);
	return r;
}
EXPORT_SYMBOL(ss_send);

/**
 * This is main body of the socket close function in Sync Sockets.
 *
 * inet_release() can sleep (as well as tcp_close()), so we make our own
 * non-sleepable socket closing.
 *
 * This function must be used only for data sockets.
 * Use standard sock_release() for listening sockets.
 *
 * In most cases it is called in softirq context and from ksoftirqd which
 * processes data from the socket (RSS and RPS distribute packets that way).
 *
 * Note: it used to be called in process context as well, at the time when
 * Tempesta starts or stops. That's not the case right now, but it may change.
 *
 * TODO In some cases we need to close socket agresively w/o FIN_WAIT_2 state,
 * e.g. by sending RST. So we need to add second parameter to the function
 * which says how to close the socket.
 * One of the examples is rcl_req_limit() (it should reset connections).
 * See tcp_sk(sk)->linger2 processing in standard tcp_close().
 *
 * Called with locked socket.
 */
static void
ss_do_close(struct sock *sk)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	if (unlikely(!sk))
		return;
	SS_DBG("[%d]: Close socket %p (%s): account=%d refcnt=%d\n",
	       smp_processor_id(), sk, ss_statename[sk->sk_state],
	       sk_has_account(sk), atomic_read(&sk->sk_refcnt));
	assert_spin_locked(&sk->sk_lock.slock);
	ss_sock_cpu_check(sk, "close");
	BUG_ON(sk->sk_state == TCP_LISTEN);
	/* We must return immediately, so LINGER option is meaningless. */
	WARN_ON(sock_flag(sk, SOCK_LINGER));
	/* We don't support virtual containers, so TCP_REPAIR is prohibited. */
	WARN_ON(tcp_sk(sk)->repair);
	/* The socket must have atomic allocation mask. */
	WARN_ON(!(sk->sk_allocation & GFP_ATOMIC));

	/* The below is mostly copy-paste from tcp_close(). */
	sk->sk_shutdown = SHUTDOWN_MASK;

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		SS_DBG("[%d]: free rcv skb %p\n", smp_processor_id(), skb);
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
	 * SS sockets are processed in softirq only,
	 * so backlog queue should be empty.
	 */
	WARN_ON(sk->sk_backlog.tail);

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

/*
 * This function is for internal Sync Sockets use only. It's called
 * under the socket lock taken by the kernel, and in the context of
 * the socket that is being closed.
 */
static void
ss_droplink(struct sock *sk)
{
	ss_do_close(sk);
	SS_CALL(connection_drop, sk);
	sock_put(sk);	/* paired with ss_do_close() */
}

/**
 * The function should be called with SS_F_SYNC flag whenever possible to
 * improve performance. Without SS_F_SYNC the return value must be checked
 * and the call must be repeated in case of bad return value.
 * Note, that SS_F_SYNC doesn't mean that the socket will be closed immediately,
 * but rather it guarantees that the socket will be closed and the caller can
 * not care about return value.
 */
int
__ss_close(struct sock *sk, int flags)
{
	if (unlikely(!sk))
		return SS_OK;
	sk_incoming_cpu_update(sk);

	if (!(flags & SS_F_SYNC) || !in_softirq()
	    || smp_processor_id() != sk->sk_incoming_cpu)
	{
		SsWork sw = {
			.sk	= sk,
			.flags  = flags,
			.action	= SS_CLOSE,
		};

		return ss_wq_push(&sw, (flags & SS_F_SYNC));
	}

	/*
	 * Don't put the work to work queue if we should execute it on current
	 * CPU and we're in softirq now. We avoid overhead on work queue
	 * operations and prevent infinite loop on synchronous push() if a
	 * consumer is actually the same softirq context.
	 *
	 * Keep in mind possible ordering problem: the socket can already have
	 * a queued work when we close it synchronously, so the socket can be
	 * closed before processing the queued work. That's not a big deal if
	 * the queued work is closing and simply pretend that socket closing
	 * event happened before the socket transmission event.
	 *
	 * The socket is owned by current CPU, so don't need to check its
	 * liveness.
	 */
	bh_lock_sock(sk);
	ss_do_close(sk);
	bh_unlock_sock(sk);
	if (flags & SS_F_CONN_CLOSE)
		SS_CALL(connection_drop, sk);
	sock_put(sk); /* paired with ss_do_close() */

	return SS_OK;
}
EXPORT_SYMBOL(__ss_close);

/*
 * Process a single SKB.
 */
static int
ss_tcp_process_skb(struct sock *sk, struct sk_buff *skb, int *processed)
{
	bool tcp_fin;
	int r = 0, offset, count;
	void *conn;
	SsSkbList skb_list;
	struct tcp_sock *tp = tcp_sk(sk);

	/* Calculate the offset into the SKB. */
	offset = tp->copied_seq - TCP_SKB_CB(skb)->seq;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		offset--;

	/* SKB may be freed in processing. Save the flag. */
	tcp_fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;

	if (ss_skb_unroll(&skb_list, skb)) {
		__kfree_skb(skb);
		return SS_DROP;
	}

	while ((skb = ss_skb_dequeue(&skb_list))) {
		/* We don't expect to see such SKBs here */
		WARN_ON(skb->tail_lock);

		if (unlikely(offset >= skb->len)) {
			offset -= skb->len;
			__kfree_skb(skb);
			continue;
		}

		count = skb->len - offset;
		tp->copied_seq += count;
		*processed += count;

		conn = sk->sk_user_data;
		/*
		 * If @sk_user_data is unset, then this connection
		 * had been dropped in a parallel thread. Dropping
		 * a connection is serialized with the socket lock.
		 * The receive queue must be empty in that case,
		 * and the execution path should never reach here.
		 */
		BUG_ON(conn == NULL);

		r = SS_CALL(connection_recv, conn, skb, offset);

		if (r < 0) {
			SS_DBG("[%d]: Processing error: sk %p r %d\n",
			       smp_processor_id(), sk, r);
			goto out; /* connection dropped */
		} else if (r == SS_STOP) {
			SS_DBG("[%d]: Stop processing: sk %p\n",
			       smp_processor_id(), sk);
			break;
		}
	}
	if (tcp_fin) {
		SS_DBG("[%d]: Data FIN: sk %p\n", smp_processor_id(), sk);
		++tp->copied_seq;
		r = SS_DROP;
	}
out:
	if (!ss_skb_queue_empty(&skb_list))
		ss_skb_queue_purge(&skb_list);

	return r;
}

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
static bool
ss_tcp_process_data(struct sock *sk)
{
	bool droplink = true;
	int r, count, processed = 0;
	unsigned int skb_len, skb_seq;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			SS_WARN("recvmsg bug: TCP sequence gap at seq %X"
				" recvnxt %X\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq);
			goto out;
		}

		__skb_unlink(skb, &sk->sk_receive_queue);
		skb_orphan(skb);

		/* Shared SKBs shouldn't be seen here. */
		if (skb_shared(skb))
			BUG();

		/* Save the original len and seq for reporting. */
		skb_len = skb->len;
		skb_seq = TCP_SKB_CB(skb)->seq;

		count = 0;
		r = ss_tcp_process_skb(sk, skb, &count);
		processed += count;

		if (r < 0)
			goto out;
		else if (r == SS_STOP)
			break;
		else if (!count)
			SS_WARN("recvmsg bug: overlapping TCP segment at %X"
				" seq %X rcvnxt %X len %x\n",
				tp->copied_seq, skb_seq, tp->rcv_nxt, skb_len);
	}
	droplink = false;
out:
	/*
	 * Recalculate an appropriate TCP receive buffer space
	 * and send ACK to a client with the new window.
	 */
	tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);

	return droplink;
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
	SS_DBG("[%d]: %s: sk %p, sk->sk_socket %p, state (%s)\n",
	       smp_processor_id(), __func__,
	       lsk, lsk->sk_socket, ss_statename[lsk->sk_state]);

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
	reqsk_put(req);
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
 */
static void
ss_tcp_data_ready(struct sock *sk)
{
	SS_DBG("[%d]: %s: sk=%p state=%s\n",
	       smp_processor_id(), __func__, sk, ss_statename[sk->sk_state]);
	ss_sock_cpu_check(sk, "recv");
	assert_spin_locked(&sk->sk_lock.slock);

	if (!skb_queue_empty(&sk->sk_error_queue)) {
		/*
		 * Error packet received.
		 * See sock_queue_err_skb() in linux/net/core/skbuff.c.
		 */
		SS_ERR("error data in socket %p\n", sk);
	}
	else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		if (ss_tcp_process_data(sk)) {
			/*
			 * Drop connection in case of internal errors,
			 * banned packets, or FIN in the received packet.
			 *
			 * ss_droplink() is responsible for calling
			 * application layer connection closing callback.
			 * The callback will free all SKBs linked with
			 * the message that is currently being processed.
			 */
			ss_droplink(sk);
		}
	}
	else {
		/*
		 * Check for URG data.
		 * TODO shouldn't we do it in th_tcp_process_data()?
		 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->urg_data & TCP_URG_VALID) {
			tp->urg_data = 0;
			SS_DBG("[%d]: urgent data in socket %p\n",
			       smp_processor_id(), sk);
		}
	}
}

/**
 * Socket state change callback.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	SS_DBG("[%d]: %s: sk=%p state=%s\n",
	       smp_processor_id(), __func__, sk, ss_statename[sk->sk_state]);
	ss_sock_cpu_check(sk, "state change");
	assert_spin_locked(&sk->sk_lock.slock);

	if (sk->sk_state == TCP_ESTABLISHED) {
		/* Process the new TCP connection. */
		SsProto *proto = sk->sk_user_data;
		struct sock *lsk = proto->listener;
		int r;

		/*
		 * The callback is called from tcp_rcv_state_process().
		 *
		 * Server never sends data right after an active connection
		 * opening from our side. Passive open is processed from
		 * tcp_v4_rcv() under the socket lock. So there is no need
		 * for synchronization with ss_tcp_process_data().
		 */
		r = SS_CALL(connection_new, sk);
		if (r) {
			SS_DBG("[%d]: New connection hook failed, r=%d\n",
			       smp_processor_id(), r);
			ss_droplink(sk);
			return;
		}
		if (lsk) {
			/*
			 * This is a new socket for an accepted connect
			 * request that the kernel has allocated itself.
			 * Kernel initializes this field to GFP_KERNEL.
			 * Tempesta works with sockets in SoftIRQ context,
			 * so set it to atomic allocation.
			 */
			sk->sk_allocation = GFP_ATOMIC;

			/*
			 * We know which socket is just accepted.
			 * Just drain listening socket accept queue,
			 * and don't care about the returned socket.
			 */
			assert_spin_locked(&lsk->sk_lock.slock);
			ss_drain_accept_queue(lsk, sk);
		}
	}
	else if (sk->sk_state == TCP_CLOSE_WAIT) {
		/*
		 * Received FIN, connection is being closed.
		 *
		 * When FIN is received from the other side of a connection,
		 * this function is called first before ss_tcp_data_ready()
		 * is called, as the kernel moves the socket's state to
		 * TCP_CLOSE_WAIT. The usual action in Tempesta is to close
		 * the connection.
		 *
		 * It may happen that FIN comes with a data SKB, or there's
		 * still data in the socket's receive queue that hasn't been
		 * processed yet. That data needs to be processed before the
		 * connection is closed.
		 */
		if (!skb_queue_empty(&sk->sk_receive_queue))
			ss_tcp_process_data(sk);
		SS_DBG("[%d]: Peer connection closing\n", smp_processor_id());
		ss_droplink(sk);
	}
	else if (sk->sk_state == TCP_CLOSE) {
		/*
		 * In current implementation we never reach TCP_CLOSE state
		 * in regular course of action. When a socket is moved from
		 * TCP_ESTABLISHED state to a closing state, we forcefully
		 * close the socket before it can reach the final state.
		 *
		 * We get here when an error has occured in the connection.
		 * It could be that RST was received which may happen for
		 * multiple reasons. Or it could be a case of TCP timeout
		 * where the connection appears to be dead. In all of these
		 * cases the socket is moved directly to TCP_CLOSE state
		 * thus skipping all other states.
		 *
		 * It's safe to call the callback since we set socket callbacks
		 * either for just created, not connected, sockets or in the
		 * function above for ESTABLISHED state. sk_state_change()
		 * callback is never called for the same socket concurrently.
		 */
		WARN_ON(!skb_queue_empty(&sk->sk_receive_queue));
		ss_do_close(sk);
		SS_CALL(connection_error, sk);
		sock_put(sk);
	}
}

void
ss_proto_init(SsProto *proto, const SsHooks *hooks, int type)
{
	proto->hooks = hooks;
	proto->type = type;

	/*
	 * The memory allocated for @proto should be already zero'ed, so don't
	 * initialize this field to NULL, but instead check the invariant.
	 */
	BUG_ON(proto->listener);
}
EXPORT_SYMBOL(ss_proto_init);

void
ss_proto_inherit(const SsProto *parent, SsProto *child, int child_type)
{
	*child = *parent;
	child->type |= child_type;
}

/**
 * Make data socket serviced by synchronous sockets.
 *
 * This function is called for each socket that is created by Tempesta.
 * It's run before a socket is bound or connected, so locking is not
 * required at that time. It's also called for each accepted socket,
 * and at that time it's run under the socket lock (see the comment
 * to TCP_ESTABLISHED case in ss_tcp_state_change()).
 */
void
ss_set_callbacks(struct sock *sk)
{
	/*
	 * ss_tcp_state_change() dereferences sk->sk_user_data as SsProto,
	 * so the caller must initialize it before setting callbacks.
	 */
	BUG_ON(!sk->sk_user_data);

	sk->sk_data_ready = ss_tcp_data_ready;
	sk->sk_state_change = ss_tcp_state_change;
}
EXPORT_SYMBOL(ss_set_callbacks);

/**
 * Store listening socket as parent for all accepted connections,
 * and initialize first callbacks.
 *
 * The function is called against just created and still inactive socket,
 * so there is no need for socket synchronization.
 */
void
ss_set_listen(struct sock *sk)
{
	((SsProto *)sk->sk_user_data)->listener = sk;

	sk->sk_state_change = ss_tcp_state_change;
}
EXPORT_SYMBOL(ss_set_listen);

/*
 * Create a new socket for IPv4 or IPv6 protocol. The original functions
 * are inet_create() and inet6_create(). They are nearly identical and
 * only minor details are different. All of them are covered here.
 *
 * NOTE: This code assumes that both IPv4 and IPv6 are compiled in as
 * part of the Linux kernel, and not as separate loadable kernel modules.
 */
static int
ss_inet_create(struct net *net, int family,
	       int type, int protocol, struct sock **nsk)
{
	int err, pfinet;
	struct sock *sk;
	struct inet_sock *inet;
	struct proto *answer_prot;

	/* TCP only is supported for now. */
	BUG_ON(type != SOCK_STREAM || protocol != IPPROTO_TCP);

	/*
	 * Get socket properties.
	 * See inet_protosw and tcpv6_protosw definitions.
	 */
	if (family == AF_INET) {
		pfinet = PF_INET;
		answer_prot = &tcp_prot;
	} else {
		pfinet = PF_INET6;
		answer_prot = &tcpv6_prot;
	}
	WARN_ON(!answer_prot->slab);

	if (!(sk = sk_alloc(net, pfinet, GFP_ATOMIC, answer_prot)))
		return -ENOBUFS;

	inet = inet_sk(sk);
	inet->is_icsk = 1;
	inet->nodefrag = 0;
	inet->inet_id = 0;

	if (net->ipv4.sysctl_ip_no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	sock_init_data(NULL, sk);
	sk->sk_type = type;
	sk->sk_allocation = GFP_ATOMIC;
	sk->sk_incoming_cpu = TFW_SK_CPU_INIT;
	sk->sk_destruct = inet_sock_destruct;
	sk->sk_protocol = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	if (family == AF_INET6) {
		/* The next two lines are inet6_sk_generic(sk) */
		const int offset = sk->sk_prot->obj_size
				   - sizeof(struct ipv6_pinfo);
		struct ipv6_pinfo *np = (struct ipv6_pinfo *)
					(((u8 *)sk) + offset);
		np->hop_limit = -1;
		np->mcast_hops = IPV6_DEFAULT_MCASTHOPS;
		np->mc_loop = 1;
		np->pmtudisc = IPV6_PMTUDISC_WANT;
		sk->sk_ipv6only = net->ipv6.sysctl.bindv6only;
		inet->pinet6 = np;
	}

	inet->uc_ttl = -1;
	inet->mc_loop = 1;
	inet->mc_ttl = 1;
	inet->mc_all = 1;
	inet->mc_index = 0;
	inet->mc_list = NULL;
	inet->rcv_tos = 0;

	sk_refcnt_debug_inc(sk);
	if (sk->sk_prot->init && (err = sk->sk_prot->init(sk))) {
		SS_ERR("cannot create socket, %d\n", err);
		sk_common_release(sk);
		return err;
	}

	*nsk = sk;

	return 0;
}

int
ss_sock_create(int family, int type, int protocol, struct sock **res)
{
	int ret;
	struct sock *sk = NULL;
	const struct net_proto_family *pf;

	rcu_read_lock();
	if ((pf = get_proto_family(family)) == NULL)
		goto out_rcu_unlock;
	if (!try_module_get(pf->owner))
		goto out_rcu_unlock;
	rcu_read_unlock();

	ret = ss_inet_create(&init_net, family, type, protocol, &sk);
	module_put(pf->owner);
	if (ret < 0)
		goto out_module_put;

	*res = sk;
	return 0;

out_module_put:
	module_put(pf->owner);
out_ret_error:
	return ret;
out_rcu_unlock:
	ret = -EAFNOSUPPORT;
	rcu_read_unlock();
	goto out_ret_error;
}
EXPORT_SYMBOL(ss_sock_create);

/*
 * The original functions are inet_release() and inet6_release().
 * NOTE: Rework this function if/when Tempesta needs multicast support.
 */
void
ss_release(struct sock *sk)
{
	BUG_ON(sock_flag(sk, SOCK_LINGER));

	sk->sk_prot->close(sk, 0);
}
EXPORT_SYMBOL(ss_release);

/**
 * The original function is inet_stream_connect() that is common
 * to IPv4 and IPv6.
 */
int
ss_connect(struct sock *sk, struct sockaddr *uaddr, int uaddr_len, int flags)
{
	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	BUG_ON((uaddr->sa_family != AF_INET) && (uaddr->sa_family != AF_INET6));

	if (uaddr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (sk->sk_state != TCP_CLOSE)
		return -EISCONN;

	return sk->sk_prot->connect(sk, uaddr, uaddr_len);
}
EXPORT_SYMBOL(ss_connect);

/*
 * The original functions are inet_bind() and inet6_bind().
 * These two can be made a bit shorter should that become necessary.
 */
int
ss_bind(struct sock *sk, struct sockaddr *uaddr, int uaddr_len)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type
	};
	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	BUG_ON(sk->sk_type != SOCK_STREAM);
	if (sk->sk_family == AF_INET)
		return inet_bind(&sock, uaddr, uaddr_len);
	else
		return inet6_bind(&sock, uaddr, uaddr_len);
}
EXPORT_SYMBOL(ss_bind);

/*
 * The original function is inet_listen() that is common to IPv4 and IPv6.
 * There isn't much to make shorter there, so just invoke it directly.
 */
int
ss_listen(struct sock *sk, int backlog)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type,
		.state = SS_UNCONNECTED
	};
	BUG_ON(sk->sk_type != SOCK_STREAM);
	return inet_listen(&sock, backlog);
}
EXPORT_SYMBOL(ss_listen);

/**
 * Mostly copy-pasted from inet_getname() and inet6_getname().
 * All Tempesta internal operations are with IPv6 addresses only,
 * as with more scalable and backward compatible with IPv4.
 */
void
ss_getpeername(struct sock *sk, TfwAddr *addr)
{
	struct inet_sock *inet = inet_sk(sk);

	if (unlikely(!inet->inet_dport
		     || ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))))
		SS_WARN("%s: bad socket dport=%x state=%x\n", __func__,
			inet->inet_dport, sk->sk_state);

	addr->family = AF_INET6;
	addr->v6.sin6_port = inet->inet_sport;
#if IS_ENABLED(CONFIG_IPV6)
	if (inet6_sk(sk)) {
		struct ipv6_pinfo *np = inet6_sk(sk);
		addr->v6.sin6_addr = sk->sk_v6_daddr;
		addr->v6.sin6_flowinfo = np->sndflow ? np->flow_label : 0;
		addr->in6_prefix = ipv6_iface_scope_id(&addr->v6.sin6_addr,
						       sk->sk_bound_dev_if);
	} else
#endif
	{
		ipv6_addr_set_v4mapped(inet->inet_daddr, &addr->v6.sin6_addr);
		addr->v6.sin6_flowinfo = 0;
		addr->in6_prefix = 0;
	}
}
EXPORT_SYMBOL(ss_getpeername);

#define __sk_close_locked(sk)					\
do {								\
	ss_do_close(sk);					\
	bh_unlock_sock(sk);					\
	SS_CALL(connection_drop, sk);				\
	sock_put(sk); /* paired with ss_do_close() */		\
} while (0)

static void
ss_tx_action(void)
{
	SsWork sw;

	while (!tfw_wq_pop(this_cpu_ptr(&si_wq), &sw)) {
		struct sock *sk = sw.sk;

		bh_lock_sock(sk);
		switch (sw.action) {
		case SS_SEND:
			ss_do_send(sk, &sw.skb_list, sw.flags);
			if (!(sw.flags & SS_F_CONN_CLOSE)) {
				bh_unlock_sock(sk);
				break;
			}
			__sk_close_locked(sk); /* paired with bh_lock_sock() */
			break;
		case SS_CLOSE:
			if (!ss_sock_live(sk)) {
				SS_DBG("[%d]: %s: Socket inactive: sk %p\n",
				       smp_processor_id(), __func__, sk);
				bh_unlock_sock(sk);
				break;
			}
			__sk_close_locked(sk); /* paired with bh_lock_sock() */
			break;
		default:
			BUG();
		}
		sock_put(sk); /* paired with tfw_wq_push() */
	}
}

int __init
tfw_sync_socket_init(void)
{
	int r, cpu;

	TFW_WQ_CHECKSZ(SsWork);
	for_each_possible_cpu(cpu) {
		TfwRBQueue *wq = &per_cpu(si_wq, cpu);
		if ((r = tfw_wq_init(wq, cpu_to_node(cpu)))) {
			SS_ERR("Cannot initialize softirq tx work queue\n");
			return r;
		}
		init_irq_work(&per_cpu(ipi_work, cpu), ss_ipi);
	}
	tempesta_set_tx_action(ss_tx_action);

	return 0;
}

void
tfw_sync_socket_exit(void)
{
	int cpu;

	tempesta_del_tx_action();
	for_each_possible_cpu(cpu) {
		irq_work_sync(&per_cpu(ipi_work, cpu));
		/*
		 * FIXME the work queue can be destroyed from under
		 * softirq TX handler.
		 */
		tfw_wq_destroy(&per_cpu(si_wq, cpu));
	}
}
