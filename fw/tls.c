/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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
#undef DEBUG
#if DBG_TLS > 0
#define DEBUG DBG_TLS
#endif

#include "cfg.h"
#include "connection.h"
#include "client.h"
#include "msg.h"
#include "procfs.h"
#include "http.h"
#include "http_frame.h"
#include "http_limits.h"
#include "tls.h"
#include "vhost.h"
#include "lib/hash.h"

/**
 * Global level TLS configuration.
 *
 * @cfg			- common tls configuration for all vhosts;
 * @allow_any_sni	- If set, all the unknown SNI are matched to default
 *			  vhost.
 */
static struct {
	TlsCfg		cfg;
	bool		allow_any_sni;
} tfw_tls;

/* Temporal value for reconfiguration stage. */
static bool allow_any_sni_reconfig;

static inline void
tfw_tls_purge_io_ctx(TlsIOCtx *io)
{
	struct sk_buff *skb;

	while ((skb = ss_skb_dequeue(&io->skb_list)))
		kfree_skb(skb);
	ttls_reset_io_ctx(io);
}

/**
 * A connection has been lost during handshake processing, warn Frang.
 * It's relatively cheap to pass SYN cookie and then send previously captured
 * or randomly forged TLS handshakes. No calculations are required on a client
 * side then.
 */
void
tfw_tls_connection_lost(TfwConn *conn)
{
	TlsCtx *tls = &((TfwTlsConn *)conn)->tls;

	if (!ttls_hs_done(tls))
		frang_tls_handler(tls, TTLS_HS_CB_FINISHED_RESUMED);
}

int
tfw_tls_msg_process(void *conn, struct sk_buff *skb)
{
	int r, parsed;
	struct sk_buff *nskb = NULL;
	TlsCtx *tls = tfw_tls_context(conn);
	TfwFsmData data_up = {};

	/*
	 * Perform TLS handshake if necessary and decrypt the TLS message
	 * in-place by chunks. Add skb to the list to build scatterlist if
	 * it contains end of current message.
	 */
next_msg:
	spin_lock(&tls->lock);
	ss_skb_queue_tail(&tls->io_in.skb_list, skb);

	/* Call TLS layer to place skb into a TLS record on top of skb_list. */
	parsed = 0;
	r = ss_skb_process(skb, ttls_recv, tls, &tls->io_in.chunks, &parsed);
	switch (r) {
	default:
		T_WARN("Unrecognized TLS receive return code -0x%X, drop packet\n",
		       -r);
		fallthrough;
	case T_DROP:
		spin_unlock(&tls->lock);
		if (!ttls_hs_done(tls))
			frang_tls_handler(tls, TTLS_HS_CB_INCOMPLETE);
		/* The skb is freed in tfw_tls_conn_dtor(). */
		return r;
	case T_POSTPONE:
		/* No complete TLS record seen yet. */
		spin_unlock(&tls->lock);
		return TFW_PASS;
	case T_OK:
		/* A complete TLS record is received. */
		T_DBG3("%s: parsed=%d skb->len=%u\n", __func__,
		       parsed, skb->len);
		break;
	}

	/*
	 * Possibly there are other TLS message in the @skb - create
	 * an skb sibling and process it on the next iteration.
	 * If a part of incomplete TLS message leaves at the end of the
	 * @skb, then store the skb in the TLS context for next FSM
	 * shot.
	 *
	 * Many sibling skbs can be produced by TLS and HTTP layers
	 * together - don't coalesce them: we process messages at once
	 * and it has sense to work with sparse skbs in HTTP
	 * adjustment logic to have some room to place a new fragments.
	 * The logic is simple because each layer works with messages
	 * from previous layer not crossing skb boundaries. The drawback
	 * is that we produce a lot of skbs causing pressure on the
	 * memory allocator.
	 *
	 * Split @skb before calling HTTP layer to chop it and not let HTTP
	 * to read after end of the message.
	 */
	if (parsed < skb->len) {
		nskb = ss_skb_split(skb, parsed);
		if (unlikely(!nskb)) {
			spin_unlock(&tls->lock);
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return T_DROP;
		}
	}

	if (tls->io_in.msgtype == TTLS_MSG_APPLICATION_DATA) {
		/*
		 * Current record contains an "application data" message.
		 * ttls_recv() has already decrypted the payload, but TLS
		 * overhead data are still attached. We need to cut them off.
		 */
		r = ss_skb_list_chop_head_tail(
				&tls->io_in.skb_list,
				ttls_payload_off(&tls->xfrm),
				TTLS_TAG_LEN);
		if (r) {
			tfw_tls_purge_io_ctx(&tls->io_in);
			kfree_skb(nskb);
			spin_unlock(&tls->lock);
			return r;
		}

		/*
		 * Pass tls->io_in.skb_list to data_up ownership for the upper
		 * layer processing.
		 */
		data_up.skb = tls->io_in.skb_list;
		ttls_reset_io_ctx(&tls->io_in);
		spin_unlock(&tls->lock);

		r = tfw_http_msg_process(conn, &data_up);
		if (r == TFW_BLOCK) {
			kfree_skb(nskb);
			return r;
		}
	} else {
		/*
		 * The decrypted payload is not required for upper levels.
		 * Lifetime of skbs in input contexts ends here.
		 */
		tfw_tls_purge_io_ctx(&tls->io_in);
		spin_unlock(&tls->lock);
	}

	if (nskb) {
		skb = nskb;
		nskb = NULL;
		goto next_msg;
	}

	return r;
}

/**
 * Add the TLS record overhead to current TCP socket control data.
 */
static int
tfw_tls_tcp_add_overhead(struct sock *sk, unsigned int overhead)
{
	if (!sk_wmem_schedule(sk, overhead))
		return -ENOMEM;
	sk->sk_wmem_queued += overhead;
	sk_mem_charge(sk, overhead);

	return 0;
}

/**
 * Propagate TCP correct sequence numbers from the current @skb with adjusted
 * sequence numbers for TLS overhead to the next one on TCP write queue.
 * So that tcp_send_head() always point to an skb with the right sequence
 * numbers.
 */
static void
tfw_tls_tcp_propagate_dseq(struct sock *sk, struct sk_buff *skb)
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
}

/**
 * The callback is called by tcp_write_xmit() if @skb must be encrypted by TLS.
 * @skb is current head of the TCP send queue. @limit defines how much data
 * can be sent right now with knowledge of current congestion and the receiver's
 * advertised window. Limit can be larger than skb->len and in this case we
 * can add the next skb in the send queue to the current encrypted TLS record.
 *
 * We extend the skbs on TCP transmission (when CWND is calculated), so we
 * also adjust TPC sequence numbers in the socket. See skb_entail().
 */
int
tfw_tls_encrypt(struct sock *sk, struct sk_buff *skb, unsigned int limit)
{
	/*
	 * TODO #1103 currently even trivial 500-bytes HTTP message generates
	 * 6 segment skb. After the fix the number probably should be decreased.
	 */
#define AUTO_SEGS_N	8

	int r = -ENOMEM;
	unsigned int head_sz, len, frags, t_sz, out_frags;
	unsigned char type;
	struct sk_buff *next = skb, *skb_tail = skb;
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	TlsCtx *tls;
	TlsIOCtx *io;
	TlsXfrm *xfrm;
	struct sg_table sgt = {
		.nents = skb_shinfo(skb)->nr_frags + !!skb_headlen(skb),
	}, out_sgt = {
		.nents = skb_shinfo(skb)->nr_frags + !!skb_headlen(skb),
	};
	struct scatterlist sg[AUTO_SEGS_N], out_sg[AUTO_SEGS_N];
	struct page **pages = NULL, **pages_end, **p;
	struct page *auto_pages[AUTO_SEGS_N];

	/*
	 * If client closes connection early, we may get here with sk_user_data
	 * being NULL.
	 */
	if (unlikely(!sk->sk_user_data)) {
		WARN_ON_ONCE(!sock_flag(sk, SOCK_DEAD));
		r = -EPIPE;
		goto err_purge_tcp_write_queue;
	}

	tls = tfw_tls_context(sk->sk_user_data);
	io = &tls->io_out;
	xfrm = &tls->xfrm;

	T_DBG3("%s: sk=%pK(snd_una=%u snd_nxt=%u limit=%u)"
	       " skb=%pK(len=%u data_len=%u type=%u frags=%u headlen=%u"
	       " seq=%u:%u)\n", __func__,
	       sk, tcp_sk(sk)->snd_una, tcp_sk(sk)->snd_nxt, limit,
	       skb, skb->len, skb->data_len, tempesta_tls_skb_type(skb),
	       skb_shinfo(skb)->nr_frags, skb_headlen(skb),
	       tcb->seq, tcb->end_seq);
	BUG_ON(!ttls_xfrm_ready(tls));
	WARN_ON_ONCE(skb->len > TLS_MAX_PAYLOAD_SIZE);
	WARN_ON_ONCE(tcb->seq + skb->len + !!(tcb->tcp_flags & TCPHDR_FIN)
		     != tcb->end_seq);

	head_sz = ttls_payload_off(xfrm);
	len = head_sz + skb->len + TTLS_TAG_LEN;
	type = tempesta_tls_skb_type(skb);
	if (!type) {
		T_WARN("%s: bad skb type %u\n", __func__, type);
		r = -EINVAL;
		goto err_kill_sock;
	}

	/* TLS header is always allocated from the skb headroom. */
	tcb->end_seq += head_sz;

	/* Try to aggregate several skbs into one TLS record. */
	while (!tcp_skb_is_last(sk, skb_tail)) {
		next = skb_queue_next(&sk->sk_write_queue, skb_tail);

		T_DBG3("next skb (%pK) in write queue: len=%u frags=%u/%u"
		       " type=%u seq=%u:%u\n",
		       next, next->len, skb_shinfo(next)->nr_frags,
		       !!skb_headlen(next), tempesta_tls_skb_type(next),
		       TCP_SKB_CB(next)->seq, TCP_SKB_CB(next)->end_seq);

		if (len + next->len > limit)
			break;
		/* Don't put different message types into the same record. */
		if (type != tempesta_tls_skb_type(next))
			break;

		/*
		 * skb at @next may lag behind in sequence numbers. Recalculate
		 * them from the previous skb which happens to be @skb_tail.
		 */
		tfw_tls_tcp_propagate_dseq(sk, skb_tail);

		len += next->len;
		sgt.nents += skb_shinfo(next)->nr_frags + !!skb_headlen(next);
		out_sgt.nents += skb_shinfo(next)->nr_frags + !!skb_headlen(next);
		skb_tail = next;
	}

	/*
	 * Use skb_tail->next as skb_head in __extend_pgfrags() to not try to
	 * put TAG to the next skb, which is out of our limit. In worst case,
	 * if there is no free frag slot in skb_tail, a new skb is allocated.
	 */
	next = skb_tail->next;
	t_sz = skb_tail->truesize;
	WARN_ON_ONCE(next == skb);
	if (skb_tail == skb) {
		r = ss_skb_expand_head_tail(skb->next, skb, head_sz, TTLS_TAG_LEN);
		if (r < 0)
			goto out;
	} else {
		r = ss_skb_expand_head_tail(NULL, skb, head_sz, 0);
		if (r < 0)
			goto out;
		sgt.nents += r;
		out_sgt.nents += r;

		r = ss_skb_expand_head_tail(skb_tail->next, skb_tail, 0,
					    TTLS_TAG_LEN);
		if (r < 0)
			goto out;
	}
	sgt.nents += r;
	out_sgt.nents += r;

	/*
	 * The last skb in our list will bring TLS tag - add it to end_seqno.
	 * Otherwise (in worst case), a new skb was inserted to fit TLS tag
	 * - fix end_seqno's for @skb_tail and this new skb.
	 *
	 * @limit = mss_now - tls_overhead, so {tso,tcp}_fragment() called from
	 * tcp_write_xmit() should set proper skb->tcp_gso_segs.
	 */
	if (likely(skb_tail->next == next)) {
		TCP_SKB_CB(skb_tail)->end_seq += TTLS_TAG_LEN;

		/* A new frag is added to the end of the current skb. */
		WARN_ON_ONCE(t_sz > skb_tail->truesize);
		t_sz = skb_tail->truesize - t_sz;
	}
	else {
		WARN_ON_ONCE(skb_tail->next->len != TTLS_TAG_LEN);
		WARN_ON_ONCE(skb_tail->truesize != t_sz);

		tfw_tls_tcp_propagate_dseq(sk, skb_tail);

		/*
		 * A new skb is added to the socket wmem.
		 *
		 * pcount for a new skb is zero, to tcp_write_xmit() will
		 * set TSO segs to proper value on next iteration.
		 */
		t_sz = skb_tail->next->truesize;

		skb_tail = skb_tail->next;
		INIT_LIST_HEAD(&skb_tail->tcp_tsorted_anchor);
	}

	/*
	 * A next skb (if any) will be left in write queue and become a new
	 * tcp_send_head() when all the skbs for the current TLS record will be
	 * transmitted, so adjust its seqnos to enter to the function next time
	 * for the new tcp_send_head() and allow TCP flow control to see correct
	 * seqnos in it. If @next is the last skb, then the whole queue is in
	 * consistent state.
	 */
	tfw_tls_tcp_propagate_dseq(sk, skb_tail);
	tcp_sk(sk)->write_seq += head_sz + TTLS_TAG_LEN;

	/*
	 * TLS record header is always allocated from the reserved skb headroom.
	 * The room for the tag may also be allocated from the reserved tailroom
	 * or in a new page fragment in skb_tail or next, probably new, skb.
	 * So to adjust the socket write memory we have to check the both skbs
	 * and only for TTLS_TAG_LEN.
	 */
	if (tfw_tls_tcp_add_overhead(sk, t_sz))
		return -ENOMEM;

	if (likely(sgt.nents <= AUTO_SEGS_N)) {
		sgt.sgl = sg;
		out_sgt.sgl = out_sg;
		pages = pages_end = auto_pages;
	} else {
		char *ptr = kmalloc(sizeof(struct scatterlist) * sgt.nents +
			            sizeof(struct scatterlist) * out_sgt.nents +
			            sizeof(struct page *) * out_sgt.nents,
				    GFP_ATOMIC);
		sgt.sgl = (struct scatterlist *)ptr;
		if (!sgt.sgl) {
			T_WARN("cannot alloc memory for TLS encryption.\n");
			return -ENOMEM;
		}

		ptr += sizeof(struct scatterlist) * sgt.nents;
		out_sgt.sgl = (struct scatterlist *)ptr;

		ptr += sizeof(struct scatterlist) * out_sgt.nents;
		pages = pages_end = (struct page **)ptr;
	}
	sg_init_table(sgt.sgl, sgt.nents);
	sg_init_table(out_sgt.sgl, out_sgt.nents);

	for (next = skb, frags = 0, out_frags = 0; ; ) {
		/*
		 * skb data and tails are already adjusted above,
		 * so use zero offset and skb->len.
		 */
		r = skb_to_sgvec(next, sgt.sgl + frags, 0, next->len);

		T_DBG3("skb_to_sgvec (%u segs) from skb %pK"
		       " (%u bytes, %u segs), done_frags=%u ret=%d\n",
		       sgt.nents, next, next->len,
		       skb_shinfo(next)->nr_frags + !!skb_headlen(next),
		       frags, r);

		if (r <= 0)
			goto out;
		frags += r;

		r = ss_skb_to_sgvec_with_new_pages(next,
		                                   out_sgt.sgl + out_frags,
		                                   &pages_end);
		if (r <= 0)
			goto out;
		out_frags += r;

		tempesta_tls_skb_clear(next);
		if (next == skb_tail)
			break;
		if (WARN_ON_ONCE(frags >= sgt.nents))
			break;
		next = skb_queue_next(&sk->sk_write_queue, next);
		sg_unmark_end(&sgt.sgl[frags - 1]);
		sg_unmark_end(&out_sgt.sgl[out_frags - 1]);
	}
	WARN_ON_ONCE(sgt.nents != frags);

	spin_lock(&tls->lock);

	/* Set IO context under the lock before encryption. */
	io->msglen = len - TLS_HEADER_SIZE;
	io->msgtype = type;
	if (!(r = ttls_encrypt(tls, &sgt, &out_sgt)))
		ttls_aad2hdriv(xfrm, skb->data);

	spin_unlock(&tls->lock);

	for (p = pages; p < pages_end; ++p)
		put_page(*p);

	/*
	 * This function is called from tcp_write_xmit() processing the TCP
	 * socket write queue, so we can not call synchronous socket closing
	 * which may purge the write queue, so call ss_close() here.
	 * At this point we have sent all the appliction data to the peer and
	 * now the TCP is sending the TLS close notify alert, i.e. there is
	 * no pending data in the TCP wite queue and we can safely purge it.
	 */
	if (type == TTLS_MSG_ALERT &&
	    (io->alert[1] == TTLS_ALERT_MSG_CLOSE_NOTIFY ||
	     io->alert[0] == TTLS_ALERT_LEVEL_FATAL))
	{
		ss_close(sk, SS_F_SYNC);
	}

out:
	if (unlikely(sgt.nents > AUTO_SEGS_N))
		kfree(sgt.sgl);
	if (!r || r == -ENOMEM)
		return r;

	/*
	 * We can not send unencrypted data and can not normally close the
	 * socket with FIN since we're in progress on sending from the write
	 * queue.
	 *
	 * TODO #861 Send RST, move the socket to dead state, and drop all
	 * the pending unencrypted data. We can not use tcp_v4_send_reset()
	 * since it works solely in response to ingress segment.
	 */
err_kill_sock:
	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_err = ECONNRESET;
		tcp_set_state(sk, TCP_CLOSE);
		sk->sk_shutdown = SHUTDOWN_MASK;
		sock_set_flag(sk, SOCK_DEAD);
	}
err_purge_tcp_write_queue:
	/*
	 * Leave encrypted segments in the retransmission rb-tree,
	 * but purge the send queue on unencrypted segments.
	 */
	while ((skb = tcp_send_head(sk))) {
		__skb_unlink(skb, &sk->sk_write_queue);
		sk_wmem_free_skb(sk, skb);
	}
	T_WARN("%s: cannot encrypt data (%d), only partial data was sent\n",
	       __func__, r);
	return r;
#undef AUTO_SEGS_N
}

/**
 * Callback function which is called by TLS module under tls->lock when it
 * initiates a record transmission, e.g. alert or a handshake message.
 */
static int
tfw_tls_send(TlsCtx *tls, struct sg_table *sgt)
{
	int r, flags = 0;
	TfwTlsConn *conn = container_of(tls, TfwTlsConn, tls);
	TlsIOCtx *io = &tls->io_out;
	TfwMsgIter it;
	TfwStr str = {};

	assert_spin_locked(&tls->lock);

	/*
	 * Encrypted (application data) messages will be prepended by a header
	 * in tfw_tls_encrypt(), so if we have an encryption context, then we
	 * don't send the header. Otherwise (handshake message) copy the whole
	 * data with a header.
	 *
	 * During handshake (!ttls_xfrm_ready(tls)), io may contain several
	 * consequent records of the same TTLS_MSG_HANDSHAKE type. io, except
	 * msglen containing length of the last record, describes the first
	 * record.
	 */
	if (ttls_xfrm_ready(tls) && io->msgtype == TTLS_MSG_ALERT) {
		str.data = io->alert;
		str.len = io->hslen;
	} else {
		str.data = io->hdr;
		str.len = TLS_HEADER_SIZE + io->hslen;
	}
	T_DBG("TLS %lu bytes +%u segments (%u bytes, last msgtype %#x)"
	      " are to be sent on conn=%pK/sk_write_xmit=%pK ready=%d\n",
	      str.len, sgt ? sgt->nents : 0, io->msglen, io->msgtype, conn,
	      conn->cli_conn.sk->sk_write_xmit, ttls_xfrm_ready(tls));

	if ((r = tfw_msg_iter_setup(&it, &io->skb_list, str.len, 0)))
		return r;
	if ((r = tfw_msg_write(&it, &str)))
		return r;
	/* Only one skb should has been allocated. */
	WARN_ON_ONCE(it.skb->next != io->skb_list
		     || it.skb->prev != io->skb_list);
	if (sgt) {
		int f, i = it.frag + 1;
		struct sk_buff *skb = it.skb;
		struct scatterlist *sg;

		for_each_sg(sgt->sgl, sg, sgt->nents, f) {
			if (i >= MAX_SKB_FRAGS) {
				if (!(skb = ss_skb_alloc(0)))
					return -ENOMEM;
				ss_skb_queue_tail(&io->skb_list, skb);
				i = 0;
			}
			skb_fill_page_desc(skb, i++, sg_page(sg), sg->offset,
					   sg->length);
			ss_skb_adjust_data_len(skb, sg->length);
			T_DBG3("fill skb frag %d by %pK,len=%u,flags=%lx in"
			       " skb=%pK,len=%u\n", i - 1,
			       sg_virt(sg), sg->length, sg->page_link & 0x3,
			       skb, skb->len);
		}
	}
	if (ttls_xfrm_need_encrypt(tls))
		flags |= SS_SKB_TYPE2F(io->msgtype) | SS_F_ENCRYPT;

	r = ss_send(conn->cli_conn.sk, &io->skb_list, flags);
	WARN_ON_ONCE(!(flags & SS_F_KEEP_SKB) && io->skb_list);

	return r;
}

static void
tfw_tls_conn_dtor(void *c)
{
	struct sk_buff *skb;
	TlsCtx *tls = tfw_tls_context(c);

	tfw_h2_context_clear(tfw_h2_context(c));

	if (tls) {
		while ((skb = ss_skb_dequeue(&tls->io_in.skb_list)))
			kfree_skb(skb);
		while ((skb = ss_skb_dequeue(&tls->io_out.skb_list)))
			kfree_skb(skb);

		if (tls->peer_conf)
			tfw_vhost_put(tfw_vhost_from_tls_conf(tls->peer_conf));

		/*
		 * We're in an upcall from the TCP layer, most likely caused
		 * by some error on the layer, and socket is already closed by
		 * ss_do_close(). We destroy the TLS context and there could not
		 * be a TSQ transmission in progress on the socket because
		 * tcp_tsq_handler() isn't called on closed socket and
		 * tcp_tasklet_func() and ss_do_close() are synchronized by
		 * the socket lock and TCP_TSQ_DEFERRED socket flag.
		 *
		 * We can not move the TLS context freeing into sk_destruct
		 * callback, because once the Tempesta connection destrcuctor
		 * (this function) is finished Tempesta FW can be unloaded and
		 * we can not leave any context on a socket with transmission
		 * in progress.
		 */
		ttls_ctx_clear(tls);
	}
	tfw_cli_conn_release((TfwCliConn *)c);
}

static int
tfw_tls_conn_init(TfwConn *c)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);
	TfwH2Ctx *h2 = tfw_h2_context(c);

	T_DBG2("%s: conn=[%p]\n", __func__, c);

	if ((r = ttls_ctx_init(tls, &tfw_tls.cfg))) {
		T_ERR("TLS (%pK) setup failed (%x)\n", tls, -r);
		return -EINVAL;
	}

	if (tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_init))
		return -EINVAL;

	if ((r = tfw_h2_context_init(h2)))
		return r;

	/*
	 * We never hook TLS connections in GFSM, but initialize it with 0 state
	 * to keep the things safe.
	 */
	tfw_gfsm_state_init(&c->state, c, 0);

	c->destructor = tfw_tls_conn_dtor;

	return 0;
}

static int
tfw_tls_conn_close(TfwConn *c, bool sync)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);

	spin_lock(&tls->lock);
	r = ttls_close_notify(tls);
	spin_unlock(&tls->lock);

	/*
	 * ttls_close_notify() calls ss_send() with SS_F_CONN_CLOSE flag, so
	 * if the call succeeded, then we'll close the socket with the alert
	 * transmission. Otherwise if we have to close the socket
	 * and can not write to the socket, then there is no other way than
	 * skip the alert and just close the socket.
	 */
	if (r) {
		T_WARN_ADDR("Close TCP socket w/o sending alert to the peer",
			    &c->peer->addr, TFW_NO_PORT);
		r = ss_close(c->sk, sync ? SS_F_SYNC : 0);
	}

	return r;
}

static void
tfw_tls_conn_drop(TfwConn *c)
{
	tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_drop);
}

/**
 * Send the @msg skbs as is - tcp_write_xmit() will care about encryption,
 * but attach TLS alert message at the end of the skb list to notify the peer
 * about connection closing if we're going to close the client connection.
 */
static int
tfw_tls_conn_send(TfwConn *c, TfwMsg *msg)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);
	TlsIOCtx *io = &tls->io_out;

	/*
	 * Only HTTP messages go this way, other (service) TLS records are sent
	 * by tfw_tls_send().
	 */
	io->msgtype = TTLS_MSG_APPLICATION_DATA;
	T_DBG("TLS %lu bytes (%u bytes, type %#x)"
	      " are to be sent on conn=%pK/sk_write_xmit=%pK ready=%d\n",
	      msg->len, io->msglen + TLS_HEADER_SIZE, io->msgtype, c,
	      c->sk->sk_write_xmit, ttls_xfrm_ready(tls));

	if (ttls_xfrm_ready(tls))
		msg->ss_flags |= SS_SKB_TYPE2F(io->msgtype) | SS_F_ENCRYPT;

	r = ss_send(c->sk, &msg->skb_head, msg->ss_flags & ~SS_F_CONN_CLOSE);
	if (r)
		return r;

	/*
	 * We can not send the alert on conn_drop hook, because the hook
	 * is called on already closed socket.
	 */
	if (msg->ss_flags & SS_F_CONN_CLOSE) {
		spin_lock(&tls->lock);
		r = ttls_close_notify(tls);
		spin_unlock(&tls->lock);
	}

	return r;
}

static TfwConnHooks tls_conn_hooks = {
	.conn_init	= tfw_tls_conn_init,
	.conn_close	= tfw_tls_conn_close,
	.conn_drop	= tfw_tls_conn_drop,
	.conn_send	= tfw_tls_conn_send,
};

static TlsPeerCfg *
tfw_tls_get_if_configured(TfwVhost *vhost)
{
	TlsPeerCfg *cfg;

	if (unlikely(!vhost))
		return NULL;

	cfg = &vhost->tls_cfg;
	if (likely(cfg->key_cert))
		return cfg;

	if (!vhost->vhost_dflt) {
		tfw_vhost_put(vhost);
		return NULL;
	}

	cfg = &vhost->vhost_dflt->tls_cfg;
	if (!cfg->key_cert) {
		tfw_vhost_put(vhost);
		return NULL;
	}

	tfw_vhost_get(vhost->vhost_dflt);
	tfw_vhost_put(vhost);

	return cfg;
}

#define SNI_WARN(fmt, ...)						\
	TFW_WITH_ADDR_FMT(&cli_conn->peer->addr, TFW_NO_PORT, addr_str,	\
			  T_WARN("TLS: sni ext: client %s requested "fmt, \
				 addr_str, __VA_ARGS__))

/**
 * Find matching vhost according to server name in SNI extension. The function
 * is also called if there is no SNI extension and fallback to some default
 * configuration is required. In the latter case @data is NULL and @len is 0.
 */
static int
tfw_tls_sni(TlsCtx *ctx, const unsigned char *data, size_t len)
{
	const TfwStr srv_name = {.data = (unsigned char *)data, .len = len};
	TfwVhost *vhost = NULL;
	TlsPeerCfg *peer_cfg;
	TfwCliConn *cli_conn = &container_of(ctx, TfwTlsConn, tls)->cli_conn;

	T_DBG2("%s: server name '%.*s'\n",  __func__, (int)len, data);

	if (WARN_ON_ONCE(ctx->peer_conf))
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;

	if (data && len) {
		vhost = tfw_vhost_lookup(&srv_name);
		if (unlikely(vhost && !vhost->vhost_dflt)) {
			SNI_WARN(" '%s' vhost by name, reject connection.\n",
				 TFW_VH_DFT_NAME);
			tfw_vhost_put(vhost);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		if (unlikely(!vhost && !tfw_tls.allow_any_sni)) {
			SNI_WARN(" unknown server name '%.*s', reject connection.\n",
				 (int)len, data);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
	}
	/*
	 * If accurate vhost is not found or client doesn't send sni extension,
	 * map the connection to default vhost.
	 */
	if (!vhost)
		vhost = tfw_vhost_lookup_default();
	if (unlikely(!vhost))
		return TTLS_ERR_CERTIFICATE_REQUIRED;

	peer_cfg = tfw_tls_get_if_configured(vhost);
	ctx->peer_conf = peer_cfg;
	if (unlikely(!peer_cfg))
		return TTLS_ERR_CERTIFICATE_REQUIRED;

	if (DBG_TLS) {
		vhost = tfw_vhost_from_tls_conf(ctx->peer_conf);
		T_DBG("%s: for server name '%.*s' vhost '%.*s' is chosen\n",
		      __func__, PR_TFW_STR(&srv_name),
		      PR_TFW_STR(&vhost->name));
	}
	/* Save processed server name as hash. */
	ctx->sni_hash = len ? hash_calc(data, len) : 0;

	return 0;
}

static unsigned long
ttls_cli_id(TlsCtx *tls, unsigned long hash)
{
	TfwCliConn *cli_conn = &container_of(tls, TfwTlsConn, tls)->cli_conn;

	return hash_calc_update((const char *)&cli_conn->peer->addr,
				sizeof(TfwAddr), hash);
}

/*
 * ------------------------------------------------------------------------
 *	TLS library configuration.
 * ------------------------------------------------------------------------
 */

static int
tfw_tls_do_init(void)
{
	int r;

	ttls_config_init(&tfw_tls.cfg);
	/* Use cute ECDHE-ECDSA-AES128-GCM-SHA256 by default. */
	r = ttls_config_defaults(&tfw_tls.cfg, TTLS_IS_SERVER);
	if (r) {
		T_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_tls_do_cleanup(void)
{
	ttls_config_free(&tfw_tls.cfg);
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */
/* TLS configuration state. */
#define TFW_TLS_CFG_F_DISABLED		0U
#define TFW_TLS_CFG_F_REQUIRED		1U
#define TFW_TLS_CFG_F_CERTS		2U
#define TFW_TLS_CFG_F_CERTS_GLOBAL	4U

static unsigned int tfw_tls_cgf = TFW_TLS_CFG_F_DISABLED;

void
tfw_tls_cfg_require(void)
{
	tfw_tls_cgf |= TFW_TLS_CFG_F_REQUIRED;
}

void
tfw_tls_cfg_configured(bool global)
{
	tfw_tls_cgf |= TFW_TLS_CFG_F_CERTS;
	if (global)
		tfw_tls_cgf |= TFW_TLS_CFG_F_CERTS_GLOBAL;
}

void
tfw_tls_match_any_sni_to_dflt(bool match)
{
	allow_any_sni_reconfig = match;
}

int
tfw_tls_cfg_alpn_protos(const char *cfg_str, bool *deprecated)
{
	ttls_alpn_proto *protos;

#define PROTO_INIT(order, proto)				\
do {								\
	protos[order].name = TTLS_ALPN_##proto;			\
	protos[order].len = sizeof(TTLS_ALPN_##proto) - 1;	\
	protos[order].id = TTLS_ALPN_ID_##proto;		\
} while (0)

	protos = kzalloc(TTLS_ALPN_PROTOS * sizeof(ttls_alpn_proto), GFP_KERNEL);
	if (unlikely(!protos))
		return -ENOMEM;

	tfw_tls.cfg.alpn_list = protos;

	if (!strcasecmp(cfg_str, "https")) {
		PROTO_INIT(0, HTTP1);
		*deprecated = true;
		return 0;
	}

	if (!strcasecmp(cfg_str, "h2")) {
		PROTO_INIT(0, HTTP2);
		*deprecated = false;
		return 0;
	}

	tfw_tls.cfg.alpn_list = NULL;
	kfree(protos);

	return -EINVAL;
#undef PROTO_INIT
}

void
tfw_tls_free_alpn_protos(void)
{
	if (tfw_tls.cfg.alpn_list) {
		kfree(tfw_tls.cfg.alpn_list);
		tfw_tls.cfg.alpn_list = NULL;
	}
}

static int
tfw_tls_cfgstart(void)
{
	allow_any_sni_reconfig = false;

	return 0;
}

static int
tfw_tls_cfgend(void)
{
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_REQUIRED)) {
		if (tfw_tls_cgf)
			T_WARN_NL("TLS: no HTTPS listener set, configuration "
				  "is ignored.\n");
		return 0;
	}
	else if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CERTS)) {
		T_ERR_NL("TLS: HTTPS listener set but no TLS certificates "
			    "provided. At least one vhost must have TLS "
			   "certificates configured.\n");
		return -EINVAL;
	}

	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CERTS_GLOBAL)) {
		T_WARN_NL("TLS: no global TLS certificates provided. "
			  "Client TLS connections with unknown "
			    "server name values or with no server name "
			    "specified will be dropped.\n");
	}

	return 0;
}

static int
tfw_tls_start(void)
{
	tfw_tls.allow_any_sni = allow_any_sni_reconfig;

	return 0;
}

static TfwCfgSpec tfw_tls_specs[] = {
	{ 0 }
};

TfwMod tfw_tls_mod = {
	.name		= "tls",
	.cfgend		= tfw_tls_cfgend,
	.cfgstart	= tfw_tls_cfgstart,
	.start		= tfw_tls_start,
	.specs		= tfw_tls_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_tls_init(void)
{
	int r;

	r = tfw_tls_do_init();
	if (r)
		return -EINVAL;

	ttls_register_callbacks(tfw_tls_send, tfw_tls_sni, frang_tls_handler,
				ttls_cli_id);

	if ((r = tfw_h2_init()))
		goto err_h2;

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_HTTPS);
	tfw_mod_register(&tfw_tls_mod);

	return 0;

err_h2:
	tfw_tls_do_cleanup();

	return r;
}

void
tfw_tls_exit(void)
{
	tfw_mod_unregister(&tfw_tls_mod);
	tfw_connection_hooks_unregister(TFW_FSM_HTTPS);
	tfw_h2_cleanup();
	tfw_tls_do_cleanup();
}
