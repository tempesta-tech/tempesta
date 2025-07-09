/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#include "hash.h"
#include "http.h"
#include "http_frame.h"
#include "http_limits.h"
#include "tf_conf.h"
#include "tf_filter.h"
#include "msg.h"
#include "procfs.h"
#include "tls.h"
#include "vhost.h"
#include "tcp.h"
#include "lib/fault_injection_alloc.h"

/* Common tls configuration for all vhosts. */
static TlsCfg tfw_tls_cfg;

/* If set, all the unknown SNI are matched to default vhost. */
static bool tfw_tls_allow_any_sni;
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
		frang_tls_handler(tls, TTLS_HS_CB_INCOMPLETE);
}

int
tfw_tls_connection_recv(TfwConn *conn, struct sk_buff *skb)
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
	ss_skb_set_owner(skb, conn->peer);

	/* Call TLS layer to place skb into a TLS record on top of skb_list. */
	parsed = 0;
	r = ss_skb_process(skb, ttls_recv, tls, &tls->io_in.chunks, &parsed);
	switch (r) {
	default:
		/*
		 * T_BLOCK is error code for high level modules (like frang),
		 * here we should deal with error code, which accurately
		 * determine further closing behavior.
		 * T_DROP is error code, which is returned when connection
		 * should be alive, but if we can't decrypt request, we should
		 * close the connection.
		 */
		WARN_ON_ONCE(r == T_BLOCK || r == T_DROP);
		fallthrough;
	case T_BAD:
		r = T_BAD;
		fallthrough;
	case T_BLOCK_WITH_FIN:
		fallthrough;
	case T_BLOCK_WITH_RST:
		if (tls->conf->endpoint == TTLS_IS_SERVER && !ttls_hs_done(tls))
			TFW_INC_STAT_BH(serv.tls_hs_failed);

		spin_unlock(&tls->lock);
		/* The skb is freed in tfw_tls_conn_dtor(). */
		return r;
	case T_POSTPONE:
		/* No complete TLS record seen yet. */
		spin_unlock(&tls->lock);
		return T_OK;
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
			return T_BAD;
		}
	}

	if (tls->io_in.msgtype == TTLS_MSG_APPLICATION_DATA)
	{
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
			return T_BAD;
		}

		/*
		 * Pass tls->io_in.skb_list to data_up ownership for the upper
		 * layer processing.
		 */
		data_up.skb = tls->io_in.skb_list;
		ttls_reset_io_ctx(&tls->io_in);
		spin_unlock(&tls->lock);

		/* Do upcall to http or websocket */
		r = tfw_connection_recv(conn, data_up.skb);
		if (r && r != T_POSTPONE && r != T_DROP) {
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
 * The callback is called by tcp_write_xmit() if @skb must be encrypted by TLS.
 * @skb is current head of the TCP send queue. @limit defines how much data
 * can be sent right now with knowledge of current congestion and the receiver's
 * advertised window. Limit can be larger than skb->len and in this case we
 * can add the next skb in the send queue to the current encrypted TLS record.
 *
 * We extend the skbs on TCP transmission (when CWND is calculated), so we
 * also adjust TCP sequence numbers in the socket. See tcp_skb_entail().
 */
int
tfw_tls_encrypt(struct sock *sk, struct sk_buff *skb, unsigned int mss_now,
		unsigned int limit)
{
#define AUTO_SEGS_N	8
#define MAX_SEG_N	64

	int r = -ENOMEM;
	unsigned int head_sz, len, frags, t_sz, out_frags, next_nents;
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

	tls = tfw_tls_context(sk->sk_user_data);
	io = &tls->io_out;
	xfrm = &tls->xfrm;

	T_DBG3("%s: sk=%pK(snd_una=%u snd_nxt=%u limit=%u)"
	       " skb=%px(len=%u data_len=%u type=%u frags=%u headlen=%u"
	       " seq=%u:%u)\n", __func__,
	       sk, tcp_sk(sk)->snd_una, tcp_sk(sk)->snd_nxt, limit,
	       skb, skb->len, skb->data_len, skb_tfw_tls_type(skb),
	       skb_shinfo(skb)->nr_frags, skb_headlen(skb),
	       tcb->seq, tcb->end_seq);
	BUG_ON(!ttls_xfrm_ready(tls));
	WARN_ON_ONCE(skb->len > TLS_MAX_PAYLOAD_SIZE);
	WARN_ON_ONCE(tcb->seq + skb->len + !!(tcb->tcp_flags & TCPHDR_FIN)
		     != tcb->end_seq);

	head_sz = ttls_payload_off(xfrm);
	len = skb->len;
	type = skb_tfw_tls_type(skb);
	/* Checked early before call this function. */
	if ((WARN_ON_ONCE(!type))) {
		r = -EINVAL;
		goto out;
	}

	/* TLS header is always allocated from the skb headroom. */
	tcb->end_seq += head_sz;

	/* Try to aggregate several skbs into one TLS record. */
	while (!tcp_skb_is_last(sk, skb_tail)) {
		next = skb_queue_next(&sk->sk_write_queue, skb_tail);
		next_nents = skb_shinfo(next)->nr_frags + !!skb_headlen(next);

		T_DBG3("next skb (%px) in write queue: len=%u frags=%u/%u"
		       " type=%u seq=%u:%u\n",
		       next, next->len, skb_shinfo(next)->nr_frags,
		       !!skb_headlen(next), skb_tfw_tls_type(next),
		       TCP_SKB_CB(next)->seq, TCP_SKB_CB(next)->end_seq);

		if (len + next->len > limit)
			break;
		if (unlikely(sgt.nents + next_nents > MAX_SEG_N))
			break;
		/* Don't put different message types into the same record. */
		if (type != skb_tfw_tls_type(next))
			break;

		/*
		 * skb at @next may lag behind in sequence numbers. Recalculate
		 * them from the previous skb which happens to be @skb_tail.
		 */
		tfw_tcp_propagate_dseq(sk, skb_tail);

		len += next->len;
		sgt.nents += next_nents;
		out_sgt.nents += next_nents;
		skb_tail = next;
	}

	len += head_sz + TTLS_TAG_LEN;

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
		if (r < 0) {
			tcb->end_seq -= head_sz;
			goto out;
		}
	} else {
		r = ss_skb_expand_head_tail(NULL, skb, head_sz, 0);
		if (r < 0) {
			tcb->end_seq -= head_sz;
			goto out;
		}
		sgt.nents += r;
		out_sgt.nents += r;

		r = ss_skb_expand_head_tail(skb_tail->next, skb_tail, 0,
					    TTLS_TAG_LEN);
		if (r < 0) {
			ss_add_overhead(sk, skb_tail->truesize - t_sz);
			goto out;
		}
	}
	sgt.nents += r;
	out_sgt.nents += r;

	/*
	 * The last skb in our list will bring TLS tag - add it to end_seqno.
	 * Otherwise (in worst case), a new skb was inserted to fit TLS tag
	 * - fix end_seqno's for @skb_tail and this new skb.
	 */
	if (likely(skb_tail->next == next)) {
		TCP_SKB_CB(skb_tail)->end_seq += TTLS_TAG_LEN;

		/* A new frag is added to the end of the current skb. */
		WARN_ON_ONCE(t_sz > skb_tail->truesize);
		t_sz = skb_tail->truesize - t_sz;

		tcp_set_skb_tso_segs(skb_tail, mss_now);
	}
	else {
		struct sk_buff *tail_next = skb_tail->next;

		WARN_ON_ONCE(tail_next->len != TTLS_TAG_LEN);
		WARN_ON_ONCE(skb_tail->truesize != t_sz);

		/* Remove skb since it must be inserted into sk write queue. */
		ss_skb_remove(tail_next);
		tfw_tcp_setup_new_skb(sk, skb_tail, tail_next, mss_now);

		/*
		 * A new skb is added to the socket wmem.
		 *
		 * pcount for a new skb is zero, to tcp_write_xmit() will
		 * set TSO segs to proper value on next iteration.
		 */
		t_sz = tail_next->truesize;

		skb_tail = tail_next;
		skb_set_tfw_tls_type(skb_tail, type);
	}

	/*
	 * A next skb (if any) will be left in write queue and become a new
	 * tcp_send_head() when all the skbs for the current TLS record will be
	 * transmitted, so adjust its seqnos to enter to the function next time
	 * for the new tcp_send_head() and allow TCP flow control to see correct
	 * seqnos in it. If @next is the last skb, then the whole queue is in
	 * consistent state.
	 */
	tfw_tcp_propagate_dseq(sk, skb_tail);
	tcp_sk(sk)->write_seq += head_sz + TTLS_TAG_LEN;

	/*
	 * TLS record header is always allocated from the reserved skb headroom.
	 * The room for the tag may also be allocated from the reserved tailroom
	 * or in a new page fragment in skb_tail or next, probably new, skb.
	 * So to adjust the socket write memory we have to check the both skbs
	 * and only for TTLS_TAG_LEN.
	 */
	ss_add_overhead(sk, t_sz);

	if (likely(sgt.nents <= AUTO_SEGS_N)) {
		sgt.sgl = sg;
		out_sgt.sgl = out_sg;
		pages = pages_end = auto_pages;
	} else {
		size_t alloc_sz = sizeof(struct scatterlist) * sgt.nents +
			sizeof(struct scatterlist) * out_sgt.nents +
			sizeof(struct page *) * out_sgt.nents;
		char *ptr = tfw_kmalloc(alloc_sz, GFP_ATOMIC);

		sgt.sgl = (struct scatterlist *)ptr;
		if (!sgt.sgl) {
			T_WARN("cannot alloc memory for TLS encryption.\n");
			r = -ENOMEM;
			goto out;
		}

		ptr += sizeof(struct scatterlist) * sgt.nents;
		out_sgt.sgl = (struct scatterlist *)ptr;

		ptr += sizeof(struct scatterlist) * out_sgt.nents;
		pages = pages_end = (struct page **)ptr;
	}
	sg_init_table(sgt.sgl, sgt.nents);
	sg_init_table(out_sgt.sgl, out_sgt.nents);

	for (next = skb, frags = 0, out_frags = 0; ; ) {
		if (likely(next->len)) {
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

			if (r < 0)
				goto free_pages;
			frags += r;

			r = ss_skb_to_sgvec_with_new_pages(next,
							   out_sgt.sgl +
							   out_frags,
							   &pages_end);
			if (r < 0)
				goto free_pages;
			out_frags += r;
		}

		skb_clear_tfw_cb(next);
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

free_pages:
	for (p = pages; p < pages_end; ++p)
		put_page(*p);
	if (unlikely(sgt.nents > AUTO_SEGS_N))
		kfree(sgt.sgl);
out:
	if (unlikely(r))
		T_WARN("%s: cannot encrypt data (%d)\n", __func__, r);
	return r;
#undef AUTO_SEGS_N
#undef MAX_SEG_N
}

static inline int
tfw_tls_close_msg_flags(TlsIOCtx *io)
{
	int flags = 0;

	switch (io->st_flags
		& (TTLS_F_ST_SHUTDOWN | TTLS_F_ST_CLOSE))
	{
	case TTLS_F_ST_CLOSE:
		flags |= __SS_F_FORCE;
		fallthrough;
	case TTLS_F_ST_SHUTDOWN:
		flags |= SS_F_CONN_CLOSE;
		break;
	default:
		/*
		 * All close notify and fatal messages should specify
		 * how to close connection (using tcp_close() or
		 * tcp_shutdown())
		 */
		BUG();
	}

	return flags;
}

static inline int
tfw_tls_on_send_alert(void *conn, struct sk_buff **skb_head)
{
	TfwH2Ctx *ctx;

	BUG_ON(TFW_CONN_PROTO((TfwConn *)conn) != TFW_FSM_H2);
	ctx = tfw_h2_context_safe((TfwConn *)conn);
	if (!ctx)
		return 0;

	if (ctx->error && ctx->error->xmit.skb_head) {
		ss_skb_queue_splice(&ctx->error->xmit.skb_head, skb_head);
	} else if (ctx->cur_send_headers) {
		/*
		 * Other frames (from any stream) MUST NOT occur between
		 * the HEADERS frame and any CONTINUATION frames that might
		 * follow. Send TLS alert later.
		 */
		ctx->error = ctx->cur_send_headers;
		ss_skb_queue_splice(&ctx->error->xmit.skb_head, skb_head);
	}

	return 0;
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
	TfwCliConn *cli_conn = &conn->cli_conn;
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
	      cli_conn->sk->sk_write_xmit, ttls_xfrm_ready(tls));

	if ((r = tfw_msg_iter_setup(&it, cli_conn->peer, &io->skb_list,
				    str.len)))
		goto out;
	if ((r = tfw_msg_iter_write(&it, &str)))
		goto out;
	/* Only one skb should has been allocated. */
	WARN_ON_ONCE(it.skb->next != io->skb_list
		     || it.skb->prev != io->skb_list);
	if (sgt) {
		int f, i = it.frag + 1;
		struct sk_buff *skb = it.skb;
		struct scatterlist *sg;

		for_each_sg(sgt->sgl, sg, sgt->nents, f) {
			if (i >= MAX_SKB_FRAGS) {
				if (!(skb = ss_skb_alloc(0))) {
					r = -ENOMEM;
					goto out;
				}
				ss_skb_set_owner(skb, cli_conn->peer);
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

	if (io->msgtype == TTLS_MSG_ALERT &&
	    (io->alert[1] == TTLS_ALERT_MSG_CLOSE_NOTIFY ||
	     io->alert[0] == TTLS_ALERT_LEVEL_FATAL)) {
		TFW_CONN_TYPE(((TfwConn *)conn)) |= Conn_Stop;
		flags |= tfw_tls_close_msg_flags(io);
		if (TFW_CONN_PROTO((TfwConn *)conn) == TFW_FSM_H2) {
			TFW_SKB_CB(io->skb_list)->on_send =
				tfw_tls_on_send_alert;
		}
	}

	r = ss_send(conn->cli_conn.sk, &io->skb_list, flags);
	WARN_ON_ONCE(!(flags & SS_F_KEEP_SKB) && io->skb_list);

out:
	/*
	 * TTLS_F_ST_SHUTDOWN and TTLS_F_ST_CLOSE flags are used
	 * to specify type of closing procedure. We save one of these
	 * flags previosly in st_flags field, use it in this function
	 * and reset them in st_flags field to be sure that we can
	 * use st_flags field for the same purpose.
	 */
	io->st_flags &= ~(TTLS_F_ST_SHUTDOWN | TTLS_F_ST_CLOSE);
	return r;
}

static void
tfw_tls_conn_dtor(void *c)
{
	struct sk_buff *skb;
	TlsCtx *tls = tfw_tls_context(c);

	if (TFW_CONN_PROTO((TfwConn *)c) == TFW_FSM_H2) {
		TfwH2Ctx *h2_ctx = tfw_h2_context_unsafe(c);

		if (ttls_hs_done(tls) && h2_ctx) {
			tfw_h2_context_clear(h2_ctx);
			tfw_h2_context_free(h2_ctx);
		}
	}

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
	TlsCtx *tls;

	T_DBG2("%s: conn=[%p]\n", __func__, c);
	BUG_ON(!(c->proto.type & TFW_FSM_HTTPS));

	tls = tfw_tls_context(c);
	if ((r = ttls_ctx_init(tls, &tfw_tls_cfg))) {
		T_ERR("TLS (%pK) setup failed (%x)\n", tls, -r);
		return -EINVAL;
	}

	if (tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_init)) {
		r = -EINVAL;
		goto err_cleanup;
	}

	/*
	 * We never hook TLS connections in GFSM, but initialize it with 0 state
	 * to keep the things safe.
	 */
	tfw_gfsm_state_init(&c->state, c, 0);

	c->destructor = tfw_tls_conn_dtor;

	return 0;
err_cleanup:
	ttls_ctx_clear(tls);
	return r;
}

static int
tfw_tls_conn_close(TfwConn *c, bool sync)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);

	spin_lock(&tls->lock);
	r = ttls_close_notify(tls, TTLS_F_ST_CLOSE);
	spin_unlock(&tls->lock);

	/*
	 * Once the TLS close notify alert is going to be sent by
	 * tcp_write_xmit(), tfw_tls_encrypt() calls ss_close(), so
	 * if the call succeeded, then we'll close the socket with the alert
	 * transmission. Otherwise if we have to close the socket
	 * and can not write to the socket, then there is no other way than
	 * skip the alert and just close the socket.
	 *
	 * That's just OK if we're closing a TCP connection during TLS handshake.
	 */
	if (r) {
		if (r != -EPROTO)
			T_WARN_ADDR("Close TCP socket w/o sending alert to"
				    " the peer", &c->peer->addr, TFW_NO_PORT);
		r = ss_close(c->sk, sync ? SS_F_SYNC : 0);
	}

	return r;
}

static int
tfw_tls_conn_abort(TfwConn *c)
{
	return ss_close(c->sk, SS_F_ABORT_FORCE);
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
	TlsCtx *tls;

	/*
	 * Save `ss_flags` for later access.
	 * Message sending may happen on another CPU,
	 * when `ss_send` returns successfully, `msg` may be invalid,
	 * so referencing `msg` since then is wrong.
	 */
	int ss_flags = READ_ONCE(msg->ss_flags);

	/* for the tls reference after ss_send */
	tfw_connection_get(c);

	tls = tfw_tls_context(c);

	T_DBG("TLS %lu bytes (%u bytes)"
	      " are to be sent on conn=%pK/sk_write_xmit=%pK ready=%d\n",
	      msg->len, tls->io_out.msglen + TLS_HEADER_SIZE, c,
	      c->sk->sk_write_xmit, ttls_xfrm_ready(tls));

	if (ttls_xfrm_ready(tls)) {
		msg->ss_flags |= SS_SKB_TYPE2F(TTLS_MSG_APPLICATION_DATA) |
			SS_F_ENCRYPT;
	}

	r = ss_send(c->sk, &msg->skb_head,
		    msg->ss_flags & ~SS_F_CLOSE_FORCE);
	if (r)
		goto out;

	/*
	 * We can not send the alert on conn_drop hook, because the hook
	 * is called on already closed socket.
	 */
	if (ss_flags & SS_F_CONN_CLOSE) {
		int close_type = ss_flags & __SS_F_FORCE ?
			TTLS_F_ST_CLOSE : TTLS_F_ST_SHUTDOWN;

		spin_lock(&tls->lock);
		r = ttls_close_notify(tls, close_type);
		spin_unlock(&tls->lock);
	}

out:
	tfw_connection_put(c);
	return r;
}

static void
tfw_tls_conn_recv_finish(TfwConn *c)
{
	tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_recv_finish);
}

static TfwConnHooks tls_conn_hooks = {
	.conn_init		= tfw_tls_conn_init,
	.conn_close		= tfw_tls_conn_close,
	.conn_abort		= tfw_tls_conn_abort,
	.conn_drop		= tfw_tls_conn_drop,
	.conn_send		= tfw_tls_conn_send,
	.conn_recv_finish	= tfw_tls_conn_recv_finish,
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
			  T_WARN("client %s requested " fmt, addr_str,	\
				 ## __VA_ARGS__))

static int
fw_tls_apply_sni_wildcard(BasicStr *name)
{
	int n;
	char *p = strnchr(name->data, name->len, '.');
	if (!p)
		return -ENOENT;
	n = name->data + name->len - p;

	/* The resulting name must be lower than a top level domain. */
	if (n < 2)
		return -ENOENT;

	/*
	 * Store leading dot to match against chopped wildcard (see
	 * tfw_tls_add_cn()) and do not confuse the name with a CN.
	 */
	name->data = p;
	name->len = n;

	return 0;
}

TfwVhost*
tfw_tls_find_vhost_by_name(BasicStr *srv_name)
{
	TfwVhost *vhost;

	/* Look for non-wildcard name */
	vhost = tfw_vhost_lookup_sni(srv_name);
	if (vhost)
		return vhost;

	/*
	 * Try wildcard SANs if the SNI requests 2nd-level or
	 * lower domain.
	 */
	if (!vhost && !fw_tls_apply_sni_wildcard(srv_name)
	    && (vhost = tfw_vhost_lookup_sni(srv_name)))
		return vhost;

	return NULL;
}

/**
 * Find matching vhost according to server name in SNI extension. The function
 * is also called if there is no SNI extension and fallback to some default
 * configuration is required. In the latter case @data is NULL and @len is 0.
 */
static int
tfw_tls_sni(TlsCtx *ctx, const unsigned char *data, size_t len)
{
	BasicStr srv_name = {.data = (char *)data, .len = len};
	TfwVhost *vhost = NULL;
	TlsPeerCfg *peer_cfg;
	TfwCliConn *cli_conn = &container_of(ctx, TfwTlsConn, tls)->cli_conn;

	T_DBG2("%s: server name '%.*s'\n",  __func__, (int)len, data);

	if (WARN_ON_ONCE(ctx->peer_conf))
		return -EBUSY;

	if (data && len) {
		/*
		 * Data comes as a copy from temporary buffer tls_handshake_t::ext
		 * See ttls_parse_client_hello() for details.
		 */
		tfw_cstrtolower_inplace(srv_name.data, len);

		vhost = tfw_tls_find_vhost_by_name(&srv_name);
		if (unlikely(!vhost && !tfw_tls_allow_any_sni)) {
			SNI_WARN("unknown server name '%.*s' in TLS SNI,"
				 " reject connection.\n", (int)len, data);
			return -ENOENT;
		}

		/* TFt computation */
		ctx->sess.tft.vhost_found = !!(u8)(vhost != NULL);
	}
	else if (!tfw_tls_allow_any_sni) {
		SNI_WARN("missing server name, reject connection.\n");
		return -ENOENT;
	}
	/*
	 * If accurate vhost is not found or client doesn't send sni extension,
	 * map the connection to default vhost.
	 */
	if (!vhost)
		vhost = tfw_vhost_lookup_default();
	if (WARN_ON_ONCE(!vhost))
		return -ENOKEY;

	/*
	 * The peer configuration might be taked from the default vhost, which
	 * is different from @vhost. We put() the virtual host, when @ctx is
	 * freed.
	 */
	ctx->vhost = vhost;
	peer_cfg = tfw_tls_get_if_configured(vhost);
	ctx->peer_conf = peer_cfg;
	if (unlikely(!peer_cfg)) {
		SNI_WARN("misconfigured vhost '%.*s', reject connection.\n",
			 PR_TFW_STR(&vhost->name));
		return -ENOKEY;
	}

	if (DBG_TLS) {
		vhost = tfw_vhost_from_tls_conf(ctx->peer_conf);
		T_DBG("found SAN/CN '%.*s' for SNI '%.*s' and vhost '%.*s'\n",
		      PR_TFW_STR(&srv_name), (int)len, data,
		      PR_TFW_STR(&vhost->name));
	}
	/* Save processed server name as hash. */
	ctx->sni_hash = hash_calc(data, len);

	return 0;
}

static inline int
tfw_tls_over(TlsCtx *tls, int state)
{
	int sk_proto = ((SsProto *)tls->sk->sk_user_data)->type;
	TfwH2Conn *conn = (TfwH2Conn*)tls->sk->sk_user_data;

	if (state == TTLS_HS_CB_FINISHED_NEW
	    || state == TTLS_HS_CB_FINISHED_RESUMED)
		TFW_INC_STAT_BH(serv.tls_hs_successful);

	if (TFW_FSM_TYPE(sk_proto) == TFW_FSM_H2) {
		int r;

		conn->h2 = tfw_h2_context_alloc();
		if (!conn->h2)
			return -ENOMEM;
		r = tfw_h2_context_init(conn->h2, conn);
		if (r) {
			T_ERR("cannot establish a new h2 connection\n");
			return r;
		}
	}

	return frang_tls_handler(tls, state);
}

static unsigned long
ttls_cli_id(TlsCtx *tls, unsigned long hash)
{
	TfwCliConn *cli_conn = &container_of(tls, TfwTlsConn, tls)->cli_conn;

	return hash_calc_update((const char *)&cli_conn->peer->addr.sin6_addr,
				sizeof(cli_conn->peer->addr.sin6_addr), hash);
}

static bool
tfw_tls_alpn_match(const TlsCtx *tls, const ttls_alpn_proto *alpn)
{
	int sk_proto = ((SsProto *)tls->sk->sk_user_data)->type;
	TfwConn *conn = (TfwConn*)tls->sk->sk_user_data;

	/* Upgrade to HTTP2. */
	if (sk_proto & Conn_Negotiable && alpn->id == TTLS_ALPN_ID_HTTP2) {
		conn->proto.type = (conn->proto.type & ~TFW_GFSM_FSM_MASK) |
					TFW_FSM_H2;
		return true;
	}

	if (TFW_FSM_TYPE(sk_proto) == TFW_FSM_H2
	    && alpn->id == TTLS_ALPN_ID_HTTP2)
		return true;

	if (TFW_FSM_TYPE(sk_proto) == TFW_FSM_HTTPS
	    && alpn->id == TTLS_ALPN_ID_HTTP1)
		return true;

	return false;
}

static bool
tfw_tft_limit_conn(TlsTft fingerprint)
{
	u64 limit = tls_get_tf_conns_limit(fingerprint);
	u64 rate = tft_get_conns_rate(fingerprint);

	return rate > limit;
}

static bool
tfw_tft_limit_rec(TlsTft fingerprint)
{
	u64 limit = tls_get_tf_recs_limit(fingerprint);
	u64 rate = tft_get_records_rate(fingerprint);

	return rate > limit;
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

	ttls_config_init(&tfw_tls_cfg);
	/* Use cute ECDHE-ECDSA-AES128-GCM-SHA256 by default. */
	r = ttls_config_defaults(&tfw_tls_cfg, TTLS_IS_SERVER);
	if (r) {
		T_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_tls_do_cleanup(void)
{
	ttls_config_free(&tfw_tls_cfg);
	tft_close_filter();
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
tfw_tls_set_allow_any_sni(bool match)
{
	allow_any_sni_reconfig = match;
}

int
tfw_tls_cfg_alpn_protos(const char *cfg_str)
{
	ttls_alpn_proto *proto0 = &tfw_tls_cfg.alpn_list[0];
	ttls_alpn_proto *proto1 = &tfw_tls_cfg.alpn_list[1];

	BUILD_BUG_ON(TTLS_ALPN_PROTOS != 2);

	if (!strcasecmp(cfg_str, "h2")) {
		/* Prefer HTTP/2 over HTTP/1. */
		switch (proto0->id) {
		case TTLS_ALPN_ID_HTTP2:
			return TFW_FSM_H2;
		case TTLS_ALPN_ID_HTTP1:
			*proto1 = *proto0;
			fallthrough;
		case 0:
			proto0->id = TTLS_ALPN_ID_HTTP2;
			proto0->name = TTLS_ALPN_HTTP2;
			proto0->len = sizeof(TTLS_ALPN_HTTP2) - 1;
			return TFW_FSM_H2;
		}
	}

	if (!strcasecmp(cfg_str, "https")) {
		switch (proto0->id) {
		case TTLS_ALPN_ID_HTTP2:
			proto1->id = TTLS_ALPN_ID_HTTP1;
			proto1->name = TTLS_ALPN_HTTP1;
			proto1->len = sizeof(TTLS_ALPN_HTTP1) - 1;
			return TFW_FSM_HTTPS;
		case TTLS_ALPN_ID_HTTP1:
			return TFW_FSM_HTTPS;
		case 0:
			proto0->id = TTLS_ALPN_ID_HTTP1;
			proto0->name = TTLS_ALPN_HTTP1;
			proto0->len = sizeof(TTLS_ALPN_HTTP1) - 1;
			return TFW_FSM_HTTPS;
		}
	}

	if (!strcasecmp(cfg_str, "h2,https") ||
	    !strcasecmp(cfg_str, "https,h2")) {

		proto0->id = TTLS_ALPN_ID_HTTP2;
		proto0->name = TTLS_ALPN_HTTP2;
		proto0->len = sizeof(TTLS_ALPN_HTTP2) - 1;

		proto1->id = TTLS_ALPN_ID_HTTP1;
		proto1->name = TTLS_ALPN_HTTP1;
		proto1->len = sizeof(TTLS_ALPN_HTTP1) - 1;

		return TFW_FSM_HTTPS | Conn_Negotiable;
	}

	return -EINVAL;
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

	return 0;
}

static int
tfw_tls_start(void)
{
	u64 storage_size = tls_get_tf_storage_size();

	tfw_tls_allow_any_sni = allow_any_sni_reconfig;

	if (storage_size && !tft_init_filter(storage_size))
		return -ENOMEM;

	return 0;
}

bool
tfw_tls_get_allow_any_sni_reconfig(void)
{
	return allow_any_sni_reconfig;
}

static TfwCfgSpec tfw_tls_specs[] = {
	{
		.name = "tft",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tls_tf_cfgop_cleanup,
		.dest = tf_hash_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tf_cfgop_begin,
			.finish_hook = tls_tf_cfgop_finish
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
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

	ttls_register_callbacks(tfw_tls_send, tfw_tls_sni, tfw_tls_over,
				ttls_cli_id, tfw_tls_alpn_match,
				tfw_tft_limit_conn, tfw_tft_limit_rec);

	if ((r = tfw_h2_init()))
		goto err_h2;

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_HTTPS);
	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_H2);
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
