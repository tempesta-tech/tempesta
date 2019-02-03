/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include "cfg.h"
#include "connection.h"
#include "client.h"
#include "msg.h"
#include "procfs.h"
#include "tls.h"

static struct {
	ttls_config	cfg;
	ttls_x509_crt	crt;
	ttls_pk_context	key;
	unsigned long	crt_pg_addr;
	unsigned int	crt_pg_order;
} tfw_tls;

/**
 * Chop skb list with begin at @skb by TLS extra data at the begin and end of
 * the the list after decryption and write the right pointer at the first skb
 * and offset to @data for upper layers processing.
 */
static int
tfw_tls_chop_skb_rec(TlsCtx *tls, struct sk_buff *skb, TfwFsmData *data)
{
	size_t off = ttls_payload_off(&tls->xfrm);

	while (unlikely(skb->len <= off)) {
		struct sk_buff *skb_head = ss_skb_dequeue(&skb);
		off -= skb_head->len;
		__kfree_skb(skb_head);
		if (WARN_ON_ONCE(!skb))
			return -EIO;
	}

	data->skb = skb;
	data->off = off;
	data->trail = ttls_xfrm_taglen(&tls->xfrm);

	return 0;
}

static int
tfw_tls_msg_process(void *conn, TfwFsmData *data)
{
	int r, parsed = 0;
	struct sk_buff *msg_skb, *nskb = NULL, *skb = data->skb;
	TfwConn *c = conn;
	TlsCtx *tls = tfw_tls_context(c);
	TfwFsmData data_up = {};

	/*
	 * @off is from TCP layer due to possible, but rare (usually malicious),
	 * sequence numbers overlapping. We have to join the skb into a list
	 * containing a complete TLS record with offset as TLS header, so now
	 * we have to chop the header if there is any.
	 */
	if (unlikely(data->off)) {
		BUG_ON(data->off >= skb->len);
		if (ss_skb_chop_head_tail(NULL, skb, data->off, 0))
			return TFW_BLOCK;
	}

	/*
	 * Perform TLS handshake if necessary and decrypt the TLS message
	 * in-place by chunks. Add skb to the list to build scatterlist if
	 * it contains end of current message.
	 */
	spin_lock(&tls->lock);
next_msg:
	ss_skb_queue_tail(&tls->io_in.skb_list, skb);
	/*
	 * Store skb_list since ttls_recv() reinitializes IO context for each
	 * TLS record.
	 */
	msg_skb = tls->io_in.skb_list;

	/* Call TLS layer to place skb into a TLS record on top of skb_list. */
	r = ss_skb_process(skb, 0, 0, ttls_recv, tls, &tls->io_in.chunks,
			   &parsed);
	switch (r) {
	default:
		T_WARN("Unrecognized TLS receive return code %d, drop packet\n",
		       r);
	case T_DROP:
		spin_unlock(&tls->lock);
		__kfree_skb(skb);
		return r;
	case T_POSTPONE:
		/*
		 * No data to pass to upper protolos, could be a handshake
		 * message spread over several skbs and/or incomplete TLS
		 * record. Typically, handshake messages fit the same skb and
		 * all the messages are processed in one ss_skb_process() call.
		 * Collect all skb chunks of data record in skb_list.
		 */
		spin_unlock(&tls->lock);
		return TFW_PASS;
	case T_OK:
		/*
		 * A complete TLS message decrypted and ready for upper
		 * layer protocols processing - fall through.
		 */
		T_DBG3("%s: parsed=%d skb->len=%u\n", __func__,
		       parsed, skb->len);
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

	/* At this point tls->io_in is initialized for the next record. */
	if ((r = tfw_tls_chop_skb_rec(tls, msg_skb, &data_up)))
		goto out_err;
	r = tfw_gfsm_move(&c->state, TFW_TLS_FSM_DATA_READY, &data_up);
	if (r == TFW_BLOCK) {
		spin_unlock(&tls->lock);
		kfree_skb(nskb);
		return r;
	}

	if (nskb) {
		skb = nskb;
		nskb = NULL;
		parsed = 0;
		goto next_msg;
	}

out_err:
	spin_unlock(&tls->lock);

	return r;
}

/**
 * Add the TLS record overhead to current TCP socket control data.
 */
static void
tfw_tls_tcp_add_overhead(struct sock *sk, unsigned int overhead)
{
	sk->sk_wmem_queued += overhead;
	sk_mem_charge(sk, overhead);
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

	next = tcp_write_queue_next(sk, skb);
	tcb_next = TCP_SKB_CB(next);
	WARN_ON_ONCE((tcb_next->seq || tcb_next->end_seq)
		     && tcb_next->seq + next->len != tcb_next->end_seq);

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
	 * TODO #1103 currently even trivail 500-bytes HTTP message generates
	 * 6 segment skb. After the fix the number probably should be decreased.
	 */
#define AUTO_SEGS_N	8

	int r = -ENOMEM;
	unsigned int head_sz, tag_sz, len, frags, t_sz;
	unsigned char type;
	struct sk_buff *next = skb, *skb_tail = skb;
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	TlsCtx *tls = tfw_tls_context(sk->sk_user_data);
	TlsIOCtx *io = &tls->io_out;
	TlsXfrm *xfrm = &tls->xfrm;
	struct sg_table sgt = {
		.nents = skb_shinfo(skb)->nr_frags + !!skb_headlen(skb),
	};
	struct scatterlist sg[AUTO_SEGS_N];

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
	tag_sz = ttls_xfrm_taglen(xfrm);
	len = head_sz + skb->len + tag_sz;
	type = tempesta_tls_skb_type(skb);
	if (!type) {
		T_WARN("%s: bad skb type %u\n", __func__, type);
		return -EINVAL;
	}

	/* TLS header is always allocated from the skb headroom. */
	tcb->end_seq += head_sz;

	/* Try to aggregate several skbs into one TLS record. */
	while (!tcp_skb_is_last(sk, skb_tail)) {
		next = tcp_write_queue_next(sk, skb_tail);
		tcb = TCP_SKB_CB(next);

		T_DBG3("next skb (%pK) in write queue: len=%u frags=%u/%u"
		       " type=%u seq=%u:%u\n",
		       next, next->len, skb_shinfo(next)->nr_frags,
		       !!skb_headlen(next), tempesta_tls_skb_type(next),
		       tcb->seq, tcb->end_seq);

		if (len + next->len > limit)
			break;
		/* Don't put different message types into the same record. */
		if (type != tempesta_tls_skb_type(next))
			break;

		/* @next has original seqnos, so advance both of them. */
		tcb->seq += head_sz;
		tcb->end_seq += head_sz;

		len += next->len;
		sgt.nents += skb_shinfo(next)->nr_frags + !!skb_headlen(next);
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
		r = ss_skb_expand_head_tail(skb->next, skb, head_sz, tag_sz);
		if (r < 0)
			goto out;
	} else {
		r = ss_skb_expand_head_tail(NULL, skb, head_sz, 0);
		if (r < 0)
			goto out;
		sgt.nents += r;

		r = ss_skb_expand_head_tail(skb_tail->next, skb_tail, 0,
					    tag_sz);
		if (r < 0)
			goto out;
	}
	sgt.nents += r;

	/*
	 * The last skb in our list will bring TLS tag - add it to end_seqno.
	 * Otherwise (in worst case), a new skb was inserted to fit TLS tag
	 * - fix end_seqno's for @skb_tail and this new skb.
	 *
	 * @limit = mss_now - tls_overhead, so {tso,tcp}_fragment() called from
	 * tcp_write_xmit() should set proper skb->tcp_gso_segs.
	 */
	if (likely(skb_tail->next == next)) {
		TCP_SKB_CB(skb_tail)->end_seq += tag_sz;

		/* A new frag is added to the end of the current skb. */
		WARN_ON_ONCE(t_sz >= skb_tail->truesize);
		t_sz = skb_tail->truesize - t_sz;
	}
	else {
		WARN_ON_ONCE(skb_tail->next->len != tag_sz);
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
	tcp_sk(sk)->write_seq += head_sz + tag_sz;

	/*
	 * TLS record header is always allocated from the reserved skb headroom.
	 * The room for the tag may also be allocated from the reserved tailroom
	 * or in a new page fragment in skb_tail or next, probably new, skb.
	 * So to adjust the socket write memory we have to check the both skbs
	 * and only for tag_sz.
	 */
	WARN_ON_ONCE(t_sz < tag_sz);
	tfw_tls_tcp_add_overhead(sk, t_sz);

	if (likely(sgt.nents <= AUTO_SEGS_N)) {
		sgt.sgl = sg;
	} else {
		sgt.sgl = kmalloc(sizeof(struct scatterlist) * sgt.nents,
				  GFP_ATOMIC);
		if (!sgt.sgl) {
			T_WARN("cannot alloc TLS encryption scatter list.\n");
			return -ENOMEM;
		}
	}
	sg_init_table(sgt.sgl, sgt.nents);

	for (next = skb, frags = 0; ; ) {
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
		tempesta_tls_skb_clear(next);
		if (next == skb_tail)
			break;
		if (WARN_ON_ONCE(frags >= sgt.nents))
			break;
		next = tcp_write_queue_next(sk, next);
		sg_unmark_end(&sgt.sgl[frags - 1]);
	}
	WARN_ON_ONCE(sgt.nents != frags);

	spin_lock(&tls->lock);

	/* Set IO context under the lock before encryption. */
	io->msglen = len - TLS_HEADER_SIZE;
	io->msgtype = type;
	if (!(r = ttls_encrypt(tls, &sgt)))
		ttls_aad2hdriv(xfrm, skb->data);

	spin_unlock(&tls->lock);

out:
	if (unlikely(sgt.nents > AUTO_SEGS_N))
		kfree(sgt.sgl);

	return r;
#undef AUTO_SEGS_N
}

/**
 * Callback function which is called by TLS module under tls->lock when it
 * initiates a record transmission, e.g. alert or a handshake message.
 */
static int
tfw_tls_send(TlsCtx *tls, struct sg_table *sgt, bool close)
{
	int r, flags = 0;
	TfwTlsConn *conn = container_of(tls, TfwTlsConn, tls);
	TlsIOCtx *io = &tls->io_out;
	TfwMsgIter it;
	TfwStr str = {};

	/*
	 * Encrypted (application data) messages will be prepended by a header
	 * in tfw_tls_encrypt(), so if we have an encryption context, then we
	 * don't send the header. Otherwise (handshake message) copy the whole
	 * data with a header.
	 *
	 * During handshake (!ttls_xfrm_ready(tls)), io may contain several
	 * consequent records of the same TTLS_MSG_HANDSHAKE type. io, except
	 * msglen contains length of the last record, describes the first
	 * record.
	 */
	str.data = io->hdr;
	str.len = TLS_HEADER_SIZE + io->hslen;
	T_DBG("TLS %lu bytes +%u segments (%u bytes, last msgtype %#x)"
	      " are to be sent on conn=%pK/sk_write_xmit=%pK ready=%d\n",
	      str.len, sgt ? sgt->nents : 0, io->msglen, io->msgtype, conn,
	      conn->cli_conn.sk->sk_write_xmit, ttls_xfrm_ready(tls));

	if ((r = tfw_msg_iter_setup(&it, &io->skb_list, str.len)))
		return r;
	if ((r = tfw_msg_write(&it, &str)))
		return r;
	/* Only one skb should has been allocated. */
	WARN_ON_ONCE(it.skb->next != io->skb_list
		     || it.skb->prev != io->skb_list);
	if (sgt) {
		int f, i = ++it.frag;
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

	if (close)
		flags |= SS_F_CONN_CLOSE;
	if (ttls_xfrm_ready(tls))
		flags |= SS_F_ENCRYPT;

	return ss_send(conn->cli_conn.sk, &io->skb_list, flags);
}

static void
tfw_tls_conn_dtor(void *c)
{
	TlsCtx *tls = tfw_tls_context(c);

	ttls_ctx_clear(tls);
	tfw_cli_conn_release((TfwCliConn *)c);
}

static int
tfw_tls_conn_init(TfwConn *c)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);

	if ((r = ttls_ctx_init(tls, &tfw_tls.cfg))) {
		TFW_ERR("TLS (%pK) setup failed (%x)\n", tls, -r);
		return -EINVAL;
	}

	if (tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_init))
		return -EINVAL;

	tfw_gfsm_state_init(&c->state, c, TFW_TLS_FSM_INIT);

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
	 * transmission. Otherwise if we have to close the socket synchronously
	 * and can not write to the socket, then there is no other way than
	 * skip the alert and just close the socket.
	 */
	if (r && sync) {
		TFW_WARN_ADDR("Close TCP socket w/o sending alert to the peer",
			      &c->peer->addr, TFW_WITH_PORT);
		r = ss_close(c->sk, SS_F_SYNC);
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

/*
 * ------------------------------------------------------------------------
 *	TLS library configuration
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
		TFW_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

	/*
	 * TODO #715 set SNI callback with ttls_conf_sni() to get per-vhost
	 * certificates.
	 */

	return 0;
}

static void
tfw_tls_do_cleanup(void)
{
	ttls_x509_crt_free(&tfw_tls.crt);
	ttls_pk_free(&tfw_tls.key);
	ttls_config_free(&tfw_tls.cfg);
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */
/* TLS configuration state. */
#define TFW_TLS_CFG_F_DISABLED	0U
#define TFW_TLS_CFG_F_REQUIRED	1U
#define TFW_TLS_CFG_F_CERT	2U
#define TFW_TLS_CFG_F_CKEY	4U
#define TFW_TLS_CFG_M_ALL	(TFW_TLS_CFG_F_CERT | TFW_TLS_CFG_F_CKEY)

static unsigned int tfw_tls_cgf = TFW_TLS_CFG_F_DISABLED;

void
tfw_tls_cfg_require(void)
{
	tfw_tls_cgf |= TFW_TLS_CFG_F_REQUIRED;
}

static int
tfw_tls_start(void)
{
	int r;

	if (tfw_runstate_is_reconfig())
		return 0;

	ttls_conf_ca_chain(&tfw_tls.cfg, tfw_tls.crt.next, NULL);
	r = ttls_conf_own_cert(&tfw_tls.cfg, &tfw_tls.crt, &tfw_tls.key);
	if (r) {
		TFW_ERR_NL("TLS: can't set own certificate (%x)\n", -r);
		return -EINVAL;
	}

	return 0;
}

/**
 * Handle 'tls_certificate <path>' config entry.
 */
static int
tfw_cfgop_tls_certificate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	void *crt_data;
	size_t crt_size;

	ttls_x509_crt_init(&tfw_tls.crt);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	crt_data = tfw_cfg_read_file((const char *)ce->vals[0], &crt_size);
	if (!crt_data) {
		TFW_ERR_NL("%s: Can't read certificate file '%s'\n",
			   ce->name, (const char *)ce->vals[0]);
		return -EINVAL;
	}

	r = ttls_x509_crt_parse(&tfw_tls.crt, (unsigned char *)crt_data,
				crt_size);
	if (r) {
		TFW_ERR_NL("%s: Invalid certificate specified (%x)\n",
			   cs->name, -r);
		free_pages((unsigned long)crt_data, get_order(crt_size));
		return -EINVAL;
	}
	tfw_tls.crt_pg_addr = (unsigned long)crt_data;
	tfw_tls.crt_pg_order = get_order(crt_size);
	tfw_tls_cgf |= TFW_TLS_CFG_F_CERT;

	return 0;
}

static void
tfw_cfgop_cleanup_tls_certificate(TfwCfgSpec *cs)
{
	ttls_x509_crt_free(&tfw_tls.crt);
	free_pages(tfw_tls.crt_pg_addr, tfw_tls.crt_pg_order);
	tfw_tls_cgf &= ~TFW_TLS_CFG_F_CERT;
}

/**
 * Handle 'tls_certificate_key <path>' config entry.
 */
static int
tfw_cfgop_tls_certificate_key(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	void *key_data;
	size_t key_size;

	ttls_pk_init(&tfw_tls.key);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	key_data = tfw_cfg_read_file((const char *)ce->vals[0], &key_size);
	if (!key_data) {
		TFW_ERR_NL("%s: Can't read certificate file '%s'\n",
			   ce->name, (const char *)ce->vals[0]);
		return -EINVAL;
	}

	r = ttls_pk_parse_key(&tfw_tls.key, (unsigned char *)key_data,
			      key_size);
	/* The key is copied, so free the paged data. */
	free_pages((unsigned long)key_data, get_order(key_size));
	if (r) {
		TFW_ERR_NL("%s: Invalid private key specified (%x)\n",
			   cs->name, -r);
		return -EINVAL;
	}
	tfw_tls_cgf |= TFW_TLS_CFG_F_CKEY;

	return 0;
}

static void
tfw_cfgop_cleanup_tls_certificate_key(TfwCfgSpec *cs)
{
	ttls_pk_free(&tfw_tls.key);
	tfw_tls_cgf &= ~TFW_TLS_CFG_F_CKEY;
}

static int
tfw_tls_cfgend(void)
{
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_REQUIRED)) {
		if (tfw_tls_cgf)
			TFW_WARN_NL("TLS: no HTTPS listener,"
				    " configuration ignored\n");
		return 0;
	}
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CERT)) {
		TFW_ERR_NL("TLS: please specify a certificate with"
			   " tls_certificate configuration option\n");
		return -EINVAL;
	}
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CKEY)) {
		TFW_ERR_NL("TLS: please specify a certificate key with"
			   " tls_certificate_key configuration option\n");
		return -EINVAL;
	}

	return 0;
}

static TfwCfgSpec tfw_tls_specs[] = {
	{
		.name = "tls_certificate",
		.deflt = NULL,
		.handler = tfw_cfgop_tls_certificate,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_tls_certificate,
	},
	{
		.name = "tls_certificate_key",
		.deflt = NULL,
		.handler = tfw_cfgop_tls_certificate_key,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_tls_certificate_key,
	},
	{ 0 }
};

TfwMod tfw_tls_mod = {
	.name	= "tls",
	.cfgend = tfw_tls_cfgend,
	.start	= tfw_tls_start,
	.specs	= tfw_tls_specs,
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

	ttls_register_bio(tfw_tls_send);

	r = tfw_gfsm_register_fsm(TFW_FSM_TLS, tfw_tls_msg_process);
	if (r) {
		tfw_tls_do_cleanup();
		return -EINVAL;
	}

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_TLS);
	tfw_mod_register(&tfw_tls_mod);

	return 0;
}

void
tfw_tls_exit(void)
{
	tfw_mod_unregister(&tfw_tls_mod);
	tfw_connection_hooks_unregister(TFW_FSM_TLS);
	tfw_gfsm_unregister_fsm(TFW_FSM_TLS);
	tfw_tls_do_cleanup();
}
