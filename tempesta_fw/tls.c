/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include "tls.h"

typedef struct {
	ttls_ssl_config	cfg;
	ttls_x509_crt	crt;
	ttls_pk_context	key;
} TfwTls;

static TfwTls tfw_tls;

/**
 * Called to build crypto request with scatterlist acceptable by the crypto
 * layer from collected skbs when TLS sees end of current message. The function
 * is here only because it has to work with skbs.
 *
 * @len - total length of the message data to be sent to crypto framework.
 * @sg	- pointer to allocated scatterlist;
 * @sgn - as ingress argument contains number of required additional segments
 *	  and returns number of chunks in the scatter list.
 */
static void *
tfw_tls_crypto_req_sglist(TtlsCtx *tls, unsigned int len,
			  struct scatterlist **sg, unsigned int *sgn)
{
	TfwTlsCtx *ttx = (TfwTlsCtx *)tls;
	struct scatterlist *sg_i;
	void *req;
	struct sk_buff *skb = ttx->skb_list;
	unsigned int rsz, off = ttx->off;

	BUG_ON(skb->len <= off);

	req = ttls_alloc_crypto_req((ttx->chunks + *sgn) * sizeof(**sg), &rsz);
	if (!req)
		return NULL;
	*sg = (char *)req + rsz - (ttx->chunks + *sgn) * sizeof(**sg);

	/* The extra segments are allocated on the head. */
	for (sg_i = *sg + *sgn; skb; skb = skb->next, off = 0) {
		int to_read = min(len, skb->len - off);
		int n = skb_to_sgvec(skb, sg_i, off, to_read);
		if (n <= 0)
			goto err;
		len -= to_read;
		sg_i += n;
		if (unlikely(sg_i > *sg + ttx->chunks)) {
			TFW_WARN("not enough scatterlist items\n");
			goto err;
		}
	}
	/* List length must match number of chunks. */
	WARN_ON_ONCE(!skb || skb->next);

	*sgn = sg_i - *sg;
	sg_init_table(*sg, *sgn);
	return req;
err:
	kfree(req);
	return NULL;
}

static int
tfw_tls_msg_process(void *conn, TfwFsmData *data)
{
	int r, parsed = 0;
	struct sk_buff *nskb = NULL, *skb = data->skb;
	unsigned int off = data->off;
	TfwConn *c = conn;
	TfwTlsCtx *ttx = tfw_tls_context(c);
	TfwFsmData data_up = {};

	BUG_ON(data_off >= skb_len);

	/*
	 * Perform TLS handshake if necessary and decrypt the TLS message
	 * in-place by chunks. Add skb to the list to build scatterlist if it
	 * it contains end of current message.
	 */
next_msg:
	ss_skb_queue_tail(&ttx->skb_list, skb);
	r = ss_skb_process(skb, off, ttls_recv, &ttx->tls, &ttx->chunks,
			   &parsed);
	switch (r) {
	default:
		TFW_WARN("Unrecognized TLS receive return code %d,"
			 " drop packet", r);
	case T_DROP:
		__kfree_skb(skb);
		return r;
	case T_POSTPONE:
		/*
		 * No data to pass to upper protolos, typically
		 * handshake and/or incomplete TLS header.
		 */
		// TODO AK: process	MBEDTLS_ERR_SSL_WANT_READ
		// 			MBEDTLS_ERR_SSL_WANT_WRITE
		return TFW_PASS;
	case T_PASS:
		/*
		 * A complete TLS message decrypted and ready for upper
		 * layer protocols processing - fall throught.
		 */
		TFW_DBG("TLS got %d data bytes (%.*s) on conn=%pK\n",
			r, r, skb->data, c);
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
	 * and it hase sense to work with sparse skbs in HTTP
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
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return T_DROP;
		}
	}

	data_up.skb = ttx->skb_list;
	data_up.off = off;
	ttx->skb_list = NULL;
	r = tfw_gfsm_move(&c->state, TFW_TLS_FSM_DATA_READY, data);
	if (r == TFW_BLOCK) {
		kfree_skb(nskb);
		return r;
	}

	ttls_init_msg_ctx(&ttx->tls);
	if (nskb) {
		skb = nskb;
		nskb = NULL;
		off = 0;
		goto next_msg;
	}

	return r;
}

/**
 * Send @buf of length @len using TLS context @tls.
 */
static inline int
tfw_tls_send_buf(TfwConn *c, const unsigned char *buf, size_t len)
{
	int r;
	TfwTlsCtx *ttx = tfw_tls_context(c);

	while ((r = ttls_ssl_write(&tls->tls, buf, len)) > 0) {
		if (r == len)
			return 0;
		buf += r;
		len -= r;
	}

	TFW_ERR("TLS write failed (%x)\n", -r);

	return -EINVAL;
}

/**
 * Send @skb using TLS context @tls.
 */
static inline int
tfw_tls_send_skb(TfwConn *c, struct sk_buff *skb)
{
	int i;

	if (skb_headlen(skb)) {
		if (tfw_tls_send_buf(c, skb->data, skb_headlen(skb)))
		    return -EINVAL;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		if (tfw_tls_send_buf(c, skb_frag_address(f), f->size))
		    return -EINVAL;
	}

	kfree_skb(skb);

	return 0;
}

/**
 * Callback function which is called by TLS library.
 */
static int
tfw_tls_send_cb(void *conn, const unsigned char *buf, size_t len)
{
	TfwConn *c = conn;
	TfwTlsCtx *ttx = tfw_tls_context(c);
	struct sk_buff *skb;

	skb = alloc_skb(MAX_TCP_HEADER + len, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, MAX_TCP_HEADER);
	skb_put(skb, len);

	if (unlikely(skb_store_bits(skb, 0, buf, len)))
		BUG();

	ss_skb_queue_tail(&tls->tx_queue, skb);
	if (ss_send(c->sk, &tls->tx_queue, 0))
		return -EIO;

	TFW_DBG("TLS %lu bytes sent on conn=%pK\n", len, c);

	return len;
}

static void
tfw_tls_conn_dtor(TfwConn *c)
{
	TFwTlsCtx *ttx = tfw_tls_context(c);

	ttls_ssl_free(&ttx.tls->ssl);
	tfw_cli_conn_release((TfwCliConn *)c);
}

static int
tfw_tls_conn_init(TfwConn *c)
{
	int r;
	TfwTlsCtx *ttx = tfw_tls_context(c);

	ttls_ssl_init(&ttx->tls->ssl);
	memset(&ttx->skb_list, 0, sizeof(*ttx)
				  - offsetof(TfwTlsCtx, skb_list));

	r = ttls_ssl_setup(&ttx.tls->ssl, &tfw_tls.cfg);
	if (r) {
		TFW_ERR("TLS (%pK) setup failed (%x)\n", tls, -r);
		return -EINVAL;
	}

	if (tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_init))
		return -EINVAL;

	tfw_gfsm_state_init(&c->state, c, TFW_TLS_FSM_INIT);

	/* Set the destructor */
	c->destructor = (void *)tfw_tls_conn_dtor;

	return 0;
}

static void
tfw_tls_conn_drop(TfwConn *c)
{
	TfwTlsCtx *ttx = tfw_tls_context(c);

	tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_drop);

	ttls_ssl_close_notify(&ttx->tls);
}

static int
tfw_tls_conn_send(TfwConn *c, TfwMsg *msg)
{
	struct sk_buff *skb;
	TfwTlsCtx *ttx = tfw_tls_context(c);

	while ((skb = ss_skb_dequeue(&msg->skb_head))) {
		if (tfw_tls_send_skb(c, skb)) {
			kfree_skb(skb);
			return -EINVAL;
		}
	}

	if (msg->ss_flags & SS_F_CONN_CLOSE)
		ttls_ssl_close_notify(&ttx->tls);

	return 0;
}

static TfwConnHooks tls_conn_hooks = {
	.conn_init	= tfw_tls_conn_init,
	.conn_drop	= tfw_tls_conn_drop,
	.conn_send	= tfw_tls_conn_send,
};

/*
 * ------------------------------------------------------------------------
 *	TLS library configuration
 * ------------------------------------------------------------------------
 */

static int
tfw_tls_rnd_cb(void *rnd, unsigned char *out, size_t len)
{
	/* TODO: improve random generation. */
	get_random_bytes(out, len);
	return 0;
}

static int
tfw_tls_do_init(void)
{
	int r;

	ttls_ssl_config_init(&tfw_tls.cfg);
	r = ttls_ssl_config_defaults(&tfw_tls.cfg,
					TTLS_SSL_IS_SERVER,
					TTLS_SSL_TRANSPORT_STREAM,
					TTLS_SSL_PRESET_DEFAULT);
	if (r) {
		TFW_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

	ttls_ssl_conf_rng(&tfw_tls.cfg, tfw_tls_rnd_cb, NULL);

	return 0;
}

static void
tfw_tls_do_cleanup(void)
{
	ttls_x509_crt_free(&tfw_tls.crt);
	ttls_pk_free(&tfw_tls.key);
	ttls_ssl_config_free(&tfw_tls.cfg);
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

	ttls_ssl_conf_ca_chain(&tfw_tls.cfg, tfw_tls.crt.next, NULL);
	r = ttls_ssl_conf_own_cert(&tfw_tls.cfg, &tfw_tls.crt, &tfw_tls.key);
	if (r) {
		TFW_ERR_NL("TLS: can't set own certificate (%x)\n", -r);
		return -EINVAL;
	}

	return 0;
}

/**
 * Handle 'ssl_certificate <path>' config entry.
 */
static int
tfw_cfgop_ssl_certificate(TfwCfgSpec *cs, TfwCfgEntry *ce)
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

	r = ttls_x509_crt_parse(&tfw_tls.crt,
				   (const unsigned char *)crt_data,
				   crt_size);
	vfree(crt_data);

	if (r) {
		TFW_ERR_NL("%s: Invalid certificate specified (%x)\n",
			   cs->name, -r);
		return -EINVAL;
	}
	tfw_tls_cgf |= TFW_TLS_CFG_F_CERT;

	return 0;
}

static void
tfw_cfgop_cleanup_ssl_certificate(TfwCfgSpec *cs)
{
	ttls_x509_crt_free(&tfw_tls.crt);
	tfw_tls_cgf &= ~TFW_TLS_CFG_F_CERT;
}

/**
 * Handle 'ssl_certificate_key <path>' config entry.
 */
static int
tfw_cfgop_ssl_certificate_key(TfwCfgSpec *cs, TfwCfgEntry *ce)
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

	r = ttls_pk_parse_key(&tfw_tls.key,
				 (const unsigned char *)key_data,
				 key_size, NULL, 0);
	vfree(key_data);

	if (r) {
		TFW_ERR_NL("%s: Invalid private key specified (%x)\n",
			   cs->name, -r);
		return -EINVAL;
	}
	tfw_tls_cgf |= TFW_TLS_CFG_F_CKEY;

	return 0;
}

static void
tfw_cfgop_cleanup_ssl_certificate_key(TfwCfgSpec *cs)
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
		.handler = tfw_cfgop_ssl_certificate,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_ssl_certificate,
	},
	{
		.name = "tls_certificate_key",
		.deflt = NULL,
		.handler = tfw_cfgop_ssl_certificate_key,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_ssl_certificate_key,
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

	ttls_register_bio(tfw_tls_build_scatterlist);

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
