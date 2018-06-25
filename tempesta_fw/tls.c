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
#include "msg.h"
#include "tls.h"

typedef struct {
	ttls_ssl_config	cfg;
	ttls_x509_crt	crt;
	ttls_pk_context	key;
} TfwTls;

static TfwTls tfw_tls;

static int
tfw_tls_msg_process(void *conn, TfwFsmData *data)
{
	int r, parsed = 0;
	struct sk_buff *nskb = NULL, *skb = data->skb;
	unsigned int off = data->off;
	TfwConn *c = conn;
	TlsCtx *tls = tfw_tls_context(c);
	TfwFsmData data_up = {};

	BUG_ON(data_off >= skb_len);

	/*
	 * Perform TLS handshake if necessary and decrypt the TLS message
	 * in-place by chunks. Add skb to the list to build scatterlist if it
	 * it contains end of current message.
	 */
	spin_lock(&tls->lock);
next_msg:
	ss_skb_queue_tail(&tls->io_in.skb_list, skb);
	r = ss_skb_process(skb, off, ttls_recv, &tls, &tls->io_in.chunks,
			   &parsed);
	switch (r) {
	default:
		TFW_WARN("Unrecognized TLS receive return code %d,"
			 " drop packet", r);
	case T_DROP:
		spin_unlock(&tls->lock);
		__kfree_skb(skb);
		return r;
	case T_POSTPONE:
		/*
		 * No data to pass to upper protolos, typically
		 * handshake and/or incomplete TLS header.
		 */
		// TODO AK: process	MBEDTLS_ERR_SSL_WANT_READ
		// 			MBEDTLS_ERR_SSL_WANT_WRITE
		spin_unlock(&tls->lock);
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
			spin_unlock(&tls->lock);
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return T_DROP;
		}
	}

	data_up.skb = tls->io_in.skb_list;
	data_up.off = off;
	tls->io_in.skb_list = NULL;
	r = tfw_gfsm_move(&c->state, TFW_TLS_FSM_DATA_READY, data);
	if (r == TFW_BLOCK) {
		spin_unlock(&tls->lock);
		kfree_skb(nskb);
		return r;
	}

	ttls_init_msg_ctx(tls);
	if (nskb) {
		skb = nskb;
		nskb = NULL;
		off = 0;
		goto next_msg;
	}
	spin_unlock(&tls->lock);

	return r;
}

/**
 * The callback is called by tcp_write_xmit() if @skb must be encrypted by TLS.
 * If @skb contains a TLS message for encryption, then it's already has a TLS
 * header and enough space for IV and a tag.
 *
 * Probably, that's not beautiful to introduce an alternate upcall beside GFSM
 * and SS, but that's efficient and I didn't find a simple and better solution.
 */
static int
tfw_tls_encrypt(struct sock *sk, struct sk_buff *skb)
{
	int r;
	unsigned short len;
	unsigned char *hdr, type;
	TlsCtx *tls = tfw_tls_context(sk->sk_user_data);
	TlsIOCtx *io = &tls->io_out;

	WARN_ON_ONCE(skb->len > TLS_MAX_PAYLOAD_SIZE);

	len = skb->len + io->xfrm->ivlen + ttls_xfrm_taglen(io->xfrm);
	type = tempesta_tls_skb_type(skb);
	if (!type)
		return -EINVAL;
	hdr = ss_skb_expand_frags(skb, TLS_AAD_SPACE_SIZE, TLS_MAX_TAG_SZ);
	if (!hdr)
		return -ENOMEM;
	tempesta_tls_skb_clear(skb);

	spin_lock(&tls->lock);

	ttls_write_hdr(tls, type, len, hdr);
	r = ttls_encrypt_skb(tfw_tls_context(sk->sk_user_data), skb);

	spin_unlock(&tls->lock);

	return r;
}

/**
 * Callback function which is called by TLS library under tls->lock.
 *
 * The function copies data in tfw_msg_write(), so @buf should be small and
 * can use automatic memory.
 */
static int
tfw_tls_send(TlsCtx *tls, const unsigned char *buf, size_t len, bool encrypt)
{
	int r;
	TfwTlsConn *conn = container_of(tls, TfwTlsConn, tls);
	TlsIOCtx *io = &tls->io_out;
	TfwMsgIter it;
	TfwStr str = { .ptr = buf, .len = len },

	T_DBG("TLS %lu bytes sent on conn=%pK\n", len, c);

	len += TLS_MAX_TAG_SZ;
	if ((r = tfw_msg_iter_setup(&it, &io->skb_list, len)))
		return r;
	if ((r = tfw_msg_write(&it, &str)))
		return r;
	return ss_send(conn->cli_conn.sk, &conn->tls.skb_list,
		       encrypt ? SS_F_TLS : 0);
}

static void
tfw_tls_conn_dtor(void *c)
{
	TlsCtx *tls = tfw_tls_context(c);

	ttls_ctx_free(&tls);
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
	c->sk->sk_write_xmit = tfw_tls_encrypt;

	return 0;
}

static void
tfw_tls_conn_drop(TfwConn *c)
{
	TlsCtx *tls = tfw_tls_context(c);

	tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_drop);

	spin_lock(&tls->lock);
	ttls_close_notify(tls);
	spin_unlock(&tls->lock);
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

	if ((r = ss_send(conn->sk, &msg->skb_head, msg->ss_flags)))
		return r;

	if (msg->ss_flags & SS_F_CONN_CLOSE) {
		spin_lock(&tls->lock);
		r = ttls_close_notify(tls);
		spin_unlock(&tls->lock);
	}

	return r;
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
tfw_tls_do_init(void)
{
	int r;

	ttls_config_init(&tfw_tls.cfg);
	r = ttls_config_defaults(&tfw_tls.cfg, TTLS_IS_SERVER,
				 TTLS_TRANSPORT_STREAM, TTLS_PRESET_DEFAULT);
	if (r) {
		TFW_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

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

	r = ttls_x509_crt_parse(&tfw_tls.crt, (const unsigned char *)crt_data,
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

	r = ttls_pk_parse_key(&tfw_tls.key, (const unsigned char *)key_data,
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
