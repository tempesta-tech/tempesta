/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2021 Tempesta Technologies, Inc.
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
		frang_tls_handler(tls, TFW_TLS_FSM_HS_DONE);
}

int
tfw_tls_msg_process(struct sock *sk, struct sk_buff *skb)
{
	return tls_process_skb(sk, skb, tfw_http_msg_process);
}

/**
 * Callback function which is called by TLS module under tls->lock when it
 * initiates a record transmission, e.g. alert or a handshake message.
 */
static int
tfw_tls_send(TlsCtx *tls)
{
	/*
	 * New skbs are created by tls_send(), so no need to initialize them
	 * in ss_do_send(). tls_skb_settype() for encryption is set for all the
	 * skbs by tls_send().
	 */
	return ss_send(tls->sk, &tls->io_out.skb_list, SS_NO_SKB_INIT);
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

	if ((r = ttls_ctx_init(tls, c->sk, &tfw_tls.cfg))) {
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
			    &c->peer->addr, TFW_WITH_PORT);
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

	ttls_register_callbacks(sizeof(TfwCliConn), tfw_tls_send, tfw_tls_sni,
				frang_tls_handler, ttls_cli_id);

	if ((r = tfw_h2_init()))
		goto err_h2;

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_TLS);
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
	tfw_connection_hooks_unregister(TFW_FSM_TLS);
	tfw_h2_cleanup();
	tfw_tls_do_cleanup();
}
