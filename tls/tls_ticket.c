/**
 *		Tempesta TLS
 *
 * TLS server tickets implementation (RFC 5077).
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "debug.h"

#include <crypto/aead.h>

#include "ttls.h"
#include "tls_ticket.h"
#include "tls_internal.h"
#include "lib/common.h"
#include "lib/hash.h"

ttls_cli_id_t *ttls_cli_id_cb;

/*
 * Ciphers used for key generation and ticket decryption. Cached to avoid
 * searches in hot path.
 */
typedef struct {
	const TlsCipherInfo	*cipher_info;
	const TlsMdInfo		*md_info;
} TlsTicketsCfg;

static TlsTicketsCfg t_cfg;

/* Message tag length fo aead encryption for tickets. Since tickets are rather
 * short (less than 200 bytes, 8 bytes for tag is enough.
 */
#define TTLS_TICKETS_TAG_LEN		8

/* ---- Configuration and Key management                                 ---- */

/*
 * Initialisation vector for session ticket master key. Hard-coded to allow
 * the same key generation on all Tempesta nodes with the same user
 * configuration and user secrets. It's ok, that attacker may know it,
 * it's just a value HMAC'ed with a really secret key.
 */
const char *ticket_secret_key_iv =
	"u5xBNXmcQwxs9yGfv3IJa0h3QIZujnuf0ISmycYSB4vhfitCMM1phNP9ft3xjEbR";
/* for ticket symmetric key: */
const char *ticket_key_sym_iv =
	"r26bMJcfLdlYyn9wM3xsHrzraeLKQHGCgYkWivTu6UVxw7VxcJQAr63k8Sa6lFUa";
/* for ticket key name: */
const char *ticket_key_name_iv =
	"qolUvqou29yxSwvz2jWTNvk3znIjy25E";

#define SLEN(s)	(sizeof(s) - 1)

static inline unsigned long
ttls_ticket_get_time(unsigned long lifetime)
{
	unsigned long ts = tfw_current_timestamp();

	ts -= ts % lifetime;

	return ts;
}

static int
__ttls_ticket_gen_key(TlsTicketKey *key, unsigned long ts,
		      const char *secret)
{
	TlsMdCtx md_ctx;
	int r;

	key->ts = ts;
	ttls_md_init(&md_ctx);
	if ((r = ttls_md_setup(&md_ctx, t_cfg.md_info, 1))) {
		T_ERR_NL("TLS: can't init ");
	}
	r |= ttls_md_hmac_starts(&md_ctx, secret, TTLS_TICKET_KEY_LEN);
	r |= ttls_md_hmac_update(&md_ctx, ticket_key_sym_iv,
				 SLEN(ticket_key_sym_iv));
	r |= ttls_md_hmac_update(&md_ctx, (unsigned char *)&key->ts,
				 sizeof(key->ts));
	r |= ttls_md_finish(&md_ctx, key->key);
	ttls_md_free(&md_ctx);

	/*
	 * Set key->ts to 0 to indicate that the calculation has failed and
	 * not try to use the key on every new handshake.
	 */
	if (r) {
		T_WARN("TLS: can't rotate tls key");
		key->ts = 0;
		return r;
	}

	return r;
}

static inline int
ttls_ticket_gen_key(TlsTicketKey *key, const char *secret,  unsigned long ts)
{
	int r;

	write_lock(&key->lock);
	r = __ttls_ticket_gen_key(key, ts, secret);
	write_unlock(&key->lock);

	return r;
}

static int
__ttls_ticket_update_keys(TlsTicketPeerCfg *tcfg)
{
	unsigned long ts = ttls_ticket_get_time(tcfg->lifetime);
	TlsTicketKey *act_key = &tcfg->keys[tcfg->active_key];
	TlsTicketKey *old_key = &tcfg->keys[tcfg->active_key ^ 1];
	int r;

	read_lock(&act_key->lock);
	if (unlikely(act_key->ts >= ts)) {
		read_unlock(&act_key->lock);
		return 0;
	}
	read_unlock(&act_key->lock);

	r = ttls_ticket_gen_key(old_key, tcfg->secret, ts);
	tcfg->active_key ^= 1;

	return r;
}

/**
 * Timer callback for key rotation.
 *
 * If multiple TLS nodes shares the same configuration (including secrets)
 * the callback will be called at the same time (more or less) so all the
 * nodes will have the same keys at the same time. No need for any external
 * synchronisation except time.
 */
static void
ttls_ticket_rotate_keys(unsigned long data)
{
	TlsTicketPeerCfg *tcfg = (TlsTicketPeerCfg *)data;
	unsigned long secs;
	int r;

	T_DBG("TLS: Rotate keys for ticket configuration [%pK]\n", tcfg);
	write_lock(&tcfg->key_lock);
	r = __ttls_ticket_update_keys(tcfg);
	write_unlock(&tcfg->key_lock);
	if (r)
		T_ERR("TLS: Can't rotate keys for ticket configuration [%pK]\n",
		      tcfg);

	/*
	 * It's not possible to set timer just to
	 * jiffies + msecs_to_jiffies(tcfg->lifetime * 1000))
	 * because timers never fire at exact time, they're always a bit late.
	 * Making plain increments will accumulate and propagate the difference
	 * and callback will fire at different time on different Tempesta
	 * nodes. To avoid it need to recalculate timer every time.
	 */
	secs = tcfg->lifetime - (tfw_current_timestamp() % tcfg->lifetime);
	mod_timer(&tcfg->timer, jiffies + msecs_to_jiffies(secs * 1000));
}

/**
 * Get current key, used for encryption. Caller is responsible to unlock the key.
 */
static TlsTicketKey *
ttls_tickets_key_current_locked(TlsTicketPeerCfg *tcfg)
{
	TlsTicketKey *key = NULL;

	read_lock(&tcfg->key_lock);

	if (likely(tcfg->keys[tcfg->active_key].ts)) {
		key = &tcfg->keys[tcfg->active_key];
		read_lock(&key->lock);
	}

	read_unlock(&tcfg->key_lock);

	return key;
}

/**
 * Find key by name, used for decryption. Caller is responsible to unlock the key.
 */
static TlsTicketKey *
ttls_tickets_key_search_locked(TlsTicketPeerCfg *tcfg, const char *key_name)
{
	TlsTicketKey *key = NULL;
	int r;

	read_lock(&tcfg->key_lock);

	key = &tcfg->keys[tcfg->active_key];
	read_lock(&key->lock);
	r = memcmp_fast(key_name, key->name, TTLS_TICKET_KEY_NAME_LEN);
	if (!r && key->ts)
		goto found;
	read_unlock(&key->lock);

	key = &tcfg->keys[tcfg->active_key ^ 1];
	read_lock(&key->lock);
	r = memcmp_fast(key_name, key->name, TTLS_TICKET_KEY_NAME_LEN);
	if (!r && key->ts)
		goto found;
	read_unlock(&key->lock);

	key = NULL;

found:
	read_unlock(&tcfg->key_lock);

	return key;
}

/**
 * Configure Session ticket configuration for selected peer (vhost).
 *
 * @cfg			- peer TLS configuration;
 * @lifetime		- TLS session ticket and key lifetime;
 * @secret_str		- user-generated secret for session ticket key
 *			  generation;
 * @len			- secret length;
 * @vhost_name		- vhost name or SNI name - string to generate unique
 *			  key name;
 * @vn_len		- vhost name length;
 *
 * If user didn't provided a secret key, a random key is generated, but in this
 * case it's not possible to restart the same session on a different Tempesta
 * node in the same group.
 */
int
ttls_tickets_configure(TlsPeerCfg *cfg, unsigned long lifetime,
		       const char *secret_str, size_t len,
		       const char *vhost_name, size_t vn_len)
{
	TlsTicketPeerCfg *tcfg = &cfg->tickets;
	int i, r;
	char rand_secret[TTLS_TICKET_KEY_LEN];
	const char *md_ctx_key = secret_str;
	size_t md_ctx_key_len = len;
	TlsMdCtx md_ctx;
	unsigned long secs;

	tcfg->active_key = 0;
	tcfg->lifetime = lifetime ? : TTLS_DEFAULT_TICKET_LIFETIME;
	rwlock_init(&tcfg->key_lock);

	ttls_md_init(&md_ctx);
	if ((r = ttls_md_setup(&md_ctx, t_cfg.md_info, 1))) {
		T_ERR_NL("TLS: can't init ");
		goto err;
	}
	if (!secret_str || !len) {
		md_ctx_key_len = sizeof(rand_secret);
		md_ctx_key = rand_secret;
		ttls_rnd(rand_secret, sizeof(rand_secret));
	}
	r |= ttls_md_hmac_starts(&md_ctx, md_ctx_key, md_ctx_key_len);
	r |= ttls_md_hmac_update(&md_ctx, ticket_secret_key_iv,
				 SLEN(ticket_secret_key_iv));
	r |= ttls_md_hmac_update(&md_ctx, vhost_name, vn_len);
	r |= ttls_md_finish(&md_ctx, tcfg->secret);
	if (r) {
		T_ERR_NL("TLS: can't init ticket secret for vhost '%s'",
			 vhost_name);
		goto err;
	}

	for (i = 0; i < 2; i++) {
		unsigned char kn_hash[TTLS_TICKET_KEY_LEN];
		TlsTicketKey *key = &tcfg->keys[i];
		unsigned long ts;

		rwlock_init(&key->lock);
		/*
		 * Make a unique name for the key: mix vhost_name and key number
		 * and ticket_key_name_iv. We don't need any cryptography safe
		 * values here. Just something pretty unique, but equal on all
		 * Tempesta noes with the same configuration. Since vhost name
		 * is not something really random, anyone can deduce the value
		 * behind the hash. It's not a problem, we just want to check,
		 * that we have issued the ticket.
		 */
		r = ttls_md_starts(&md_ctx);
		r |= ttls_md_update(&md_ctx, ticket_key_name_iv,
				    SLEN(ticket_key_name_iv));
		r |= ttls_md_update(&md_ctx, (unsigned char *)&i, sizeof(i));
		r |= ttls_md_update(&md_ctx, vhost_name, vn_len);
		r |= ttls_md_finish(&md_ctx, kn_hash);
		if (r) {
			T_ERR_NL("TLS: can't init ticket key name");
			goto err;
		}
		memcpy(key->name, kn_hash,
		       min(sizeof(key->name), sizeof(kn_hash)));
		/*
		 * The configuration is just being created or updated,
		 * create current key, and previous key to allow resuming
		 * sessions with clients who got the session before
		 * (re-)configuration or switched from existent Tempesta nodes
		 * to this fresh new one.
		 */
		ts = ttls_ticket_get_time(tcfg->lifetime);
		if (i)
			ts -= tcfg->lifetime;
		if ((r = __ttls_ticket_gen_key(key, ts, tcfg->secret))) {
			T_ERR_NL("TLS: can't init ticket key value");
			goto err;
		}
	}

	setup_timer(&tcfg->timer, ttls_ticket_rotate_keys, (unsigned long)tcfg);
	secs = tcfg->lifetime - (tfw_current_timestamp() % tcfg->lifetime);
	mod_timer(&tcfg->timer, jiffies + msecs_to_jiffies(secs * 1000));

err:
	ttls_md_free(&md_ctx);
	return r;
}

/**
 * Clean Session Ticket keys.
 *
 * Vhost is unloaded and to be deleted: safe to remove keys. Can be called in
 * process context.
 */
int
ttls_tickets_clean(TlsPeerCfg *cfg)
{
	TlsTicketPeerCfg *tcfg = &cfg->tickets;

	del_timer_sync(&tcfg->timer);
	/* Wipe the keys. */
	memset(tcfg, 0, sizeof(TlsTicketPeerCfg));

	return 0;
}

/**
 * Setup TLS tickets shared context.
 */
int
ttls_tickets_init()
{
	int err = TTLS_ERR_BAD_INPUT_DATA;

	t_cfg.cipher_info = ttls_cipher_info_from_type(TTLS_CIPHER_AES_256_GCM);

	if (!t_cfg.cipher_info
	    || (t_cfg.cipher_info->mode != TTLS_MODE_GCM
		&& t_cfg.cipher_info->mode != TTLS_MODE_CCM)
	    || t_cfg.cipher_info->key_len > TTLS_TICKET_KEY_LEN)
	{
		return err;
	}

	t_cfg.md_info = ttls_md_info_from_type(TTLS_MD_SHA256);
	if (!t_cfg.md_info || !t_cfg.md_info->alg_hmac)
		return err;

	return 0;
}

void ttls_tickets_exit()
{
	memset(&t_cfg, 0, sizeof(t_cfg));
}

/* ---- Processing tickets                                               ---- */

/**
 * Handshake state description to be stored and restored from a TLS ticket.
 * @sess		- Session data, internal structure is used as is;
 * @client_hash		- client identifier, depends on IP address, prevents
 *			  session reuse by different clients;
 * @cert_len		- client certificate length;
 * @cert_data		- raw certificate content;
 */
typedef struct {
	unsigned long	client_hash;
	size_t		cert_len;
	TlsSess		sess;
	char		cert_data[0];
} __attribute__((packed)) TlsState;

/**
 * Session ticket structure as recommended by RFC 5077.
 *
 * @name		- key id, pseudo random number expected to be unique
 *			  for every virtual server, depends on SNI value;
 * @iv			- initialisation vector for crypto operations, unique
 *			  for every ticket;
 * @ts			- timestamp for pseudo-random ticket keys generation;
 * @state		- encrypted ticket payload - saved handshake state;
 *
 * Each ticket uses two cryptographic keys: one to protect payload (handshake
 * state) which contains TLS master key for the connection, the other is used
 * for cryptographic message digest.
 *
 * HMAC is not the part of the structure due to variadic size of the @state.
 */
typedef struct {
	unsigned char	name[TTLS_TICKET_KEY_NAME_LEN];
	unsigned char	iv[TTLS_MAX_IV_LENGTH];
	TlsState	state;
} __attribute__((packed)) TlsTicket;

typedef struct {
	TlsCipherCtx c_ctx;
	int tag_len;

	struct aead_request *req;
} TlSTicketCryptCtx;

static inline size_t
ttls_ticket_sess_true_size(TlsState *state)
{
	return sizeof(TlsState) + state->cert_len;
}

static inline size_t
ttls_ticket_sess_exp_size(const TlsSess *sess)
{
	return sizeof(TlsState) + (sess->peer_cert ? sess->peer_cert->raw.len : 0);
}

/**
 * Serialize a session state
 */
static int
ttls_ticket_sess_save(const TlsSess *sess, TlsState *state, size_t buf_len)
{
	if (buf_len < ttls_ticket_sess_exp_size(sess))
		return TTLS_ERR_BUFFER_TOO_SMALL;

	memcpy_fast(&state->sess, sess, sizeof(TlsSess));
	state->cert_len = sess->peer_cert ? sess->peer_cert->raw.len : 0;

	if (sess->peer_cert)
		memcpy_fast(state->cert_data, sess->peer_cert->raw.p,
			    state->cert_len);

	return 0;
}

/**
 * Deserialise session from the ticket, see ttls_ticket_sess_save()
 */
static int
ttls_ticket_sess_load(TlsState *state, size_t len, unsigned long lifetime)
{
	long time_pass = ttls_time() - state->sess.start;

	if ((time_pass < 0) || (unsigned long)time_pass > lifetime)
		return TTLS_ERR_SESSION_TICKET_EXPIRED;

	if (state->cert_len > len)
		return TTLS_ERR_BAD_INPUT_DATA;

	if (!state->cert_len) {
		state->sess.peer_cert = NULL;
	}
	else {
		TlsSess *sess = &state->sess;
		int r;

		sess->peer_cert = kmalloc(sizeof(ttls_x509_crt), GFP_ATOMIC);
		if (!sess->peer_cert)
			return TTLS_ERR_ALLOC_FAILED;

		ttls_x509_crt_init(sess->peer_cert);
		r = ttls_x509_crt_parse_der(sess->peer_cert, state->cert_data,
					    state->cert_len);
		if (r) {
			ttls_x509_crt_free(sess->peer_cert);
			kfree(sess->peer_cert);
			sess->peer_cert = NULL;
			return r;
		}
	}

	return 0;
}

static void
ttls_ticket_ctx_free(TlSTicketCryptCtx *ctx)
{
	if (ctx->req)
		ttls_aead_req_free(ctx->c_ctx.cipher_ctx, ctx->req);
	ttls_cipher_free(&ctx->c_ctx);
}

static int
ttls_ticket_ctx_init(TlSTicketCryptCtx *ctx, TlsTicket *tik, TlsTicketKey *key)
{
	int r;
	ctx->tag_len = TTLS_TICKETS_TAG_LEN;

	if ((r = ttls_cipher_setup(&ctx->c_ctx, t_cfg.cipher_info, ctx->tag_len)))
		return r;
	r = crypto_aead_setkey(ctx->c_ctx.cipher_ctx, key->key, sizeof(key->key));
	if (r)
		goto err_key;

	ctx->req = ttls_aead_req_alloc(ctx->c_ctx.cipher_ctx);
	if (unlikely(!ctx->req))
		goto err_req;

	aead_request_set_ad(ctx->req, sizeof(TlsTicket) - sizeof(TlsState));
	aead_request_set_tfm(ctx->req, ctx->c_ctx.cipher_ctx);

	return 0;

err_req:
err_key:
	ttls_ticket_ctx_free(ctx);

	return r;
}

static int
ttls_ticket_encrypt(TlsTicket *tik, TlsTicketKey *key, size_t full_enc_len)
{
	TlSTicketCryptCtx ctx = { 0 };
	size_t crypt_len = ttls_ticket_sess_true_size(&tik->state);
	struct scatterlist sg;
	struct sg_table sgt = {
		.sgl	= &sg,
		.nents	= 1,
	};
	int r;

	memcpy_fast(tik->name, key->name, sizeof(key->name));
	ttls_rnd(tik->iv, sizeof(tik->iv));

	if ((r = ttls_ticket_ctx_init(&ctx, tik, key)))
		return r;

	aead_request_set_crypt(ctx.req, sgt.sgl, sgt.sgl, crypt_len, tik->iv);

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, tik, full_enc_len);
	if ((r = crypto_aead_encrypt(ctx.req)))
		T_WARN("AEAD encryption failed: %d\n", r);

	ttls_ticket_ctx_free(&ctx);

	return r;
}

static int
ttls_ticket_decrypt(TlsTicket *tik, size_t len, TlsTicketKey *key)
{
	TlSTicketCryptCtx ctx = { 0 };
	size_t decrypt_len;
	struct scatterlist sg;
	struct sg_table sgt = {
		.sgl	= &sg,
		.nents	= 1,
	};
	int r;

	if ((r = ttls_ticket_ctx_init(&ctx, tik, key)))
		return r;

	decrypt_len = len - (sizeof(TlsTicket) - sizeof(TlsState));
	aead_request_set_crypt(ctx.req, sgt.sgl, sgt.sgl, decrypt_len, tik->iv);

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, tik, len);
	if ((r = crypto_aead_decrypt(ctx.req)))
		T_WARN("AEAD decryption failed: %d\n", r);

	ttls_ticket_ctx_free(&ctx);

	return r;
}

/**
 * Parse a session ticket as generated by the @ttls_ticket_write() function,
 * and, if the ticket is authentic and valid, load the session.
 */
int
ttls_ticket_parse(TlsCtx *ctx, unsigned char *buf, size_t len)
{
	TlsTicket *tik = (TlsTicket *)buf;
	TlsTicketPeerCfg *tcfg = &ctx->peer_conf->tickets;
	TlsTicketKey *key;
	size_t state_len = len - TTLS_TICKET_KEY_NAME_LEN - TTLS_MAX_IV_LENGTH;
	TlsSess *recv_sess;
	unsigned long cli_hash;
	int r;

	if (unlikely(!ctx->peer_conf->sess_tickets))
		return TTLS_ERR_SESSION_TICKET_EXPIRED;
	if (len < sizeof(TlsTicket))
		return TTLS_ERR_BUFFER_TOO_SMALL;

	key = ttls_tickets_key_search_locked(tcfg, tik->name);
	if (unlikely(!key))
		return TTLS_ERR_SESSION_TICKET_EXPIRED;
	r = ttls_ticket_decrypt(tik, len, key);
	read_unlock(&key->lock);
	if (unlikely(r))
		return r;
	/*
	 * RFC 6066 Section 3.
	 * The client SHOULD
	 * include the same server_name extension in the session resumption
	 * request as it did in the full handshake that established the session.
	 * A server that implements this extension MUST NOT accept the request
	 * to resume the session if the server_name extension contains a
	 * different name.
	 *
	 * We make the rule more strict and deny passing tickets between clients
	 * (bots). IP address of a user can be changed time to time (DHCP,
	 * mobile-to-wifi switches, but this doesn't happen on high rates.
	 */
	cli_hash = ttls_cli_id_cb(ctx, ctx->hs->ticket_ctx.sni_hash);
	if (tik->state.client_hash != cli_hash) {
		bzero_fast(tik, len);
		return TTLS_ERR_SESSION_TICKET_EXPIRED;
	}
	r = ttls_ticket_sess_load(&tik->state, state_len, tcfg->lifetime);
	if (unlikely(r)) {
		bzero_fast(tik, len);
		return r;
	}

	/*
	 * Keep the session ID sent by the client, since we MUST send it back to
	 * inform them we're accepting the ticket  (RFC 5077 section 3.4)
	 */
	recv_sess = &tik->state.sess;
	recv_sess->id_len = ctx->sess.id_len;
	memcpy_fast(&recv_sess->id, ctx->sess.id, recv_sess->id_len);
	memcpy_fast(&ctx->sess, recv_sess, sizeof(TlsSess));
	/* Zeroize to protect keys, no need to free as we copied the content */
	bzero_fast(tik, len);

	return 0;
}

/**
 * Add processed server name to hash of server names. Used in TLS session ticket
 * matching.
 */
void
ttls_hs_add_sni_hash(TlsCtx *tls, const char* data, size_t len)
{
	tls->hs->ticket_ctx.sni_hash = len ? hash_calc(data, len) : 0;
}
EXPORT_SYMBOL(ttls_hs_add_sni_hash);

/**
 * Generate an encrypted and authenticated ticket for the session and write
 * it to the output buffer.
 */
int
ttls_ticket_write(TlsCtx *ctx, unsigned char *buf,
		  size_t buf_sz, size_t *tlen,
		  uint32_t *ticket_lifetime)
{
	TlsTicket *tik = (TlsTicket *)buf;
	TlsTicketPeerCfg *tcfg = &ctx->peer_conf->tickets;
	TlsTicketKey *key;
	int r;

	if (unlikely(!ctx->peer_conf->sess_tickets)) {
		*tlen = 0;
		return 0;
	}

	r = ttls_ticket_sess_save(&ctx->sess, &tik->state, buf_sz);
	if (unlikely(r))
		return r;
	tik->state.client_hash = ttls_cli_id_cb(ctx, ctx->hs->ticket_ctx.sni_hash);

	key = ttls_tickets_key_current_locked(tcfg);
	if (unlikely(!key))
		return TTLS_ERR_INTERNAL_ERROR;
	*tlen = sizeof(TlsTicket) + tik->state.cert_len + TTLS_TICKETS_TAG_LEN;
	r = ttls_ticket_encrypt(tik, key, *tlen);
	read_unlock(&key->lock);
	if (unlikely(r))
		return r;

	*ticket_lifetime = tcfg->lifetime;

	return 0;
}
