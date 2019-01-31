/**
 *		Tempesta TLS
 *
 * TLS server tickets implementation (RFC 5077).
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
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
#include "config.h"

#if defined(TTLS_TICKET_C)

#include "ssl_ticket.h"

/*
 * Initialze context
 */
void ttls_ticket_init(ttls_ticket_context *ctx)
{
	memset(ctx, 0, sizeof(ttls_ticket_context));
	spin_lock_init(&ctx->mutex);
}

#define MAX_KEY_BYTES 32	/* 256 bits */

/*
 * Generate/update a key
 * TODO #1054 use a configuration option to generate the key with the random
 * number generator or on top of shared secret.
 */
static int ssl_ticket_gen_key(ttls_ticket_context *ctx,
				   unsigned char index)
{
	int ret;
	unsigned char buf[MAX_KEY_BYTES];
	ttls_ticket_key *key = ctx->keys + index;

	key->generation_time = (uint32_t) ttls_time();

	ttls_rnd(key->name, sizeof(key->name));
	ttls_rnd(buf, sizeof(buf));

	/* With GCM and CCM, same context can encrypt & decrypt */
	ret = ttls_cipher_setkey(&key->ctx, buf, key->ctx.cipher_info->key_len,
				 TTLS_ENCRYPT);

	bzero_fast(buf, sizeof(buf));

	return ret;
}

/*
 * Rotate/generate keys if necessary
 */
static int ssl_ticket_update_keys(ttls_ticket_context *ctx)
{
	if (ctx->ticket_lifetime != 0)
	{
		uint32_t current_time = (uint32_t) ttls_time();
		uint32_t key_time = ctx->keys[ctx->active].generation_time;

		if (current_time > key_time &&
			current_time - key_time < ctx->ticket_lifetime)
		{
			return 0;
		}

		ctx->active = 1 - ctx->active;

		return(ssl_ticket_gen_key(ctx, ctx->active));
	}
	else
		return 0;
}

/**
 * Setup context for actual use.
 *
 * TODO #1054: Use strong enough, but fast, cipher, e.g. AES-GCM-256.
 * @lifetime should be configurable, and typically not so large, e.g. 2h.
 */
int ttls_ticket_setup(ttls_ticket_context *ctx, ttls_cipher_type_t cipher,
	uint32_t lifetime)
{
	int ret;
	const TlsCipherInfo *cipher_info;

	ctx->ticket_lifetime = lifetime;

	cipher_info = ttls_cipher_info_from_type(cipher);
	if (cipher_info == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	if (cipher_info->mode != TTLS_MODE_GCM &&
		cipher_info->mode != TTLS_MODE_CCM)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	if (cipher_info->key_len > MAX_KEY_BYTES)
		return(TTLS_ERR_BAD_INPUT_DATA);

	/* TODO set correct auth tag size. */
	if ((ret = ttls_cipher_setup(&ctx->keys[0].ctx, cipher_info, 16)) ||
		(ret = ttls_cipher_setup(&ctx->keys[1].ctx, cipher_info, 16)))
	{
		return ret;
	}

	if ((ret = ssl_ticket_gen_key(ctx, 0)) != 0 ||
		(ret = ssl_ticket_gen_key(ctx, 1)) != 0)
	{
		return ret;
	}

	return 0;
}

/*
 * Serialize a session in the following format:
 *  0   .   n-1	 session structure, n = sizeof(TlsSess)
 *  n   .   n+2	 peer_cert length = m (0 if no certificate)
 *  n+3 .   n+2+m   peer cert ASN.1
 */
static int ssl_save_session(const TlsSess *session,
				 unsigned char *buf, size_t buf_len,
				 size_t *olen)
{
	unsigned char *p = buf;
	size_t left = buf_len;
	size_t cert_len;

	if (left < sizeof(TlsSess))
		return(TTLS_ERR_BUFFER_TOO_SMALL);

	memcpy(p, session, sizeof(TlsSess));
	p += sizeof(TlsSess);
	left -= sizeof(TlsSess);

	if (session->peer_cert == NULL)
		cert_len = 0;
	else
		cert_len = session->peer_cert->raw.len;

	if (left < 3 + cert_len)
		return(TTLS_ERR_BUFFER_TOO_SMALL);

	*p++ = (unsigned char)(cert_len >> 16 & 0xFF);
	*p++ = (unsigned char)(cert_len >>  8 & 0xFF);
	*p++ = (unsigned char)(cert_len	   & 0xFF);

	if (session->peer_cert != NULL)
		memcpy(p, session->peer_cert->raw.p, cert_len);

	p += cert_len;

	*olen = p - buf;

	return 0;
}

/*
 * Unserialise session, see ssl_save_session()
 */
static int ssl_load_session(TlsSess *session,
				 const unsigned char *buf, size_t len)
{
	const unsigned char *p = buf;
	const unsigned char * const end = buf + len;
	size_t cert_len;

	if (p + sizeof(TlsSess) > end)
		return(TTLS_ERR_BAD_INPUT_DATA);

	memcpy(session, p, sizeof(TlsSess));
	p += sizeof(TlsSess);

	if (p + 3 > end)
		return(TTLS_ERR_BAD_INPUT_DATA);

	cert_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (cert_len == 0)
	{
		session->peer_cert = NULL;
	}
	else
	{
		int ret;

		if (p + cert_len > end)
			return(TTLS_ERR_BAD_INPUT_DATA);

		session->peer_cert = ttls_calloc(1, sizeof(ttls_x509_crt));

		if (session->peer_cert == NULL)
			return(TTLS_ERR_ALLOC_FAILED);

		ttls_x509_crt_init(session->peer_cert);

		if ((ret = ttls_x509_crt_parse_der(session->peer_cert,
				p, cert_len)) != 0)
		{
			ttls_x509_crt_free(session->peer_cert);
			ttls_free(session->peer_cert);
			session->peer_cert = NULL;
			return ret;
		}

		p += cert_len;
	}

	if (p != end)
		return(TTLS_ERR_BAD_INPUT_DATA);

	return 0;
}

/*
 * Create session ticket, with the following structure:
 *
 *	struct {
 *		opaque key_name[4];
 *		opaque iv[12];
 *		opaque encrypted_state<0..2^16-1>;
 *		opaque tag[16];
 *	} ticket;
 *
 * The key_name, iv, and length of encrypted_state are the additional
 * authenticated data.
 */
int ttls_ticket_write(void *p_ticket,
				  const TlsSess *session,
				  unsigned char *start,
				  const unsigned char *end,
				  size_t *tlen,
				  uint32_t *ticket_lifetime)
{
	int ret;
	ttls_ticket_context *ctx = p_ticket;
	ttls_ticket_key *key;
	unsigned char *key_name = start;
	unsigned char *iv = start + 4;
	unsigned char *state_len_bytes = iv + 12;
	unsigned char *state = state_len_bytes + 2;
	unsigned char *tag;
	size_t clear_len, ciph_len;

	*tlen = 0;

	if (ctx == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	/* We need at least 4 bytes for key_name, 12 for IV, 2 for len 16 for tag,
	 * in addition to session itself, that will be checked when writing it. */
	if (end - start < 4 + 12 + 2 + 16)
		return(TTLS_ERR_BUFFER_TOO_SMALL);

	spin_lock(&ctx->mutex);

	if ((ret = ssl_ticket_update_keys(ctx)) != 0)
		goto cleanup;

	key = &ctx->keys[ctx->active];

	*ticket_lifetime = ctx->ticket_lifetime;

	memcpy(key_name, key->name, 4);

	ttls_rnd(iv, 12);

	/* Dump session state */
	if ((ret = ssl_save_session(session,
		  state, end - state, &clear_len)) != 0 ||
		(unsigned long) clear_len > 65535)
	{
		 goto cleanup;
	}
	state_len_bytes[0] = (clear_len >> 8) & 0xff;
	state_len_bytes[1] = (clear_len	 ) & 0xff;

	/* Encrypt and authenticate */
	tag = state + clear_len;
	/* TODO replace with linux/crypto as in ttls.c. */
	if ((ret = ttls_cipher_auth_encrypt(&key->ctx,
		iv, 12, key_name, 4 + 12 + 2,
		state, clear_len, state, &ciph_len, tag, 16)) != 0)
	{
		goto cleanup;
	}
	if (ciph_len != clear_len)
	{
		ret = TTLS_ERR_INTERNAL_ERROR;
		goto cleanup;
	}

	*tlen = 4 + 12 + 2 + 16 + ciph_len;

cleanup:
	spin_unlock(&ctx->mutex);

	return ret;
}

/*
 * Select key based on name
 */
static ttls_ticket_key *ssl_ticket_select_key(
		ttls_ticket_context *ctx,
		const unsigned char name[4])
{
	unsigned char i;

	for (i = 0; i < sizeof(ctx->keys) / sizeof(*ctx->keys); i++)
		if (memcmp(name, ctx->keys[i].name, 4) == 0)
			return(&ctx->keys[i]);

	return(NULL);
}

/*
 * Load session ticket (see ttls_ticket_write for structure)
 */
int ttls_ticket_parse(void *p_ticket,
				  TlsSess *session,
				  unsigned char *buf,
				  size_t len)
{
	int ret;
	ttls_ticket_context *ctx = p_ticket;
	ttls_ticket_key *key;
	unsigned char *key_name = buf;
	unsigned char *iv = buf + 4;
	unsigned char *enc_len_p = iv + 12;
	unsigned char *ticket = enc_len_p + 2;
	unsigned char *tag;
	size_t enc_len, clear_len;

	if (ctx == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	/* See ttls_ticket_write() */
	if (len < 4 + 12 + 2 + 16)
		return(TTLS_ERR_BAD_INPUT_DATA);

	spin_lock(&ctx->mutex);

	if ((ret = ssl_ticket_update_keys(ctx)) != 0)
		goto cleanup;

	enc_len = (enc_len_p[0] << 8) | enc_len_p[1];
	tag = ticket + enc_len;

	if (len != 4 + 12 + 2 + enc_len + 16)
	{
		ret = TTLS_ERR_BAD_INPUT_DATA;
		goto cleanup;
	}

	/* Select key */
	if ((key = ssl_ticket_select_key(ctx, key_name)) == NULL)
	{
		/* We can't know for sure but this is a likely option unless we're
		 * under attack - this is only informative anyway */
		ret = TTLS_ERR_SESSION_TICKET_EXPIRED;
		goto cleanup;
	}

	/* Decrypt and authenticate */
	/* TODO replace with linux/crypto as in ttls.c. */
	if ((ret = ttls_cipher_auth_decrypt(&key->ctx, iv, 12,
		key_name, 4 + 12 + 2, ticket, enc_len,
		ticket, &clear_len, tag, 16)) != 0)
	{
		goto cleanup;
	}
	if (clear_len != enc_len)
	{
		ret = TTLS_ERR_INTERNAL_ERROR;
		goto cleanup;
	}

	/* Actually load session */
	if ((ret = ssl_load_session(session, ticket, clear_len)) != 0)
		goto cleanup;

	{
		/* Check for expiration */
		time_t current_time = ttls_time();

		if (current_time < session->start ||
			(uint32_t)(current_time - session->start) > ctx->ticket_lifetime)
		{
			ret = TTLS_ERR_SESSION_TICKET_EXPIRED;
			goto cleanup;
		}
	}

cleanup:
	spin_unlock(&ctx->mutex);

	return ret;
}

/*
 * Free context
 */
void ttls_ticket_free(ttls_ticket_context *ctx)
{
	ttls_cipher_free(&ctx->keys[0].ctx);
	ttls_cipher_free(&ctx->keys[1].ctx);
	bzero_fast(ctx, sizeof(ttls_ticket_context));
}

#endif /* TTLS_TICKET_C */
