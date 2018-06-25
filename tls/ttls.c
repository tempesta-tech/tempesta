/*
 *		Tempesta TLS
 *
 * Main TLS shared functions for the server and client.
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
#include <asm/fpu/api.h>
#include <linux/module.h>
#include <net/tls.h>

#include "lib/str.h"
#include "config.h"
#include "debug.h"
#include "oid.h"
#include "ssl_internal.h"
#include "ttls.h"

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta TLS");
MODULE_VERSION("0.2.0");
MODULE_LICENSE("GPL");

static struct kmem_cache *ttls_hs_cache;
static ttls_send_cb_t	*ttls_send_cb;

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
static struct aead_request *
ttls_crypto_req_sglist(TlsCtx *tls, unsigned int len, struct scatterlist **sg,
		       unsigned int *sgn)
{
	TlsIOCtx *io = &tls->io_in;
	struct scatterlist *sg_i;
	struct aaed_request *req;
	struct sk_buff *skb = io->skb_list;
	unsigned int sz, off = io->off;

	BUG_ON(skb->len <= off);

	sz = sizeof(*req) + (io->chunks + *sgn) * sizeof(**sg);
	req = kmalloc(sz, GFP_ATOMIC);
	if (!req)
		return NULL;
	*sg = (struct scatterlist *)(req + 1);

	/* The extra segments are allocated on the head. */
	for (sg_i = *sg + *sgn; skb; skb = skb->next, off = 0) {
		int to_read = min(len, skb->len - off);
		int n = skb_to_sgvec(skb, sg_i, off, to_read);
		if (n <= 0)
			goto err;
		len -= to_read;
		sg_i += n;
		if (unlikely(sg_i > *sg + io->chunks)) {
			TFW_WARN("not enough scatterlist items\n");
			goto err;
		}
	}
	/* List length must match number of chunks. */
	WARN_ON_ONCE(!skb || skb->next);

	*sgn = sg_i - *sg;
	sg_mark_end(*sg + *sgn - 1);
	return req;
err:
	kfree(req);
	return NULL;
}

/**
 * Register I/O callbacks from the underlying network layer.
 */
void
ttls_register_bio(ttls_send_cb_t *send_cb)
{
	ttls_send_cb = send_cb;
}

static int
ttls_ep_check(TlsIOCtx *io, const char *iod)
{
	int i;
	int ep_len = 0; /* Length of the "epoch" field in the record header */

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ep_len = 2;
#endif

	for (i = 8; i > ep_len; i--)
		if (++io->ctr[i - 1])
			break;
	/* The loop goes to its end iff the counter is wrapping. */
	if (i == ep_len) {
		T_WARN("%s message counter would wrap\n", iod);
		return TTLS_ERR_COUNTER_WRAPPING;
	}
	return 0;
}

/*
 * Start a timer.
 * Passing millisecs = 0 cancels a running timer.
 */
static void ssl_set_timer(ttls_context *tls, uint32_t millisecs)
{
	if (tls->f_set_timer == NULL)
		return;

	TTLS_DEBUG_MSG(3, ("set_timer to %d ms", (int) millisecs));
	tls->f_set_timer(tls->p_timer, millisecs / 4, millisecs);
}

/*
 * Return -1 is timer is expired, 0 if it isn't.
 */
static int ssl_check_timer(ttls_context *tls)
{
	if (tls->f_get_timer == NULL)
		return 0;

	if (tls->f_get_timer(tls->p_timer) == 2)
	{
		TTLS_DEBUG_MSG(3, ("timer expired"));
		return(-1);
	}

	return 0;
}

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *	enum{
 *		2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *	} MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static unsigned int mfl_code_to_length[TTLS_MAX_FRAG_LEN_INVALID] =
{
	TTLS_MAX_CONTENT_LEN,	/* TTLS_MAX_FRAG_LEN_NONE */
	512,					/* TTLS_MAX_FRAG_LEN_512 */
	1024,				 /* TTLS_MAX_FRAG_LEN_1024 */
	2048,				 /* TTLS_MAX_FRAG_LEN_2048 */
	4096,				 /* TTLS_MAX_FRAG_LEN_4096 */
};
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

#if defined(TTLS_CLI_C)
static int ssl_session_copy(ttls_session *dst, const ttls_session *src)
{
	ttls_session_free(dst);
	memcpy(dst, src, sizeof(ttls_session));

	if (src->peer_cert != NULL)
	{
		int r;

		dst->peer_cert = ttls_calloc(1, sizeof(ttls_x509_crt));
		if (dst->peer_cert == NULL)
			return(TTLS_ERR_ALLOC_FAILED);

		ttls_x509_crt_init(dst->peer_cert);

		if ((r = ttls_x509_crt_parse_der(dst->peer_cert, src->peer_cert->raw.p,
							src->peer_cert->raw.len)) != 0)
		{
			ttls_free(dst->peer_cert);
			dst->peer_cert = NULL;
			return r;
		}
	}

#if defined(TTLS_SESSION_TICKETS) && defined(TTLS_CLI_C)
	if (src->ticket != NULL)
	{
		dst->ticket = ttls_calloc(1, src->ticket_len);
		if (dst->ticket == NULL)
			return(TTLS_ERR_ALLOC_FAILED);

		memcpy(dst->ticket, src->ticket, src->ticket_len);
	}
#endif /* TTLS_SESSION_TICKETS && TTLS_CLI_C */

	return 0;
}
#endif /* TTLS_CLI_C */

/*
 * Key material generation
 */
static int tls_prf_generic(ttls_md_type_t md_type,
			const unsigned char *secret, size_t slen,
			const char *label,
			const unsigned char *random, size_t rlen,
			unsigned char *dstbuf, size_t dlen)
{
	size_t nb;
	size_t i, j, k, md_len;
	unsigned char tmp[128];
	unsigned char h_i[TTLS_MD_MAX_SIZE];
	const ttls_md_info_t *md_info;
	ttls_md_context_t md_ctx;
	int r;

	ttls_md_init(&md_ctx);

	if ((md_info = ttls_md_info_from_type(md_type)) == NULL)
		return(TTLS_ERR_INTERNAL_ERROR);

	md_len = ttls_md_get_size(md_info);

	if (sizeof(tmp) < md_len + strlen(label) + rlen)
		return(TTLS_ERR_BAD_INPUT_DATA);

	nb = strlen(label);
	memcpy(tmp + md_len, label, nb);
	memcpy(tmp + md_len + nb, random, rlen);
	nb += rlen;

	/*
	 * Compute P_<hash>(secret, label + random)[0..dlen]
	 */
	if ((r = ttls_md_setup(&md_ctx, md_info, 1)) != 0)
		return r;

	ttls_md_hmac_starts(&md_ctx, secret, slen);
	ttls_md_hmac_update(&md_ctx, tmp + md_len, nb);
	ttls_md_hmac_finish(&md_ctx, tmp);

	for (i = 0; i < dlen; i += md_len)
	{
		ttls_md_hmac_reset (&md_ctx);
		ttls_md_hmac_update(&md_ctx, tmp, md_len + nb);
		ttls_md_hmac_finish(&md_ctx, h_i);

		ttls_md_hmac_reset (&md_ctx);
		ttls_md_hmac_update(&md_ctx, tmp, md_len);
		ttls_md_hmac_finish(&md_ctx, tmp);

		k = (i + md_len > dlen) ? dlen % md_len : md_len;

		for (j = 0; j < k; j++)
			dstbuf[i + j] = h_i[j];
	}

	ttls_md_free(&md_ctx);

	bzero_fast(tmp, sizeof(tmp));
	bzero_fast(h_i, sizeof(h_i));

	return 0;
}

#if defined(TTLS_SHA256_C)
static int tls_prf_sha256(const unsigned char *secret, size_t slen,
		 const char *label,
		 const unsigned char *random, size_t rlen,
		 unsigned char *dstbuf, size_t dlen)
{
	return(tls_prf_generic(TTLS_MD_SHA256, secret, slen,
			 label, random, rlen, dstbuf, dlen));
}
#endif /* TTLS_SHA256_C */

#if defined(TTLS_SHA512_C)
static int tls_prf_sha384(const unsigned char *secret, size_t slen,
		 const char *label,
		 const unsigned char *random, size_t rlen,
		 unsigned char *dstbuf, size_t dlen)
{
	return(tls_prf_generic(TTLS_MD_SHA384, secret, slen,
			 label, random, rlen, dstbuf, dlen));
}
#endif /* TTLS_SHA512_C */

static void ssl_update_checksum_start(ttls_context *, const unsigned char *, size_t);

#if defined(TTLS_SHA256_C)
static void ssl_update_checksum_sha256(ttls_context *, const unsigned char *, size_t);
static void ssl_calc_verify_tls_sha256(ttls_context *,unsigned char *);
static void ssl_calc_finished_tls_sha256(ttls_context *,unsigned char *, int);
#endif

#if defined(TTLS_SHA512_C)
static void ssl_update_checksum_sha384(ttls_context *, const unsigned char *, size_t);
static void ssl_calc_verify_tls_sha384(ttls_context *, unsigned char *);
static void ssl_calc_finished_tls_sha384(ttls_context *, unsigned char *, int);
#endif

int ttls_derive_keys(ttls_context *tls)
{
	int r = 0;
	unsigned char tmp[64];
	unsigned char keyblk[256];
	unsigned char *key1;
	unsigned char *key2;
	unsigned char *mac_enc;
	unsigned char *mac_dec;
	size_t mac_key_len;
	size_t iv_copy_len;
	const ttls_cipher_info_t *cipher_info;
	const ttls_md_info_t *md_info;

	ttls_session *session = tls->session_negotiate;
	ttls_transform *transform = tls->transform_negotiate;
	TlsHandshake *hs = tls->hs;

	TTLS_DEBUG_MSG(2, ("=> derive keys"));

	cipher_info = ttls_cipher_info_from_type(transform->ciphersuite_info->cipher);
	if (cipher_info == NULL)
	{
		TTLS_DEBUG_MSG(1, ("cipher info for %d not found",
							transform->ciphersuite_info->cipher));
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	md_info = ttls_md_info_from_type(transform->ciphersuite_info->mac);
	if (md_info == NULL)
	{
		TTLS_DEBUG_MSG(1, ("ttls_md info for %d not found",
							transform->ciphersuite_info->mac));
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	/*
	 * Set appropriate PRF function and other TLS1.2 functions
	 */
#if defined(TTLS_SHA512_C)
	if (tls->minor_ver == TTLS_MINOR_VERSION_3 &&
		transform->ciphersuite_info->mac == TTLS_MD_SHA384)
	{
		hs->tls_prf = tls_prf_sha384;
		hs->calc_verify = ssl_calc_verify_tls_sha384;
		hs->calc_finished = ssl_calc_finished_tls_sha384;
	}
	else
#endif
#if defined(TTLS_SHA256_C)
	if (tls->minor_ver == TTLS_MINOR_VERSION_3)
	{
		hs->tls_prf = tls_prf_sha256;
		hs->calc_verify = ssl_calc_verify_tls_sha256;
		hs->calc_finished = ssl_calc_finished_tls_sha256;
	}
	else
#endif
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	/*
	 * SSLv3:
	 * master =
	 *	 MD5(premaster + SHA1('A' + premaster + randbytes)) +
	 *	 MD5(premaster + SHA1('BB' + premaster + randbytes)) +
	 *	 MD5(premaster + SHA1('CCC' + premaster + randbytes))
	 *
	 * TLSv1+:
	 * master = PRF(premaster, "master secret", randbytes)[0..47]
	 */
	if (hs->resume == 0)
	{
		TTLS_DEBUG_BUF(3, "premaster secret", hs->premaster,
					 hs->pmslen);

#if defined(TTLS_EXTENDED_MASTER_SECRET)
		if (tls->hs->extended_ms == TTLS_EXTENDED_MS_ENABLED)
		{
			unsigned char session_hash[48];
			size_t hash_len;

			TTLS_DEBUG_MSG(3, ("using extended master secret"));

			tls->hs->calc_verify(tls, session_hash);

			if (tls->minor_ver == TTLS_MINOR_VERSION_3)
			{
#if defined(TTLS_SHA512_C)
				if (tls->transform_negotiate->ciphersuite_info->mac ==
					TTLS_MD_SHA384)
				{
					hash_len = 48;
				}
				else
#endif
					hash_len = 32;
			}
			else
				hash_len = 36;

			TTLS_DEBUG_BUF(3, "session hash", session_hash, hash_len);

			r = hs->tls_prf(hs->premaster, hs->pmslen,
						 "extended master secret",
						 session_hash, hash_len,
						 session->master, 48);
			if (r != 0)
			{
				TTLS_DEBUG_RET(1, "prf", r);
				return r;
			}

		}
		else
#endif
		r = hs->tls_prf(hs->premaster, hs->pmslen,
					 "master secret",
					 hs->randbytes, 64,
					 session->master, 48);
		if (r != 0)
		{
			TTLS_DEBUG_RET(1, "prf", r);
			return r;
		}

		bzero_fast(hs->premaster, sizeof(hs->premaster));
	}
	else
		TTLS_DEBUG_MSG(3, ("no premaster (session resumed)"));

	/*
	 * Swap the client and server random values.
	 */
	memcpy(tmp, hs->randbytes, 64);
	memcpy(hs->randbytes, tmp + 32, 32);
	memcpy(hs->randbytes + 32, tmp, 32);
	bzero_fast(tmp, sizeof(tmp));

	/*
	 * SSLv3:
	 *	key block =
	 *	 MD5(master + SHA1('A'	+ master + randbytes)) +
	 *	 MD5(master + SHA1('BB' + master + randbytes)) +
	 *	 MD5(master + SHA1('CCC' + master + randbytes)) +
	 *	 MD5(master + SHA1('DDDD' + master + randbytes)) +
	 *	 ...
	 *
	 * TLSv1:
	 *	key block = PRF(master, "key expansion", randbytes)
	 */
	r = hs->tls_prf(session->master, 48, "key expansion",
				 hs->randbytes, 64, keyblk, 256);
	if (r != 0)
	{
		TTLS_DEBUG_RET(1, "prf", r);
		return r;
	}

	TTLS_DEBUG_MSG(3, ("ciphersuite = %s",
		ttls_get_ciphersuite_name(session->ciphersuite)));
	TTLS_DEBUG_BUF(3, "master secret", session->master, 48);
	TTLS_DEBUG_BUF(4, "random bytes", hs->randbytes, 64);
	TTLS_DEBUG_BUF(4, "key block", keyblk, 256);

	bzero_fast(hs->randbytes, sizeof(hs->randbytes));

	/*
	 * Determine the appropriate key, IV and MAC length.
	 */

	transform->keylen = cipher_info->key_bitlen / 8;

	if (cipher_info->mode == TTLS_MODE_GCM
	    || cipher_info->mode == TTLS_MODE_CCM)
	{
		transform->maclen = 0;
		mac_key_len = 0;

		transform->ivlen = 12;
		transform->fixed_ivlen = 4;

		/* Minimum length is expicit IV + tag */
		transform->minlen = transform->ivlen - transform->fixed_ivlen
				+ (transform->ciphersuite_info->flags &
				TTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16);
	}
	else
	{
		/* Initialize HMAC contexts */
		if ((r = ttls_md_setup(&transform->md_ctx_enc, md_info, 1)) != 0 ||
			(r = ttls_md_setup(&transform->md_ctx_dec, md_info, 1)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_md_setup", r);
			return r;
		}

		/* Get MAC length */
		mac_key_len = ttls_md_get_size(md_info);
		transform->maclen = mac_key_len;

		/* IV length */
		transform->ivlen = cipher_info->iv_size;
		WARN_ON_ONCE(transform->ivlen > 16);

		/* Minimum length */
		if (cipher_info->mode == TTLS_MODE_STREAM)
			transform->minlen = transform->maclen;
		else
		{
			/*
			 * GenericBlockCipher:
			 * 1. if EtM is in use: one block plus MAC
			 *	otherwise: * first multiple of blocklen greater than maclen
			 * 2. IV except for SSL3 and TLS 1.0
			 */
			if (session->encrypt_then_mac) {
				transform->minlen = transform->maclen
					 + cipher_info->block_size;
			} else {
				transform->minlen = transform->maclen
					 + cipher_info->block_size
					 - transform->maclen % cipher_info->block_size;
			}
			transform->minlen += transform->ivlen;
		}
	}

	TTLS_DEBUG_MSG(3, ("keylen: %d, minlen: %d, ivlen: %d, maclen: %d",
			 transform->keylen, transform->minlen, transform->ivlen,
			 transform->maclen));

	/*
	 * Finally setup the cipher contexts, IVs and MAC secrets.
	 */
#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT)
	{
		key1 = keyblk + mac_key_len * 2;
		key2 = keyblk + mac_key_len * 2 + transform->keylen;

		mac_enc = keyblk;
		mac_dec = keyblk + mac_key_len;

		iv_copy_len = (transform->fixed_ivlen) ?
					transform->fixed_ivlen : transform->ivlen;
		memcpy(transform->iv_enc, key2 + transform->keylen, iv_copy_len);
		memcpy(transform->iv_dec, key2 + transform->keylen + iv_copy_len,
				iv_copy_len);
	}
	else
#endif /* TTLS_CLI_C */
	if (tls->conf->endpoint == TTLS_IS_SERVER)
	{
		key1 = keyblk + mac_key_len * 2 + transform->keylen;
		key2 = keyblk + mac_key_len * 2;

		mac_enc = keyblk + mac_key_len;
		mac_dec = keyblk;

		iv_copy_len = (transform->fixed_ivlen) ?
					transform->fixed_ivlen : transform->ivlen;
		memcpy(transform->iv_dec, key1 + transform->keylen, iv_copy_len);
		memcpy(transform->iv_enc, key1 + transform->keylen + iv_copy_len,
				iv_copy_len);
	}
	else
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	if (tls->minor_ver >= TTLS_MINOR_VERSION_1)
	{
		ttls_md_hmac_starts(&transform->md_ctx_enc, mac_enc, mac_key_len);
		ttls_md_hmac_starts(&transform->md_ctx_dec, mac_dec, mac_key_len);
	}
	else
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

#if defined(TTLS_EXPORT_KEYS)
	if (tls->conf->f_export_keys != NULL)
	{
		tls->conf->f_export_keys(tls->conf->p_export_keys,
				 session->master, keyblk,
				 mac_key_len, transform->keylen,
				 iv_copy_len);
	}
#endif

	if ((r = ttls_cipher_setup(&transform->cipher_ctx_enc,
					 cipher_info)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_cipher_setup", r);
		return r;
	}

	if ((r = ttls_cipher_setup(&transform->cipher_ctx_dec,
					 cipher_info)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_cipher_setup", r);
		return r;
	}

	if ((r = ttls_cipher_setkey(&transform->cipher_ctx_enc, key1,
					 cipher_info->key_bitlen,
					 TTLS_ENCRYPT)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_cipher_setkey", r);
		return r;
	}

	if ((r = ttls_cipher_setkey(&transform->cipher_ctx_dec, key2,
					 cipher_info->key_bitlen,
					 TTLS_DECRYPT)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_cipher_setkey", r);
		return r;
	}

	bzero_fast(keyblk, sizeof(keyblk));

	TTLS_DEBUG_MSG(2, ("<= derive keys"));

	return 0;
}

#if defined(TTLS_SHA256_C)
void ssl_calc_verify_tls_sha256(ttls_context *tls, unsigned char hash[32])
{
	ttls_sha256_context sha256;

	ttls_sha256_init(&sha256);

	TTLS_DEBUG_MSG(2, ("=> calc verify sha256"));

	ttls_sha256_clone(&sha256, &tls->hs->fin_sha256);
	ttls_sha256_finish_ret(&sha256, hash);

	TTLS_DEBUG_BUF(3, "calculated verify result", hash, 32);
	TTLS_DEBUG_MSG(2, ("<= calc verify"));

	ttls_sha256_free(&sha256);

	return;
}
#endif /* TTLS_SHA256_C */

#if defined(TTLS_SHA512_C)
void ssl_calc_verify_tls_sha384(ttls_context *tls, unsigned char hash[48])
{
	ttls_sha512_context sha512;

	ttls_sha512_init(&sha512);

	TTLS_DEBUG_MSG(2, ("=> calc verify sha384"));

	ttls_sha512_clone(&sha512, &tls->hs->fin_sha512);
	ttls_sha512_finish_ret(&sha512, hash);

	TTLS_DEBUG_BUF(3, "calculated verify result", hash, 48);
	TTLS_DEBUG_MSG(2, ("<= calc verify"));

	ttls_sha512_free(&sha512);

	return;
}
#endif /* TTLS_SHA512_C */

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int ttls_psk_derive_premaster(ttls_context *tls, ttls_key_exchange_type_t key_ex)
{
	unsigned char *p = tls->hs->premaster;
	unsigned char *end = p + sizeof(tls->hs->premaster);
	const unsigned char *psk = tls->conf->psk;
	size_t psk_len = tls->conf->psk_len;

	/* If the psk callback was called, use its result */
	if (tls->hs->psk != NULL)
	{
		psk = tls->hs->psk;
		psk_len = tls->hs->psk_len;
	}

	/*
	 * PMS = struct {
	 *	 opaque other_secret<0..2^16-1>;
	 *	 opaque psk<0..2^16-1>;
	 * };
	 * with "other_secret" depending on the particular key exchange
	 */
#if defined(TTLS_KEY_EXCHANGE_PSK_ENABLED)
	if (key_ex == TTLS_KEY_EXCHANGE_PSK)
	{
		if (end - p < 2)
			return(TTLS_ERR_BAD_INPUT_DATA);

		*(p++) = (unsigned char)(psk_len >> 8);
		*(p++) = (unsigned char)(psk_len	 );

		if (end < p || (size_t)(end - p) < psk_len)
			return(TTLS_ERR_BAD_INPUT_DATA);

		memset(p, 0, psk_len);
		p += psk_len;
	}
	else
#endif /* TTLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
	if (key_ex == TTLS_KEY_EXCHANGE_RSA_PSK)
	{
		/*
		 * other_secret already set by the ClientKeyExchange message,
		 * and is 48 bytes long
		 */
		*p++ = 0;
		*p++ = 48;
		p += 48;
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
	if (key_ex == TTLS_KEY_EXCHANGE_DHE_PSK)
	{
		int r;
		size_t len;

		/* Write length only when we know the actual value */
		if ((r = ttls_dhm_calc_secret(&tls->hs->dhm_ctx,
						 p + 2, end - (p + 2), &len,
						 tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_dhm_calc_secret", r);
			return r;
		}
		*(p++) = (unsigned char)(len >> 8);
		*(p++) = (unsigned char)(len);
		p += len;

		TTLS_DEBUG_MPI(3, "DHM: K ", &tls->hs->dhm_ctx.K );
	}
	else
#endif /* TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
	if (key_ex == TTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		int r;
		size_t zlen;

		if ((r = ttls_ecdh_calc_secret(&tls->hs->ecdh_ctx, &zlen,
						 p + 2, end - (p + 2),
						 tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_ecdh_calc_secret", r);
			return r;
		}

		*(p++) = (unsigned char)(zlen >> 8);
		*(p++) = (unsigned char)(zlen	 );
		p += zlen;

		TTLS_DEBUG_MPI(3, "ECDH: z", &tls->hs->ecdh_ctx.z);
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	/* opaque psk<0..2^16-1>; */
	if (end - p < 2)
		return(TTLS_ERR_BAD_INPUT_DATA);

	*(p++) = (unsigned char)(psk_len >> 8);
	*(p++) = (unsigned char)(psk_len	 );

	if (end < p || (size_t)(end - p) < psk_len)
		return(TTLS_ERR_BAD_INPUT_DATA);

	memcpy(p, psk, psk_len);
	p += psk_len;

	tls->hs->pmslen = p - tls->hs->premaster;

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

void
ttls_read_version(TlsCtx *tls, const unsigned char ver[2])
{
#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM) {
		tls->major_ver = 255 - ver[0] + 2;
		tls->minor_ver = 255 - ver[1] + 1;
		if (tls->minor_ver == TTLS_MINOR_VERSION_1)
			/* DTLS 1.0 stored as TLS 1.1 internally */
			++tls->minor_ver;
	} else
#endif
	{
		tls->major_ver = ver[0];
		tls->minor_ver = ver[1];
	}
}

static void
ttls_make_aad(TlsCtx *tls, TlsIOCtx *io)
{
	memcpy_fast(io->aad_buf, io->ctr, 8);
	ttls_write_hdr(tls, io->msgtype, io->msglen, io->aad_buf + 8);
	T_DBG3_BUF("additional data used for AEAD",
		   io->aad_buf, TLS_AAD_SPACE_SIZE);
}

static unsigned char
ttls_xfrm_taglen(TlsXfrm *xfrm)
{
	return xfrm->ciphersuite_info->flags & TTLS_CIPHERSUITE_SHORT_TAG
		? 8 : 16;
}

int
ttls_encrypt_skb(TlsCtx *tls, struct sk_buff *skb)
{
	ttls_cipher_mode_t mode;
	int r, chunks;
	TtlsXfrm *xfrm = tls->io_out.xfrm;
	struct aaed_request *req;
	struct scatterlist *sg;

	BUG_ON(!tls->session_out || !xfrm);
	if (tls->out_msglen > TTLS_MAX_CONTENT_LEN) {
		T_DBG("%s record content %u too large, maximum %d\n",
		      __func__, (unsigned)tls->out_msglen,
		      TTLS_MAX_CONTENT_LEN);
		return TTLS_ERR_BAD_INPUT_DATA;
	}

	// TODO AK handshake:
	// crypto_aead_setauthsize(sw_ctx->aead_send, ctx->tag_size)
	// and adjust skb data/len if necessary... The same in ttls_descrypt_buf().

	mode = ttls_cipher_get_cipher_mode(&tls->transform_out->cipher_ctx_enc);
	WARN_ON_ONCE(mode != TTLS_MODE_GCM && mode != TTLS_MODE_CCM);

	ttls_make_aad(tls, &tls->io_out);

	/* Reminder if we ever add an AEAD mode with a different size. */
	WARN_ON_ONCE(xfrm->ivlen - xfrm->fixed_ivlen != 8);
	/* Generate IV. */
	*(long *)(xfrm->iv + xfrm->fixed_ivlen) = *(long *)tls->io_out.ctr;
	*(long *)xfrm->iv = *(long *)tls->io_out.ctr;
	T_DBG3_BUF("IV used", tls->io_out.iv, xfrm->ivlen - xfrm->fixed_ivlen);

	/* Allocate and prepare crypto request. */
	chunsk = skb_shinfo(skb)->nr_frags
		 + (skb_headlen(skb) > TLS_AAD_SPACE_SIZE ? 1 : 0);
	req = kmalloc(sizeof(*req) + sizeof(*sg) * chunks, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	sg = (struct scatterlist *)(req + 1);
	r = skb_to_sgvec(skb, sg, TLS_AAD_SPACE_SIZE,
			 skb->len - TLS_AAD_SPACE_SIZE);
	if (r <= 0) {
		kfree(req);
		return -ENOMEM;
	}
	sg_mark_end(*sg + r - 1);

	/* Encrypt and authenticate. */
	aead_request_set_tfm(req, xfrm->aead);
	aead_request_set_ad(req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(req, sg, sg, skb->len - TLS_MAX_OVERHEAD,
			       xfrm->iv);
	r = crypto_aead_encrypt(req);
	if (r)
		T_DBG2("encrypt failed: %d", r);
	kfree(req);

	return r;
}
EXPORT_SYMBOL(ttls_encrypt_skb);

static int
ttls_decrypt_buf(TlsCtx *tls)
{
	size_t dec_msglen, padlen = 0, correct = 1;
	int r;
	ttls_cipher_mode_t mode;
	TlsXfrm *xfrm = tls->io_in.xfrm;
	size_t explicit_iv_len = xfrm->ivlen - xfrm->fixed_ivlen;
	unsigned int sgn = 1;
	unsigned char taglen;
	struct aead_request *req;
	struct scatterlist *sg;

	BUG_ON(!tls->io_in.sess || !xfrm);
	if (unlikely(tls->in_msglen < xfrm->minlen)) {
		T_DBG("%s in_msglen (%d) < minlen (%d)\n", __func__,
		      tls->in_msglen, xfrm->minlen);
		return TTLS_ERR_INVALID_MAC;
	}

	taglen = ttls_xfrm_taglen(xfrm);
	mode = ttls_cipher_get_cipher_mode(&xfrm->io_in.cipher_ctx);
	WARN_ON_ONCE(mode != TTLS_MODE_GCM && mode != TTLS_MODE_CCM);

	if (unlikely(tls->io_in.msglen < explicit_iv_len + taglen)) {
		T_DBG("%s: msglen (%d) < explicit_iv_len (%d)"
		      " + taglen (%d)\n",
		      tls->io_in.msglen, explicit_iv_len, taglen);
		return TTLS_ERR_INVALID_MAC;
	}
	dec_msglen = tls->io_in.msglen - explicit_iv_len - taglen;
	tls->io_in.msglen = dec_msglen;

	memcpy_fast(xfrm->iv + xfrm->fixed_ivlen, tls->in_iv,
		    xfrm->ivlen - xfrm->fixed_ivlen);
	req = ttls_crypto_req_sglist(tls, dec_msglen + taglen, &sg, &sgn);
	if (!req)
		return TTLS_ERR_INTERNAL_ERROR;
	ttls_make_aad(tls, &tls->io_in);
	sg_set_buf(&sg[0], tls->io_in.aad_buf, TLS_AAD_SPACE_SIZE);

	T_DBG3_BUF("IV used", xfrm->iv, xfrm->ivlen);
	T_DBG3_SL("TAG used", sg, sgn, dec_msglen, taglen);

	/* Decrypt and authenticate. */
	aead_request_set_tfm(req, xfrm->aead);
	aead_request_set_ad(req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(req, sg, sg, dec_len, xfrm->iv);
	r = crypto_aead_decrypt(req);
	kfree(req);
	if (r) {
		T_DBG2("decrypt failed: %d", r);
		return r;
	}

	/*
	 * Three or more empty messages may be a DoS attack
	 * (excessive CPU consumption).
	 */
	if (unlikely(!tls->io_in.msglen && ++tls->nb_zero > 3)) {
		T_WARN("received four consecutive empty messages,"
		       " possible DoS attack\n");
		return T_DROP;
	} else {
		tls->nb_zero = 0;
	}

#if defined(TTLS_PROTO_DTLS)
	/* in_ctr read from peer, not maintained internally. */
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		return T_OK;
#endif
	return ttls_ep_check(&tls->io_in, "incomming");
}

int
ttls_sendmsg(TlsCtx *tls, const char *buf, size_t len)
{
	int r;
	size_t n;
	unsigned char *buf, i;
	TlsIOCtx *io = &tls->io_out;

	T_DBG("write record: type=%d len=%d\n", io->msgtype, io->msglen);

	n = ttls_hdr_len(tls) + io->msglen;
	if ((r = ttls_send_cb(tls, buf, len, !!io->xfrm)))
		return r;

	return ttls_ep_check(&tls->io_out, "outgoing");
}

int
ttls_write_record(TlsCtx *tls, char *buf, size_t len) // TODO AK
{
	int r, out_msg_type;
	TlsIOCtx *io = &tls->io_out;

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		tls->hs != NULL &&
		tls->hs->retransmit_state == TTLS_RETRANS_SENDING)
	{
		; /* Skip special handshake treatment when resending */
	}
	else
#endif
	if (io->msgtype == TTLS_MSG_HANDSHAKE) {
		size_t len = tls->io_out.msglen;

		out_msg_type = tls->out_msg[0];
		if (out_msg_type != TTLS_HS_HELLO_REQUEST &&
			tls->hs == NULL)
		{
			TTLS_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		tls->out_msg[1] = (unsigned char)((len - 4) >> 16);
		tls->out_msg[2] = (unsigned char)((len - 4) >> 8);
		tls->out_msg[3] = (unsigned char)((len - 4)	 );

		/*
		 * DTLS has additional fields in the Handshake layer,
		 * between the length field and the actual payload:
		 *	 uint16 message_seq;
		 *	 uint24 fragment_offset;
		 *	 uint24 fragment_length;
		 */
#if defined(TTLS_PROTO_DTLS)
		if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		{
			/* Make room for the additional DTLS fields */
			if (TTLS_MAX_CONTENT_LEN - tls->out_msglen < 8)
			{
				TTLS_DEBUG_MSG(1, ("DTLS handshake message too large: "
					 "size %u, maximum %u",
					 (unsigned) (tls->in_hslen - 4),
					 (unsigned) (TTLS_MAX_CONTENT_LEN - 12)));
				return(TTLS_ERR_BAD_INPUT_DATA);
			}

			memmove(tls->out_msg + 12, tls->out_msg + 4, len - 4);
			tls->out_msglen += 8;
			len += 8;

			/* Write message_seq and update it, except for HelloRequest */
			if (out_msg_type != TTLS_HS_HELLO_REQUEST)
			{
				tls->out_msg[4] = (tls->hs->out_msg_seq >> 8) & 0xFF;
				tls->out_msg[5] = (tls->hs->out_msg_seq	 ) & 0xFF;
				++(tls->hs->out_msg_seq);
			}
			else
			{
				tls->out_msg[4] = 0;
				tls->out_msg[5] = 0;
			}

			/* We don't fragment, so frag_offset = 0 and frag_len = len */
			memset(tls->out_msg + 6, 0x00, 3);
			memcpy(tls->out_msg + 9, tls->out_msg + 1, 3);
		}
#endif /* TTLS_PROTO_DTLS */

		if (out_msg_type != TTLS_HS_HELLO_REQUEST)
			tls->hs->update_checksum(tls, tls->out_msg, len);
	}

	/* Save handshake and CCS messages for resending */
#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		tls->hs != NULL &&
		tls->hs->retransmit_state != TTLS_RETRANS_SENDING &&
		(tls->out_msgtype == TTLS_MSG_CHANGE_CIPHER_SPEC ||
		 tls->out_msgtype == TTLS_MSG_HANDSHAKE))
	{
		if ((r = ssl_flight_append(tls)) != 0)
		{
			TTLS_DEBUG_RET(1, "ssl_flight_append", r);
			return r;
		}
	}
#endif

	io->msglen += io->xfrm->ivlen + ttls_xfrm_taglen(io->xfrm);
	ttls_write_hdr(tls, io->msgtype, io->msglen, io->hdr);

	T_DBG3("output record: type=%d ver=%d:%d len=%d",
		io->hdr[0], io->hdr[1], io->hdr[2], io->msglen);

	return ttls_sendmsg(tls, buf, len);
}

int ttls_prepare_handshake_record(ttls_context *tls)
{
	if (tls->in_msglen < ttls_hs_hdr_len(tls))
	{
		TTLS_DEBUG_MSG(1, ("handshake message too short: %d",
							tls->in_msglen));
		return(TTLS_ERR_INVALID_RECORD);
	}

	tls->in_hslen = ttls_hs_hdr_len(tls) + (
					(tls->in_msg[1] << 16) |
					(tls->in_msg[2] << 8 ) |
					 tls->in_msg[3]);

	TTLS_DEBUG_MSG(3, ("handshake message: msglen ="
			" %d, type = %d, hslen = %d",
			tls->in_msglen, tls->in_msg[0], tls->in_hslen));

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
	{
		int r;
		unsigned int recv_msg_seq = (tls->in_msg[4] << 8) | tls->in_msg[5];

		/* tls->hs is NULL when receiving ClientHello for renego */
		if (tls->hs != NULL &&
			recv_msg_seq != tls->hs->in_msg_seq)
		{
			/* Retransmit only on last message from previous flight, to avoid
			 * too many retransmissions.
			 * Besides, No sane server ever retransmits HelloVerifyRequest */
			if (recv_msg_seq == tls->hs->in_flight_start_seq - 1 &&
				tls->in_msg[0] != TTLS_HS_HELLO_VERIFY_REQUEST)
			{
				TTLS_DEBUG_MSG(2, ("received message from last flight, "
						"message_seq = %d, start_of_flight = %d",
						recv_msg_seq,
						tls->hs->in_flight_start_seq));

				if ((r = ttls_resend(tls)) != 0)
				{
					TTLS_DEBUG_RET(1, "ttls_resend", r);
					return r;
				}
			}
			else
			{
				TTLS_DEBUG_MSG(2, ("dropping out-of-sequence message: "
						"message_seq = %d, expected = %d",
						recv_msg_seq,
						tls->hs->in_msg_seq));
			}

			return(TTLS_ERR_WANT_READ);
		}
		/* Wait until message completion to increment in_msg_seq */

		/* Reassemble if current message is fragmented or reassembly is
		 * already in progress */
		if (tls->in_msglen < tls->in_hslen ||
			memcmp(tls->in_msg + 6, "\0\0\0",		3) != 0 ||
			memcmp(tls->in_msg + 9, tls->in_msg + 1, 3) != 0 ||
			(tls->hs != NULL && tls->hs->hs_msg != NULL))
		{
			TTLS_DEBUG_MSG(2, ("found fragmented DTLS handshake message"));

			if ((r = ssl_reassemble_dtls_handshake(tls)) != 0)
			{
				TTLS_DEBUG_RET(1, "ssl_reassemble_dtls_handshake", r);
				return r;
			}
		}
	}
	else
#endif /* TTLS_PROTO_DTLS */
	/* With TLS we don't handle fragmentation (for now) */
	if (tls->in_msglen < tls->in_hslen)
	{
		TTLS_DEBUG_MSG(1, ("TLS handshake fragmentation not supported"));
		return(TTLS_ERR_FEATURE_UNAVAILABLE);
	}

	return 0;
}

void ttls_update_handshake_status(ttls_context *tls)
{

	if (tls->state != TTLS_HANDSHAKE_OVER &&
		tls->hs != NULL)
	{
		tls->hs->update_checksum(tls, tls->in_msg, tls->in_hslen);
	}

	/* Handshake message is complete, increment counter */
#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		tls->hs != NULL)
	{
		tls->hs->in_msg_seq++;
	}
#endif
}

static int
ttls_hdr_check(TlsCtx *tls)
{
	/* Check record type */
	if (unlikely(tls->in_msgtype < TTLS_MSG_CHANGE_CIPHER_SPEC
		     || tls->in_msgtype > TTLS_MSG_APPLICATION_DATA))
	{
		T_DBG("unknown record type %d\n", tls->in_msgtype);
#if defined(TTLS_PROTO_DTLS)
		/*
		 * Silently ignore invalid DTLS records as recommended by
		 * RFC 6347 Section 4.1.2.7.
		 */
		if (tls->conf->transport != TTLS_TRANSPORT_DATAGRAM)
#endif
			ttls_send_alert_msg(tls,
				TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);

		return T_DROP;
	}
	/* Check version */
	if (unlikely(major_ver != tls->major_ver)) {
		T_DBG("major version mismatch %d\n", major_ver);
		return T_DROP;
	}
	if (unlikely(minor_ver > tls->conf->max_minor_ver)) {
		T_DBG("minor version mismatch %d\n", minor_ver);
		return T_DROP;
	}
	/* Check length against the size of our buffer */
	if (unlikely(tls->in_msglen > TTLS_PAYLOAD_LEN)) {
		T_DBG("bad message length %u\n", tls->in_msglen);
		return T_DROP;
	}
	/* Check length against bounds of the current transform and version */
	if (!tls->transform_in) {
		if (tls->in_msglen < 1
		    || tls->in_msglen > TTLS_MAX_CONTENT_LEN)
		{
			T_DBG(("bad message length %u\n", tls->in_msglen);
			return T_DROP;
		}
	} else {
		/*
		 * TLS encrypted messages can have up to 256 bytes of padding.
		 */
		if (tls->in_msglen < tls->transform_in->minlen
		    || tls->in_msglen > tls->transform_in->minlen
		    			+ TTLS_MAX_CONTENT_LEN + 256)
		{
			T_DBG(("bad message length %u\n", tls->in_msglen);
			return T_DROP;
		}
	}

	/*
	 * DTLS-related tests done last, because most of them may result in
	 * silently dropping the record (but not the whole datagram), and we
	 * only want to consider that after ensuring that the "basic" fields
	 * (type, version, length) are sane.
	 */
#if defined(TTLS_PROTO_DTLS)
#error "TODO: read the 8 bytes to in_ctr above"
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM) {
		unsigned int rec_epoch = (tls->in_ctr[0] << 8) | tls->in_ctr[1];

		/* Drop unexpected ChangeCipherSpec messages */
		if (tls->in_msgtype == TTLS_MSG_CHANGE_CIPHER_SPEC &&
			tls->state != TTLS_CLIENT_CHANGE_CIPHER_SPEC &&
			tls->state != TTLS_SERVER_CHANGE_CIPHER_SPEC)
		{
			T_DBG("dropping unexpected ChangeCipherSpec");
			return TTLS_ERR_UNEXPECTED_RECORD;
		}

		/* Drop unexpected ApplicationData records,
		 * except at the beginning of renegotiations */
		if (tls->in_msgtype == TTLS_MSG_APPLICATION_DATA &&
			tls->state != TTLS_HANDSHAKE_OVER)
		{
			T_DBG("dropping unexpected ApplicationData");
			return TTLS_ERR_UNEXPECTED_RECORD;
		}

		/* Check epoch (and sequence number) with DTLS */
		if (rec_epoch != tls->in_epoch) {
			T_DBG("record from another epoch: expected %d,"
			      " received %d", tls->in_epoch, rec_epoch);
#if defined(TTLS_DTLS_CLIENT_PORT_REUSE)
			/*
			 * Check for an epoch 0 ClientHello. We can't use in_msg
			 * here to access the first byte of record content
			 * (handshake type), as we have an active transform
			 * (possibly iv_len != 0), so use the fact that the
			 * record header len is 13 instead.
			 */
			if (tls->conf->endpoint == TTLS_IS_SERVER &&
				tls->state == TTLS_HANDSHAKE_OVER &&
				rec_epoch == 0 &&
				tls->in_msgtype == TTLS_MSG_HANDSHAKE &&
				tls->in_left > 13 &&
				tls->in_buf[13] == TTLS_HS_CLIENT_HELLO)
			{
				T_DBG("possible client reconnect from the"
				      " same port");
				return ssl_handle_possible_reconnect(tls);
			} else
#endif /* TTLS_DTLS_CLIENT_PORT_REUSE */
				return TTLS_ERR_UNEXPECTED_RECORD;
		}
#if defined(TTLS_DTLS_ANTI_REPLAY)
		/* Replay detection only works for the current epoch */
		if (rec_epoch == tls->in_epoch &&
			ttls_dtls_replay_check(tls) != 0)
		{
			T_DBG("replayed record");
			return TTLS_ERR_UNEXPECTED_RECORD;
		}
#endif
	}
#endif /* TTLS_PROTO_DTLS */

	return T_OK;
}

/**
 * Read TLS message header:
 *
 *	ContentType type;
 *	ProtocolVersion version;
 *	uint16 epoch;		(TLS only)
 *	uint48 sequence_number;	(DTLS only)
 *	uint16 length;
 *	[uint128 IV | alert];
 *
 * While IV and alert message aren't a part of TLS message header, we read it
 * here for application data messages to simplify further decryption logic.
 * TLS header and IV are quite small, so it's more efficiently just to always
 * copy it instead of manipulating with fragmented data.
 *
 * Return 0 if header looks sane (and, for DTLS, the record is expected)
 * TTLS_ERR_INVALID_RECORD if the header looks bad,
 * TTLS_ERR_UNEXPECTED_RECORD (DTLS only) if sane but unexpected,
 * T_POSTPONE if we need more data for the header.
 *
 * With DTLS, ttls_read_record() will:
 * 1. proceed with the record if this function returns 0
 * 2. drop only the current record if this function returns UNEXPECTED_RECORD
 * 3. return CLIENT_RECONNECT if this function return that value
 * 4. drop the whole datagram if this function returns anything else.
 * Point 2 is needed when the peer is resending, and we have already received
 * the first record from a datagram but are still waiting for the others.
 */
static int
ttls_parse_record_hdr(TlsCtx *tls, unsigned char *buf, size_t len,
		      unsigned int *read)
{
	int r, hlen, iva_len, n = 0;
	TlsIOCtx *io = &tls->io_in;

	if (tls->st_flags & TTLS_F_ST_HDRIV)
		return T_OK; /* The header is parsed in previous chunk. */

	/* Read TLS message header, probably fragmented. */
	hlen = ttls_hdr_len(tls);
	if (unlikely(io->hdr_iv_cpsz + len < hlen)) {
		memcpy(io->hdr + io->hdr_iv_cpsz, buf, len);
		*read += len;
		io->hdr_iv_cpsz += len;
		return T_POSTPONE;
	}
	if (io->hdr_iv_cpsz < hlen) {
		n = hlen - io->hdr_iv_cpsz;
		memcpy(io->hdr + io->hdr_ib_cpsz, buf, n);
		*read += n;
		io->hdr_iv_cpsz += n;
	}

	io->msgtype = io->hdr[0];
	ttls_read_version(tls, io->hdr + 1);
	io->msglen = ((unsigned short)io->hdr[3] << 8) | io->hdr[4];
	T_DBG3("input rec: type=%d ver=%d:%d len=%d\n",
	       io->msgtype, tls->major_ver, tls->minor_ver, io->msglen);

	if ((r = ttls_hdr_check(tls)))
		return r;
	switch (io->msgtype) {
	case TTLS_MSG_APPLICATION_DATA:
		iva_len = TTLS_IV_LEN;
		break;
	case TTLS_MSG_ALERT:
		iva_len = 2; /* level & description */
		break;
	default:
		tls->st_flags |= TTLS_F_ST_HDRIV;
		return T_OK;
	}

	/* Read IV (probably fragmented) for application data message. */
	len -= n;
	if (unlikely(io->hdr_iv_cpsz + len < hlen + iva_len)) {
		memcpy(io->iv + io->hdr_iv_cpsz - hlen, buf + n, len);
		*read += len;
		io->hdr_iv_cpsz += len;
		return T_POSTPONE;
	}
	iva_len -= io->hdr_iv_cpsz - hlen;
	memcpy(io->iv + io->hdr_iv_cpsz - hlen, buf + n, iva_len);
	io->hdr_iv_cpsz += iva_len;
	*read += iva_len;
	tls->st_flags |= TTLS_F_ST_HDRIV;

	return T_OK;
}

/**
 * If applicable, decrypt (and decompress) record content.
 */
static int
ttls_prepare_record_content(TlsCtx *tls)
{
	int r;

	T_DBG2("input record from network: %pK len=%d\n",
		tls->io_in.hdr, ttls_hdr_len(tls) + tls->io_in.msglen);

	if (tls->io_in.xfrm) {
		if ((r = ttls_decrypt_buf(tls)))
			return r;
		if (tls->io_in.msglen > TTLS_MAX_CONTENT_LEN) {
			T_DBG("bad message length %u\n", tls->io_in.msglen);
			return T_DROP;
		}
	}

#if defined(TTLS_DTLS_ANTI_REPLAY)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_dtls_replay_update(tls);
#endif

	return T_OK;
}

void
ttls_handshake_free(TlsHandshake *hs)
{
	if (!hs)
		return;

#if defined(TTLS_SHA256_C)
	ttls_sha256_free(&hs->fin_sha256);
#endif
#if defined(TTLS_SHA512_C)
	ttls_sha512_free(&hs->fin_sha512);
#endif
#if defined(TTLS_DHM_C)
	ttls_dhm_free(&hs->dhm_ctx);
#endif
#if defined(TTLS_ECDH_C)
	ttls_ecdh_free(&hs->ecdh_ctx);
#endif
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ttls_ecjpake_free(&hs->ecjpake_ctx);
#if defined(TTLS_CLI_C)
	ttls_free(hs->ecjpake_cache);
	hs->ecjpake_cache = NULL;
	hs->ecjpake_cache_len = 0;
#endif
#endif
#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	/* explicit void pointer cast for buggy MS compiler */
	kfree(hs->curves);
#endif
#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	if (hs->psk) {
		bzero_fast(hs->psk, hs->psk_len);
		kfree(hs->psk);
	}
#endif

	/*
	 * Free only the linked list wrapper, not the keys themselves
	 * since the belong to the SNI callback.
	 */
	if (hs->sni_key_cert) {
		ttls_key_cert *cur = hs->sni_key_cert, *next;
		while (cur) {
			next = cur->next;
			kfree(cur);
			cur = next;
		}
	}

#if defined(TTLS_PROTO_DTLS)
	kfree(hs->verify_cookie);
	kfree(hs->hs_msg);
	ssl_flight_free(hs->flight);
#endif
	bzero_fast(hs, sizeof(TlsHandshake));
	kfree(hs);
}

static void
ttls_handshake_wrapup_free_hs_transform(TlsCtx *tls)
{
	/* Free our hs params. */
	ttls_handshake_free(tls->hs);
	tls->hs = NULL;

	/* Free the previous transform and swith in the current one. */
	if (tls->transform) {
		ttls_transform_free(tls->transform);
		ttls_free(tls->transform);
	}
	tls->transform = tls->transform_negotiate;
	tls->transform_negotiate = NULL;

	TTLS_DEBUG_MSG(3, ("<= hs wrapup: final free"));
}

void
ttls_handshake_wrapup(TlsCtx *tls)
{
	int resume = tls->hs->resume;

	/* Free the previous session and switch in the current one. */
	if (tls->session) {
		/* RFC 7366 3.1: keep the EtM state. */
		tls->session_negotiate->encrypt_then_mac =
				 tls->session->encrypt_then_mac;

		ttls_session_free(tls->session);
		// TODO AK: probably we can remove the free() call and just
		// aggregate session into TfwCtx, probably we also don't need
		// session_negotiate (renegotiation only?)
		kfree(tls->session);
	}
	tls->session = tls->session_negotiate;
	tls->session_negotiate = NULL;

	/* Add cache entry. */
	if (tls->conf->f_set_cache && tls->session->id_len && !resume
	    && tls->conf->f_set_cache(tls->conf->p_cache, tls->session))
		T_DBG("cache did not store session\n");

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		tls->hs->flight != NULL)
	{
		/* Cancel handshake timer */
		ssl_set_timer(tls, 0);

		/* Keep last flight around in case we need to resend it:
		 * we need the handshake and transform structures for that */
		TTLS_DEBUG_MSG(3, ("skip freeing handshake and transform"));
	}
	else
#endif
		ttls_handshake_wrapup_free_hs_transform(tls);

	tls->state = TTLS_HANDSHAKE_OVER;
}

int
ttls_read_record_layer(TlsCtx *tls, unsigned char *buf, size_t len,
		       unsigned int *read)
{
	int n, r;

	/*
	 * Step A
	 *
	 * Consume last content-layer message and potentially
	 * update in_msglen which keeps track of the contents'
	 * consumption state.
	 *
	 * (1) Handshake messages:
	 *	 Remove last handshake message, move content
	 *	 and adapt in_msglen.
	 *
	 * (2) Alert messages:
	 *	 Consume whole record content, in_msglen = 0.
	 *
	 *	 NOTE: This needs to be fixed, since like for
	 *	 handshake messages it is allowed to have
	 *	 multiple alerts witin a single record.
	 *	 Internal reference IOTSSL-1321.
	 *
	 * (3) Change cipher spec:
	 *	 Consume whole record content, in_msglen = 0.
	 *
	 * (4) Application data:
	 *	 Don't do anything - the record layer provides
	 *	 the application data as a stream transport
	 *	 and consumes through ttls_read only.
	 */

	/* Case (1): Handshake messages */
	if (tls->in_hslen) {
		/* Hard assertion to be sure that no application data
		 * is in flight, as corrupting tls->in_msglen during
		 * tls->in_offt != NULL is fatal. */
		if (tls->in_offt != NULL)
		{
			TTLS_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		/*
		 * Get next Handshake message in the current record
		 */

		/* Notes:
		 * (1) in_hslen is *NOT* necessarily the size of the
		 *	 current handshake content: If DTLS handshake
		 *	 fragmentation is used, that's the fragment
		 *	 size instead. Using the total handshake message
		 *	 size here is FAULTY and should be changed at
		 *	 some point. Internal reference IOTSSL-1414.
		 * (2) While it doesn't seem to cause problems, one
		 *	 has to be very careful not to assume that in_hslen
		 *	 is always <= in_msglen in a sensible communication.
		 *	 Again, it's wrong for DTLS handshake fragmentation.
		 *	 The following check is therefore mandatory, and
		 *	 should not be treated as a silently corrected assertion.
		 *	 Additionally, tls->in_hslen might be arbitrarily out of
		 *	 bounds after handling a DTLS message with an unexpected
		 *	 sequence number, see ttls_prepare_handshake_record.
		 */
		if (tls->in_hslen < tls->in_msglen)
		{
			// TODO AK: eat handshake message
			tls->in_msglen -= tls->in_hslen;
			memmove(tls->in_msg, tls->in_msg + tls->in_hslen,
					 tls->in_msglen);

			TTLS_DEBUG_BUF(4, "remaining content in record",
					 tls->in_msg, tls->in_msglen);
		}
		else
		{
			tls->in_msglen = 0;
		}

		tls->in_hslen = 0;
	}
	/* Case (4): Application data */
	else if (tls->in_offt != NULL)
	{
		return 0;
	}
	/* Everything else (CCS & Alerts) */
	else
	{
		tls->in_msglen = 0;
	}

	/*
	 * Step B
	 *
	 * Fetch and decode new record if current one is fully consumed.
	 *
	 * TODO AK control message length - reread message header if we're done
	 * with current message.
	 */
	if (tls->in_msglen > 0)
	{
		/* There's something left to be processed in the current record. */
		return 0;
	}

#if defined(TTLS_PROTO_DTLS)
read_record_header:
#endif
	r = ttls_parse_record_hdr(tls, buf, len, read);
	if (r) {
#if defined(TTLS_PROTO_DTLS)
		if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM
		    && r != TTLS_ERR_CLIENT_RECONNECT)
		{
			if (r == TTLS_ERR_UNEXPECTED_RECORD) {
				/*
				 * Skip unexpected record
				 * (but not whole datagram).
				 */
				tls->next_record_offset = tls->in_msglen
							+ ttls_hdr_len(tls);
				T_DBG3("discarding unexpected record (header)");
			} else {
				/*
				 * Skip invalid record and the rest
				 * of the datagram.
				 */
				tls->next_record_offset = 0;
				tls->in_left = 0;
				T_DBG3("discarding invalid record (header)");
			}
			/* Get next record */
			goto read_record_header;
		}
#endif
		return r;
	}
	n = tls->in_msglen - tls->in_rlen;
	if (len - *read < n) {
		tls->in_rlen += len - *read;
		*read = len;
		return T_POSTPONE;
	}
	*read += n;

#if defined(TTLS_PROTO_DTLS)
	/* Done reading this record, get ready for the next one */
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		tls->next_record_offset = tls->in_msglen + ttls_hdr_len(tls);
#endif

	/*
	 * Current record either fully processed or to be discarded.
	 * Read and optionally decrypt the message contents.
	 */
	if ((r = ttls_prepare_record_content(tls))) {
#if defined(TTLS_PROTO_DTLS)
		if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM) {
			/* Silently discard invalid records */
			if (r != TTLS_ERR_INVALID_RECORD
			    && r != TTLS_ERR_INVALID_MAC)
				return r;
			/*
			 * Except when waiting for Finished as a bad mac
			 * here probably means something went wrong in
			 * the handshake (eg wrong psk used, mitm
			 * downgrade attempt, etc.)
			 */
			if (tls->state == TTLS_CLIENT_FINISHED ||
				tls->state == TTLS_SERVER_FINISHED)
			{
				if (r == TTLS_ERR_INVALID_MAC)
					ttls_send_alert_msg(tls,
						TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_BAD_RECORD_MAC);
				return r;
			}
#if defined(TTLS_DTLS_BADMAC_LIMIT)
			if (tls->conf->badmac_limit != 0 &&
				++tls->badmac_seen >= tls->conf->badmac_limit)
			{
				T_DBG("too many records with bad MAC");
				return(TTLS_ERR_INVALID_MAC);
			}
#endif

			/* As above, invalid records cause
			 * dismissal of the whole datagram. */

			tls->next_record_offset = 0;

			T_DBG("discarding invalid record (mac)");
			goto read_record_header;
		} else
#endif
		{
			/* Error out (and send alert) on invalid records */
			if (r == TTLS_ERR_INVALID_MAC)
				ttls_send_alert_msg(tls,
						TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_BAD_RECORD_MAC);
			return r;
		}
	}

#if defined(TTLS_PROTO_DTLS)
	/*
	 * When we sent the last flight of the handshake, we MUST respond to a
	 * retransmit of the peer's previous flight with a retransmit. (In
	 * practice, only the Finished message will make it, other messages
	 * including CCS use the old transform so they're dropped as invalid.)
	 *
	 * If the record we received is not a handshake message, however, it
	 * means the peer received our last flight so we can clean up
	 * handshake info.
	 *
	 * This check needs to be done before prepare_handshake() due to an edge
	 * case: if the client immediately requests renegotiation, this
	 * finishes the current handshake first, avoiding the new ClientHello
	 * being mistaken for an ancient message in the current handshake.
	 */
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		tls->hs != NULL &&
		tls->state == TTLS_HANDSHAKE_OVER)
	{
		if (tls->in_msgtype == TTLS_MSG_HANDSHAKE &&
			tls->in_msg[0] == TTLS_HS_FINISHED)
		{
			T_DBG("received retransmit of last flight");
			if ((r = ttls_resend(tls)) != 0)
				return r;
			return(TTLS_ERR_WANT_READ);
		} else {
			ttls_handshake_wrapup_free_hs_transform(tls);
		}
	}
#endif

	return T_OK;
}

/**
 * Handle particular types of records.
 */
int
ttls_handle_message_type(TlsCtx *tls)
{
	int r;
	TlsIOCtx *io = &tls->io_in;

	if (io->msgtype == TTLS_MSG_HANDSHAKE)
		if ((r = ttls_prepare_handshake_record(tls)))
			return r;

	/* Process TLS alerts. */
	if (io->msgtype != TTLS_MSG_ALERT)
		return;
	T_DBG("got an alert message, type: %d:%d\n",
	      io->alert[0], io->alert[1]);

	/* Ignore non-fatal alerts, except close_notify and no_renegotiation. */
	if (io->alert[0] == TTLS_ALERT_LEVEL_FATAL) {
		T_DBG("is a fatal alert message (msg %d)", io->alert[1]);
		return TTLS_ERR_FATAL_ALERT_MESSAGE;
	}
	if (io->alert[0] == TTLS_ALERT_LEVEL_WARNING
	    && io->alert[1] == TTLS_ALERT_MSG_CLOSE_NOTIFY)
	{
		T_DBG("is a close notify message");
		return TTLS_ERR_PEER_CLOSE_NOTIFY;
	}
	/* Silently ignore: fetch new message */
	return TTLS_ERR_NON_FATAL;
}

/*
 * Read a record.
 *
 * Silently ignore non-fatal alert (and for DTLS, invalid records as well,
 * RFC 6347 4.1.2.7) and continue reading until a valid record is found.
 */
int
ttls_read_record(TlsCtx *tls, unsigned char *buf, size_t len,
		 unsigned int *read)
{
	int r = 0;

	do {
		r = ttls_read_record_layer(tls, buf + *read, len - *read, read);
		if (r)
			return r;
		r = ttls_handle_message_type(tls);
	} while (TTLS_ERR_NON_FATAL == r);
	if (r)
		return r;

	if (tls->in_msgtype == TTLS_MSG_HANDSHAKE)
		ttls_update_handshake_status(tls);

	return r;
}

/**
 * Send an alert message.
 *
 * @lvl	- the alert level of the message (TTLS_ALERT_LEVEL_WARNING or
 * 	  TTLS_ALERT_LEVEL_FATAL)
 * @msg	- the alert message (SSL_ALERT_MSG_*)
 *
 * If this function returns something other than 0 or
 * TTLS_ERR_WANT_READ/WRITE, then the ssl context becomes unusable, and you
 * should either free it or call ttls_session_reset() on it before re-using
 * it for a new connection; the current connection must be closed.
 */
int
ttls_send_alert_msg(TlsCtx *tls, unsigned char lvl, unsigned char msg)
{
	TlsIOCtx *io = &tls->io_out;

	T_DBG("send alert level=%u message=%u\n", lvl, msg);

	io->msgtype = TTLS_MSG_ALERT;
	io->msglen = 2;
	io->alert[0] = lvl;
	io->alert[1] = msg;

	return ttls_write_record(tls);
}

int ttls_write_certificate(ttls_context *tls)
{
	int r = TTLS_ERR_FEATURE_UNAVAILABLE;
	size_t i, n;
	const ttls_x509_crt *crt;
	const ttls_ciphersuite_t *ciphersuite_info = tls->transform_negotiate->ciphersuite_info;

	TTLS_DEBUG_MSG(2, ("=> write certificate"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_DEBUG_MSG(2, ("<= skip write certificate"));
		tls->state++;
		return 0;
	}

#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT)
	{
		if (tls->client_auth == 0)
		{
			TTLS_DEBUG_MSG(2, ("<= skip write certificate"));
			tls->state++;
			return 0;
		}

	}
#endif /* TTLS_CLI_C */
	if (tls->conf->endpoint == TTLS_IS_SERVER)
	{
		if (ttls_own_cert(tls) == NULL)
		{
			TTLS_DEBUG_MSG(1, ("got no certificate to send"));
			return(TTLS_ERR_CERTIFICATE_REQUIRED);
		}
	}

	TTLS_DEBUG_CRT(3, "own certificate", ttls_own_cert(tls));

	/*
	 *	 0 . 0	handshake type
	 *	 1 . 3	handshake length
	 *	 4 . 6	length of all certs
	 *	 7 . 9	length of cert. 1
	 *	10 . n-1 peer certificate
	 *	 n . n+2 length of cert. 2
	 *	n+3 . ... upper level cert, etc.
	 */
	i = 7;
	crt = ttls_own_cert(tls);

	while (crt != NULL)
	{
		n = crt->raw.len;
		if (n > TTLS_MAX_CONTENT_LEN - 3 - i)
		{
			TTLS_DEBUG_MSG(1, ("certificate too large, %d > %d",
						 i + 3 + n, TTLS_MAX_CONTENT_LEN));
			return(TTLS_ERR_CERTIFICATE_TOO_LARGE);
		}

		tls->out_msg[i	] = (unsigned char)(n >> 16);
		tls->out_msg[i + 1] = (unsigned char)(n >> 8);
		tls->out_msg[i + 2] = (unsigned char)(n	 );

		i += 3; memcpy(tls->out_msg + i, crt->raw.p, n);
		i += n; crt = crt->next;
	}

	tls->out_msg[4] = (unsigned char)((i - 7) >> 16);
	tls->out_msg[5] = (unsigned char)((i - 7) >> 8);
	tls->out_msg[6] = (unsigned char)((i - 7)	 );

	tls->out_msglen = i;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0] = TTLS_HS_CERTIFICATE;

	tls->state++;

	if ((r = ttls_write_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", r);
		return r;
	}

	TTLS_DEBUG_MSG(2, ("<= write certificate"));

	return r;
}

int ttls_parse_certificate(ttls_context *tls)
{
	int r = TTLS_ERR_FEATURE_UNAVAILABLE;
	size_t i, n;
	const ttls_ciphersuite_t *ciphersuite_info = tls->transform_negotiate->ciphersuite_info;
	int authmode = tls->conf->authmode;
	uint8_t alert;

	TTLS_DEBUG_MSG(2, ("=> parse certificate"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_DEBUG_MSG(2, ("<= skip parse certificate"));
		tls->state++;
		return 0;
	}

	if (tls->conf->endpoint == TTLS_IS_SERVER &&
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK)
	{
		TTLS_DEBUG_MSG(2, ("<= skip parse certificate"));
		tls->state++;
		return 0;
	}

	if (tls->hs->sni_authmode != TTLS_VERIFY_UNSET)
		authmode = tls->hs->sni_authmode;

	if (tls->conf->endpoint == TTLS_IS_SERVER &&
		authmode == TTLS_VERIFY_NONE)
	{
		tls->session_negotiate->verify_result = TTLS_X509_BADCERT_SKIP_VERIFY;
		TTLS_DEBUG_MSG(2, ("<= skip parse certificate"));
		tls->state++;
		return 0;
	}

	if ((r = ttls_read_record(tls)) != 0)
	{
		/* ttls_read_record may have sent an alert already. We
		 let it decide whether to alert. */
		TTLS_DEBUG_RET(1, "ttls_read_record", r);
		return r;
	}

	tls->state++;

	if (tls->conf->endpoint == TTLS_IS_SERVER &&
		tls->minor_ver != TTLS_MINOR_VERSION_0)
	{
		if (tls->in_hslen == 3 + ttls_hs_hdr_len(tls) &&
			tls->in_msgtype == TTLS_MSG_HANDSHAKE	&&
			tls->in_msg[0] == TTLS_HS_CERTIFICATE &&
			memcmp(tls->in_msg + ttls_hs_hdr_len(tls), "\0\0\0", 3) == 0)
		{
			TTLS_DEBUG_MSG(1, ("TLSv1 client has no certificate"));

			/* The client was asked for a certificate but didn't send
			 one. The client should know what's going on, so we
			 don't send an alert. */
			tls->session_negotiate->verify_result = TTLS_X509_BADCERT_MISSING;
			if (authmode == TTLS_VERIFY_OPTIONAL)
				return 0;
			else
				return(TTLS_ERR_NO_CLIENT_CERTIFICATE);
		}
	}

	if (tls->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad certificate message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (tls->in_msg[0] != TTLS_HS_CERTIFICATE ||
		tls->in_hslen < ttls_hs_hdr_len(tls) + 3 + 3)
	{
		TTLS_DEBUG_MSG(1, ("bad certificate message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CERTIFICATE);
	}

	i = ttls_hs_hdr_len(tls);

	/*
	 * Same message structure as in ttls_write_certificate()
	 */
	n = (tls->in_msg[i+1] << 8) | tls->in_msg[i+2];

	if (tls->in_msg[i] != 0 ||
		tls->in_hslen != n + 3 + ttls_hs_hdr_len(tls))
	{
		TTLS_DEBUG_MSG(1, ("bad certificate message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CERTIFICATE);
	}

	/* In case we tried to reuse a session but it failed */
	if (tls->session_negotiate->peer_cert != NULL)
	{
		ttls_x509_crt_free(tls->session_negotiate->peer_cert);
		ttls_free(tls->session_negotiate->peer_cert);
	}

	if ((tls->session_negotiate->peer_cert = ttls_calloc(1,
				sizeof(ttls_x509_crt))) == NULL)
	{
		TTLS_DEBUG_MSG(1, ("alloc(%d bytes) failed",
					 sizeof(ttls_x509_crt)));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_INTERNAL_ERROR);
		return(TTLS_ERR_ALLOC_FAILED);
	}

	ttls_x509_crt_init(tls->session_negotiate->peer_cert);

	i += 3;

	while (i < tls->in_hslen)
	{
		if (tls->in_msg[i] != 0)
		{
			TTLS_DEBUG_MSG(1, ("bad certificate message"));
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_CERTIFICATE);
		}

		n = ((unsigned int) tls->in_msg[i + 1] << 8)
			| (unsigned int) tls->in_msg[i + 2];
		i += 3;

		if (n < 128 || i + n > tls->in_hslen)
		{
			TTLS_DEBUG_MSG(1, ("bad certificate message"));
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_CERTIFICATE);
		}

		r = ttls_x509_crt_parse_der(tls->session_negotiate->peer_cert,
					 tls->in_msg + i, n);
		switch(r)
		{
		case 0: /*ok*/
		case TTLS_ERR_X509_UNKNOWN_SIG_ALG + TTLS_ERR_OID_NOT_FOUND:
			/* Ignore certificate with an unknown algorithm: maybe a
			 prior certificate was already trusted. */
			break;

		case TTLS_ERR_X509_ALLOC_FAILED:
			alert = TTLS_ALERT_MSG_INTERNAL_ERROR;
			goto crt_parse_der_failed;

		case TTLS_ERR_X509_UNKNOWN_VERSION:
			alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			goto crt_parse_der_failed;

		default:
			alert = TTLS_ALERT_MSG_BAD_CERT;
		crt_parse_der_failed:
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL, alert);
			TTLS_DEBUG_RET(1, " ttls_x509_crt_parse_der", r);
			return r;
		}

		i += n;
	}

	TTLS_DEBUG_CRT(3, "peer certificate", tls->session_negotiate->peer_cert);

	if (authmode != TTLS_VERIFY_NONE)
	{
		ttls_x509_crt *ca_chain;
		ttls_x509_crl *ca_crl;

		if (tls->hs->sni_ca_chain != NULL)
		{
			ca_chain = tls->hs->sni_ca_chain;
			ca_crl = tls->hs->sni_ca_crl;
		}
		else
		{
			ca_chain = tls->conf->ca_chain;
			ca_crl = tls->conf->ca_crl;
		}

		/*
		 * Main check: verify certificate
		 */
		r = ttls_x509_crt_verify_with_profile(
				tls->session_negotiate->peer_cert,
				ca_chain, ca_crl,
				tls->conf->cert_profile,
				tls->hostname,
				&tls->session_negotiate->verify_result,
				tls->conf->f_vrfy, tls->conf->p_vrfy);

		if (r != 0)
		{
			TTLS_DEBUG_RET(1, "x509_verify_cert", r);
		}

		/*
		 * Secondary checks: always done, but change 'r' only if it was 0
		 */

		{
			const ttls_pk_context *pk = &tls->session_negotiate->peer_cert->pk;

			/* If certificate uses an EC key, make sure the curve is OK */
			if (ttls_pk_can_do(pk, TTLS_PK_ECKEY) &&
				ttls_check_curve(tls, ttls_pk_ec(*pk)->grp.id) != 0)
			{
				tls->session_negotiate->verify_result |= TTLS_X509_BADCERT_BAD_KEY;

				TTLS_DEBUG_MSG(1, ("bad certificate (EC key curve)"));
				if (r == 0)
					r = TTLS_ERR_BAD_HS_CERTIFICATE;
			}
		}

		if (ttls_check_cert_usage(tls->session_negotiate->peer_cert,
						 ciphersuite_info,
						 ! tls->conf->endpoint,
						 &tls->session_negotiate->verify_result) != 0)
		{
			TTLS_DEBUG_MSG(1, ("bad certificate (usage extensions)"));
			if (r == 0)
				r = TTLS_ERR_BAD_HS_CERTIFICATE;
		}

		/* ttls_x509_crt_verify_with_profile is supposed to report a
		 * verification failure through TTLS_ERR_X509_CERT_VERIFY_FAILED,
		 * with details encoded in the verification flags. All other kinds
		 * of error codes, including those from the user provided f_vrfy
		 * functions, are treated as fatal and lead to a failure of
		 * ssl_parse_certificate even if verification was optional. */
		if (authmode == TTLS_VERIFY_OPTIONAL &&
			(r == TTLS_ERR_X509_CERT_VERIFY_FAILED ||
			 r == TTLS_ERR_BAD_HS_CERTIFICATE))
		{
			r = 0;
		}

		if (ca_chain == NULL && authmode == TTLS_VERIFY_REQUIRED)
		{
			TTLS_DEBUG_MSG(1, ("got no CA chain"));
			r = TTLS_ERR_CA_CHAIN_REQUIRED;
		}

		if (r != 0)
		{
			/* The certificate may have been rejected for several reasons.
			 Pick one and send the corresponding alert. Which alert to send
			 may be a subject of debate in some cases. */
			if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_OTHER)
				alert = TTLS_ALERT_MSG_ACCESS_DENIED;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_CN_MISMATCH)
				alert = TTLS_ALERT_MSG_BAD_CERT;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_KEY_USAGE)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_EXT_KEY_USAGE)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_NS_CERT_TYPE)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_BAD_PK)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_BAD_KEY)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_EXPIRED)
				alert = TTLS_ALERT_MSG_CERT_EXPIRED;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_REVOKED)
				alert = TTLS_ALERT_MSG_CERT_REVOKED;
			else if (tls->session_negotiate->verify_result & TTLS_X509_BADCERT_NOT_TRUSTED)
				alert = TTLS_ALERT_MSG_UNKNOWN_CA;
			else
				alert = TTLS_ALERT_MSG_CERT_UNKNOWN;
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
								alert);
		}

#if defined(DEBUG) && (DEBUG == 3)
		if (tls->session_negotiate->verify_result != 0)
		{
			TTLS_DEBUG_MSG(3, ("! Certificate verification flags %x",
						tls->session_negotiate->verify_result));
		}
		else
		{
			TTLS_DEBUG_MSG(3, ("Certificate verification flags clear"));
		}
#endif
	}

	TTLS_DEBUG_MSG(2, ("<= parse certificate"));

	return r;
}

int ttls_write_change_cipher_spec(ttls_context *tls)
{
	int r;

	TTLS_DEBUG_MSG(2, ("=> write change cipher spec"));

	tls->out_msgtype = TTLS_MSG_CHANGE_CIPHER_SPEC;
	tls->out_msglen = 1;
	tls->out_msg[0] = 1;

	tls->state++;

	if ((r = ttls_write_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", r);
		return r;
	}

	TTLS_DEBUG_MSG(2, ("<= write change cipher spec"));

	return 0;
}

int ttls_parse_change_cipher_spec(ttls_context *tls)
{
	int r;

	TTLS_DEBUG_MSG(2, ("=> parse change cipher spec"));

	if ((r = ttls_read_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_read_record", r);
		return r;
	}

	if (tls->in_msgtype != TTLS_MSG_CHANGE_CIPHER_SPEC)
	{
		TTLS_DEBUG_MSG(1, ("bad change cipher spec message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (tls->in_msglen != 1 || tls->in_msg[0] != 1)
	{
		TTLS_DEBUG_MSG(1, ("bad change cipher spec message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC);
	}

	/*
	 * Switch to our negotiated transform and session parameters for inbound
	 * data.
	 */
	TTLS_DEBUG_MSG(3, ("switching to new transform spec for inbound data"));
	tls->transform_in = tls->transform_negotiate;
	tls->session_in = tls->session_negotiate;

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
	{
#if defined(TTLS_DTLS_ANTI_REPLAY)
		ssl_dtls_replay_reset(tls);
#endif

		/* Increment epoch */
		if (++tls->in_epoch == 0)
		{
			TTLS_DEBUG_MSG(1, ("DTLS epoch would wrap"));
			/* This is highly unlikely to happen for legitimate reasons, so
			 treat it as an attack and don't send an alert. */
			return(TTLS_ERR_COUNTER_WRAPPING);
		}
	}
	else
#endif /* TTLS_PROTO_DTLS */
	memset(tls->in_ctr, 0, 8);

	/*
	 * TODO AK
	 * Set the in_msg pointer to the correct location based on IV length
	 */
	tls->in_msg = tls->in_iv + tls->transform_negotiate->ivlen -
				 tls->transform_negotiate->fixed_ivlen;
	tls->state++;

	TTLS_DEBUG_MSG(2, ("<= parse change cipher spec"));

	return 0;
}

void ttls_optimize_checksum(ttls_context *tls,
		const ttls_ciphersuite_t *ciphersuite_info)
{
#if defined(TTLS_SHA512_C)
	if (ciphersuite_info->mac == TTLS_MD_SHA384)
		tls->hs->update_checksum = ssl_update_checksum_sha384;
	else
#endif
#if defined(TTLS_SHA256_C)
	if (ciphersuite_info->mac != TTLS_MD_SHA384)
		tls->hs->update_checksum = ssl_update_checksum_sha256;
	else
#endif
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return;
	}
}

void ttls_reset_checksum(ttls_context *tls)
{
#if defined(TTLS_SHA256_C)
	ttls_sha256_starts_ret(&tls->hs->fin_sha256, 0);
#endif
#if defined(TTLS_SHA512_C)
	ttls_sha512_starts_ret(&tls->hs->fin_sha512, 1);
#endif
}

static void ssl_update_checksum_start(ttls_context *tls,
			 const unsigned char *buf, size_t len)
{
#if defined(TTLS_SHA256_C)
	ttls_sha256_update_ret(&tls->hs->fin_sha256, buf, len);
#endif
#if defined(TTLS_SHA512_C)
	ttls_sha512_update_ret(&tls->hs->fin_sha512, buf, len);
#endif
}

#if defined(TTLS_SHA256_C)
static void ssl_update_checksum_sha256(ttls_context *tls,
			const unsigned char *buf, size_t len)
{
	ttls_sha256_update_ret(&tls->hs->fin_sha256, buf, len);
}
#endif

#if defined(TTLS_SHA512_C)
static void ssl_update_checksum_sha384(ttls_context *tls,
			const unsigned char *buf, size_t len)
{
	ttls_sha512_update_ret(&tls->hs->fin_sha512, buf, len);
}
#endif

#if defined(TTLS_SHA256_C)
static void ssl_calc_finished_tls_sha256(
		ttls_context *tls, unsigned char *buf, int from)
{
	int len = 12;
	const char *sender;
	ttls_sha256_context sha256;
	unsigned char padbuf[32];

	ttls_session *session = tls->session_negotiate;
	if (!session)
		session = tls->session;

	ttls_sha256_init(&sha256);

	TTLS_DEBUG_MSG(2, ("=> calc finished tls sha256"));

	ttls_sha256_clone(&sha256, &tls->hs->fin_sha256);

	/*
	 * TLSv1.2:
	 * hash = PRF(master, finished_label,
	 *			 Hash(handshake))[0.11]
	 */

#if !defined(TTLS_SHA256_ALT)
	TTLS_DEBUG_BUF(4, "finished sha2 state", (unsigned char *)
				 sha256.state, sizeof(sha256.state));
#endif

	sender = (from == TTLS_IS_CLIENT)
			 ? "client finished"
			 : "server finished";

	ttls_sha256_finish_ret(&sha256, padbuf);

	tls->hs->tls_prf(session->master, 48, sender,
				 padbuf, 32, buf, len);

	TTLS_DEBUG_BUF(3, "calc finished result", buf, len);

	ttls_sha256_free(&sha256);

	bzero_fast( padbuf, sizeof( padbuf));

	TTLS_DEBUG_MSG(2, ("<= calc finished"));
}
#endif /* TTLS_SHA256_C */

#if defined(TTLS_SHA512_C)
static void ssl_calc_finished_tls_sha384(
		ttls_context *tls, unsigned char *buf, int from)
{
	int len = 12;
	const char *sender;
	ttls_sha512_context sha512;
	unsigned char padbuf[48];

	ttls_session *session = tls->session_negotiate;
	if (!session)
		session = tls->session;

	ttls_sha512_init(&sha512);

	TTLS_DEBUG_MSG(2, ("=> calc finished tls sha384"));

	ttls_sha512_clone(&sha512, &tls->hs->fin_sha512);

	/*
	 * TLSv1.2:
	 * hash = PRF(master, finished_label,
	 *			 Hash(handshake))[0.11]
	 */

#if !defined(TTLS_SHA512_ALT)
	TTLS_DEBUG_BUF(4, "finished sha512 state", (unsigned char *)
				 sha512.state, sizeof(sha512.state));
#endif

	sender = (from == TTLS_IS_CLIENT)
			 ? "client finished"
			 : "server finished";

	ttls_sha512_finish_ret(&sha512, padbuf);

	tls->hs->tls_prf(session->master, 48, sender,
				 padbuf, 48, buf, len);

	TTLS_DEBUG_BUF(3, "calc finished result", buf, len);

	ttls_sha512_free(&sha512);

	bzero_fast( padbuf, sizeof(padbuf));

	TTLS_DEBUG_MSG(2, ("<= calc finished"));
}
#endif /* TTLS_SHA512_C */

int ttls_write_finished(ttls_context *tls)
{
	int r, hash_len;

	TTLS_DEBUG_MSG(2, ("=> write finished"));

	/*
	 * Set the out_msg pointer to the correct location based on IV length
	 */
	if (tls->minor_ver >= TTLS_MINOR_VERSION_2)
	{
		tls->out_msg = tls->out_iv + tls->transform_negotiate->ivlen -
					 tls->transform_negotiate->fixed_ivlen;
	}
	else
		tls->out_msg = tls->out_iv;

	tls->hs->calc_finished(tls, tls->out_msg + 4, tls->conf->endpoint);

	/*
	 * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
	 * may define some other value. Currently (early 2016), no defined
	 * ciphersuite does this (and this is unlikely to change as activity has
	 * moved to TLS 1.3 now) so we can keep the hardcoded 12 here.
	 */
	hash_len = (tls->minor_ver == TTLS_MINOR_VERSION_0) ? 36 : 12;

	tls->out_msglen = 4 + hash_len;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0] = TTLS_HS_FINISHED;

	/*
	 * In case of session resuming, invert the client and server
	 * ChangeCipherSpec messages order.
	 */
	if (tls->hs->resume != 0)
	{
#if defined(TTLS_CLI_C)
		if (tls->conf->endpoint == TTLS_IS_CLIENT)
			tls->state = TTLS_HANDSHAKE_WRAPUP;
#endif
		if (tls->conf->endpoint == TTLS_IS_SERVER)
			tls->state = TTLS_CLIENT_CHANGE_CIPHER_SPEC;
	}
	else
		tls->state++;

	/*
	 * Switch to our negotiated transform and session parameters for outbound
	 * data.
	 */
	TTLS_DEBUG_MSG(3, ("switching to new transform spec for outbound data"));

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
	{
		unsigned char i;

		/* Remember current epoch settings for resending */
		tls->hs->alt_transform_out = tls->transform_out;
		memcpy(tls->hs->alt_out_ctr, tls->out_ctr, 8);

		/* Set sequence_number to zero */
		memset(tls->out_ctr + 2, 0, 6);

		/* Increment epoch */
		for (i = 2; i > 0; i--)
			if (++tls->out_ctr[i - 1] != 0)
				break;

		/* The loop goes to its end iff the counter is wrapping */
		if (i == 0)
		{
			TTLS_DEBUG_MSG(1, ("DTLS epoch would wrap"));
			return(TTLS_ERR_COUNTER_WRAPPING);
		}
	}
	else
#endif /* TTLS_PROTO_DTLS */
	memset(tls->out_ctr, 0, 8);

	tls->transform_out = tls->transform_negotiate;
	tls->session_out = tls->session_negotiate;

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_send_flight_completed(tls);
#endif

	if ((r = ttls_write_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", r);
		return r;
	}

	TTLS_DEBUG_MSG(2, ("<= write finished"));

	return 0;
}

#define SSL_MAX_HASH_LEN 12

int ttls_parse_finished(ttls_context *tls)
{
	int r;
	unsigned int hash_len;
	unsigned char buf[SSL_MAX_HASH_LEN];

	TTLS_DEBUG_MSG(2, ("=> parse finished"));

	tls->hs->calc_finished(tls, buf, tls->conf->endpoint ^ 1);

	if ((r = ttls_read_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_read_record", r);
		return r;
	}

	if (tls->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad finished message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	/* There is currently no ciphersuite using another length with TLS 1.2 */
	hash_len = 12;

	if (tls->in_msg[0] != TTLS_HS_FINISHED ||
		tls->in_hslen != ttls_hs_hdr_len(tls) + hash_len)
	{
		TTLS_DEBUG_MSG(1, ("bad finished message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_FINISHED);
	}

	if (crypto_memneq(tls->in_msg + ttls_hs_hdr_len(tls),
					 buf, hash_len) != 0)
	{
		TTLS_DEBUG_MSG(1, ("bad finished message"));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_FINISHED);
	}

	if (tls->hs->resume != 0)
	{
#if defined(TTLS_CLI_C)
		if (tls->conf->endpoint == TTLS_IS_CLIENT)
			tls->state = TTLS_CLIENT_CHANGE_CIPHER_SPEC;
#endif
		if (tls->conf->endpoint == TTLS_IS_SERVER)
			tls->state = TTLS_HANDSHAKE_WRAPUP;
	}
	else
		tls->state++;

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_recv_flight_completed(tls);
#endif

	TTLS_DEBUG_MSG(2, ("<= parse finished"));

	return 0;
}

static void
ssl_handshake_params_init(TlsHandshake *hs)
{
	bzero_fast(hs, sizeof(*hs));

#if defined(TTLS_SHA256_C)
	ttls_sha256_init(&hs->fin_sha256);
	ttls_sha256_starts_ret(&hs->fin_sha256, 0);
#endif
#if defined(TTLS_SHA512_C)
	ttls_sha512_init(&hs->fin_sha512);
	ttls_sha512_starts_ret(&hs->fin_sha512, 1);
#endif

	hs->update_checksum = ssl_update_checksum_start;

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	ttls_sig_hash_set_init(&hs->hash_algs);
#endif

#if defined(TTLS_DHM_C)
	ttls_dhm_init(&hs->dhm_ctx);
#endif
#if defined(TTLS_ECDH_C)
	ttls_ecdh_init(&hs->ecdh_ctx);
#endif
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ttls_ecjpake_init(&hs->ecjpake_ctx);
#endif
	hs->sni_authmode = TTLS_VERIFY_UNSET;
}

int
ttls_ctx_init(TlsCtx *tls, const ttls_config *conf)
{
	bzero_fast(tls, sizeof(*tls));
	spin_lock_init(&tls->lock);

	tls->conf = conf;

	tls->hs = kmem_cache_alloc(ttls_hs_cache, GFP_ATOMIC);
	if (!tls->hs)
		return -ENOMEM;

	/* Initialize structures */
	ttls_cipher_init(&tls.xfrm->cipher_ctx_enc);
	ttls_cipher_init(&tls.xfrm->cipher_ctx_dec);
	ttls_md_init(&tls.xfrm->md_ctx_enc);
	ttls_md_init(&tls.xfrm->md_ctx_dec);
	ssl_handshake_params_init(tls->hs);

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM) {
		tls->hs->alt_transform_out = tls->transform_out;
		if (tls->conf->endpoint == TTLS_IS_CLIENT)
			tls->hs->retransmit_state = TTLS_RETRANS_PREPARING;
		else
			tls->hs->retransmit_state = TTLS_RETRANS_WAITING;
		ssl_set_timer(tls, 0);
	}
#endif
	return 0;
}
EXPORT_SYMBOL(ttls_ctx_init);

/**
 * Clear current FSM state for TLS record processing. Must be called whenever
 * a TLS record is full read and we're going to read a next one.
 */
void
ttls_init_msg_ctx(TlsCtx *tls)
{
	tls->in_msgtype = 0;
	tls->tmp_bsz = 0;
	tls->st_flags = 0;
}
EXPORT_SYMBOL(ttls_init_msg_ctx);

/*
 * SSL set accessors
 */
void ttls_conf_endpoint(ttls_config *conf, int endpoint)
{
	conf->endpoint = endpoint;
}

void ttls_conf_transport(ttls_config *conf, int transport)
{
	conf->transport = transport;
}

void ttls_conf_authmode(ttls_config *conf, int authmode)
{
	conf->authmode = authmode;
}

void ttls_conf_verify(ttls_config *conf,
		int (*f_vrfy)(void *, ttls_x509_crt *, int, uint32_t *),
		void *p_vrfy)
{
	conf->f_vrfy	 = f_vrfy;
	conf->p_vrfy	 = p_vrfy;
}

void ttls_conf_rng(ttls_config *conf,
		int (*f_rng)(void *, unsigned char *, size_t),
		void *p_rng)
{
	conf->f_rng	 = f_rng;
	conf->p_rng	 = p_rng;
}

void ttls_conf_dbg(ttls_config *conf,
		void (*f_dbg)(void *, int, const char *, int, const char *),
		void *p_dbg)
{
	conf->f_dbg	 = f_dbg;
	conf->p_dbg	 = p_dbg;
}

void ttls_set_timer_cb(ttls_context *tls,
		void *p_timer,
		ttls_set_timer_t *f_set_timer,
		ttls_get_timer_t *f_get_timer)
{
	tls->p_timer		= p_timer;
	tls->f_set_timer	= f_set_timer;
	tls->f_get_timer	= f_get_timer;

	/* Make sure we start with no timer running */
	ssl_set_timer(tls, 0);
}

void ttls_conf_session_cache(ttls_config *conf,
		void *p_cache,
		int (*f_get_cache)(void *, ttls_session *),
		int (*f_set_cache)(void *, const ttls_session *))
{
	conf->p_cache = p_cache;
	conf->f_get_cache = f_get_cache;
	conf->f_set_cache = f_set_cache;
}

#if defined(TTLS_CLI_C)
int ttls_set_session(ttls_context *tls, const ttls_ssl_session *session)
{
	int r;

	if (tls == NULL ||
		session == NULL ||
		tls->session_negotiate == NULL ||
		tls->conf->endpoint != TTLS_IS_CLIENT)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	if ((r = ssl_session_copy(tls->session_negotiate, session)) != 0)
		return r;

	tls->hs->resume = 1;

	return 0;
}
#endif /* TTLS_CLI_C */

void ttls_conf_ciphersuites(ttls_config *conf,
		const int *ciphersuites)
{
	conf->ciphersuite_list[TTLS_MINOR_VERSION_0] = ciphersuites;
	conf->ciphersuite_list[TTLS_MINOR_VERSION_1] = ciphersuites;
	conf->ciphersuite_list[TTLS_MINOR_VERSION_2] = ciphersuites;
	conf->ciphersuite_list[TTLS_MINOR_VERSION_3] = ciphersuites;
}

void ttls_conf_ciphersuites_for_version(ttls_config *conf,
		const int *ciphersuites,
		int major, int minor)
{
	if (major != TTLS_MAJOR_VERSION_3)
		return;

	if (minor < TTLS_MINOR_VERSION_0 || minor > TTLS_MINOR_VERSION_3)
		return;

	conf->ciphersuite_list[minor] = ciphersuites;
}

void ttls_conf_cert_profile(ttls_config *conf,
		const ttls_x509_crt_profile *profile)
{
	conf->cert_profile = profile;
}

/* Append a new keycert entry to a (possibly empty) list */
static int ssl_append_key_cert(ttls_key_cert **head,
		ttls_x509_crt *cert,
		ttls_pk_context *key)
{
	ttls_key_cert *new;

	new = ttls_calloc(1, sizeof(ttls_key_cert));
	if (new == NULL)
		return(TTLS_ERR_ALLOC_FAILED);

	new->cert = cert;
	new->key = key;
	new->next = NULL;

	/* Update head is the list was null, else add to the end */
	if (*head == NULL)
	{
		*head = new;
	}
	else
	{
		ttls_key_cert *cur = *head;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = new;
	}

	return 0;
}

int ttls_conf_own_cert(ttls_config *conf,
		ttls_x509_crt *own_cert,
		ttls_pk_context *pk_key)
{
	return(ssl_append_key_cert(&conf->key_cert, own_cert, pk_key));
}

void ttls_conf_ca_chain(ttls_config *conf,
		ttls_x509_crt *ca_chain,
		ttls_x509_crl *ca_crl)
{
	conf->ca_chain = ca_chain;
	conf->ca_crl	 = ca_crl;
}

int ttls_set_hs_own_cert(ttls_context *tls,
		ttls_x509_crt *own_cert,
		ttls_pk_context *pk_key)
{
	return(ssl_append_key_cert(&tls->hs->sni_key_cert,
				 own_cert, pk_key));
}

void ttls_set_hs_ca_chain(ttls_context *tls,
		ttls_x509_crt *ca_chain,
		ttls_x509_crl *ca_crl)
{
	tls->hs->sni_ca_chain = ca_chain;
	tls->hs->sni_ca_crl	 = ca_crl;
}

void ttls_set_hs_authmode(ttls_context *tls,
		int authmode)
{
	tls->hs->sni_authmode = authmode;
}

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
/*
 * Set EC J-PAKE password for current handshake
 */
int ttls_set_hs_ecjpake_password(ttls_context *tls,
		const unsigned char *pw,
		size_t pw_len)
{
	ttls_ecjpake_role role;

	if (tls->hs == NULL || tls->conf == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	if (tls->conf->endpoint == TTLS_IS_SERVER)
		role = TTLS_ECJPAKE_SERVER;
	else
		role = TTLS_ECJPAKE_CLIENT;

	return(ttls_ecjpake_setup(&tls->hs->ecjpake_ctx,
				 role,
				 TTLS_MD_SHA256,
				 TTLS_ECP_DP_SECP256R1,
				 pw, pw_len));
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int ttls_conf_psk(ttls_config *conf,
		const unsigned char *psk, size_t psk_len,
		const unsigned char *psk_identity, size_t psk_identity_len)
{
	if (psk == NULL || psk_identity == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	if (psk_len > TTLS_PSK_MAX_LEN)
		return(TTLS_ERR_BAD_INPUT_DATA);

	/* Identity len will be encoded on two bytes */
	if ((psk_identity_len >> 16) != 0 ||
		psk_identity_len > TTLS_MAX_CONTENT_LEN)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	if (conf->psk != NULL)
	{
		bzero_fast(conf->psk, conf->psk_len);

		ttls_free(conf->psk);
		conf->psk = NULL;
		conf->psk_len = 0;
	}
	if (conf->psk_identity != NULL)
	{
		ttls_free(conf->psk_identity);
		conf->psk_identity = NULL;
		conf->psk_identity_len = 0;
	}

	if ((conf->psk = ttls_calloc(1, psk_len)) == NULL ||
		(conf->psk_identity = ttls_calloc(1, psk_identity_len)) == NULL)
	{
		ttls_free(conf->psk);
		ttls_free(conf->psk_identity);
		conf->psk = NULL;
		conf->psk_identity = NULL;
		return(TTLS_ERR_ALLOC_FAILED);
	}

	conf->psk_len = psk_len;
	conf->psk_identity_len = psk_identity_len;

	memcpy(conf->psk, psk, conf->psk_len);
	memcpy(conf->psk_identity, psk_identity, conf->psk_identity_len);

	return 0;
}

int ttls_set_hs_psk(ttls_context *tls,
		const unsigned char *psk, size_t psk_len)
{
	if (psk == NULL || tls->hs == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	if (psk_len > TTLS_PSK_MAX_LEN)
		return(TTLS_ERR_BAD_INPUT_DATA);

	if (tls->hs->psk != NULL)
	{
		bzero_fast(tls->hs->psk, tls->hs->psk_len);
		ttls_free(tls->hs->psk);
		tls->hs->psk_len = 0;
	}

	if ((tls->hs->psk = ttls_calloc(1, psk_len)) == NULL)
		return(TTLS_ERR_ALLOC_FAILED);

	tls->hs->psk_len = psk_len;
	memcpy(tls->hs->psk, psk, tls->hs->psk_len);

	return 0;
}

void ttls_conf_psk_cb(ttls_config *conf,
		int (*f_psk)(void *, ttls_context *, const unsigned char *,
		size_t),
		void *p_psk)
{
	conf->f_psk = f_psk;
	conf->p_psk = p_psk;
}
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(TTLS_DHM_C)

int ttls_conf_dh_param_bin(ttls_config *conf,
		const unsigned char *dhm_P, size_t P_len,
		const unsigned char *dhm_G, size_t G_len)
{
	int r;

	if ((r = ttls_mpi_read_binary(&conf->dhm_P, dhm_P, P_len)) != 0 ||
		(r = ttls_mpi_read_binary(&conf->dhm_G, dhm_G, G_len)) != 0)
	{
		ttls_mpi_free(&conf->dhm_P);
		ttls_mpi_free(&conf->dhm_G);
		return r;
	}

	return 0;
}

int ttls_conf_dh_param_ctx(ttls_config *conf, ttls_dhm_context *dhm_ctx)
{
	int r;

	if ((r = ttls_mpi_copy(&conf->dhm_P, &dhm_ctx->P)) != 0 ||
		(r = ttls_mpi_copy(&conf->dhm_G, &dhm_ctx->G)) != 0)
	{
		ttls_mpi_free(&conf->dhm_P);
		ttls_mpi_free(&conf->dhm_G);
		return r;
	}

	return 0;
}
#endif /* TTLS_DHM_C */

#if defined(TTLS_DHM_C) && defined(TTLS_CLI_C)
/*
 * Set the minimum length for Diffie-Hellman parameters
 */
void ttls_conf_dhm_min_bitlen(ttls_config *conf,
		unsigned int bitlen)
{
	conf->dhm_min_bitlen = bitlen;
}
#endif /* TTLS_DHM_C && TTLS_CLI_C */

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Set allowed/preferred hashes for hs signatures
 */
void ttls_conf_sig_hashes(ttls_config *conf,
		const int *hashes)
{
	conf->sig_hashes = hashes;
}
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * Set the allowed elliptic curves
 */
void ttls_conf_curves(ttls_config *conf,
		const ttls_ecp_group_id *curve_list)
{
	conf->curve_list = curve_list;
}

int ttls_set_hostname(ttls_context *tls, const char *hostname)
{
	/* Initialize to suppress unnecessary compiler warning */
	size_t hostname_len = 0;

	/* Check if new hostname is valid before
	 * making any change to current one */
	if (hostname != NULL)
	{
		hostname_len = strlen(hostname);

		if (hostname_len > TTLS_MAX_HOST_NAME_LEN)
			return(TTLS_ERR_BAD_INPUT_DATA);
	}

	/* Now it's clear that we will overwrite the old hostname,
	 * so we can free it safely */

	if (tls->hostname != NULL)
	{
		bzero_fast(tls->hostname, strlen(tls->hostname));
		ttls_free(tls->hostname);
	}

	/* Passing NULL as hostname shall clear the old one */

	if (hostname == NULL)
	{
		tls->hostname = NULL;
	}
	else
	{
		tls->hostname = ttls_calloc(1, hostname_len + 1);
		if (tls->hostname == NULL)
			return(TTLS_ERR_ALLOC_FAILED);

		memcpy(tls->hostname, hostname, hostname_len);

		tls->hostname[hostname_len] = '\0';
	}

	return 0;
}

void ttls_conf_sni(ttls_config *conf,
		int (*f_sni)(void *, ttls_context *,
			const unsigned char *, size_t),
		void *p_sni)
{
	conf->f_sni = f_sni;
	conf->p_sni = p_sni;
}

int ttls_conf_alpn_protocols(ttls_config *conf, const char **protos)
{
	size_t cur_len, tot_len;
	const char **p;

	/*
	 * RFC 7301 3.1: "Empty strings MUST NOT be included and byte strings
	 * MUST NOT be truncated."
	 * We check lengths now rather than later.
	 */
	tot_len = 0;
	for (p = protos; *p != NULL; p++)
	{
		cur_len = strlen(*p);
		tot_len += cur_len;

		if (cur_len == 0 || cur_len > 255 || tot_len > 65535)
			return(TTLS_ERR_BAD_INPUT_DATA);
	}

	conf->alpn_list = protos;

	return 0;
}

const char *ttls_get_alpn_protocol(const ttls_context *tls)
{
	return(tls->alpn_chosen);
}

void ttls_conf_max_version(ttls_config *conf, int major, int minor)
{
	conf->max_major_ver = major;
	conf->max_minor_ver = minor;
}

void ttls_conf_min_version(ttls_config *conf, int major, int minor)
{
	conf->min_major_ver = major;
	conf->min_minor_ver = minor;
}

#if defined(TTLS_FALLBACK_SCSV) && defined(TTLS_CLI_C)
void ttls_conf_fallback(ttls_config *conf, char fallback)
{
	conf->fallback = fallback;
}
#endif

void ttls_conf_cert_req_ca_list(ttls_config *conf,
		char cert_req_ca_list)
{
	conf->cert_req_ca_list = cert_req_ca_list;
}

#if defined(TTLS_EXTENDED_MASTER_SECRET)
void ttls_conf_extended_master_secret(ttls_config *conf, char ems)
{
	conf->extended_ms = ems;
}
#endif

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
int ttls_conf_max_frag_len(ttls_config *conf, unsigned char mfl_code)
{
	if (mfl_code >= TTLS_MAX_FRAG_LEN_INVALID ||
		mfl_code_to_length[mfl_code] > TTLS_MAX_CONTENT_LEN)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	conf->mfl_code = mfl_code;

	return 0;
}
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

void ttls_conf_legacy_renegotiation(ttls_config *conf, int allow_legacy)
{
	conf->allow_legacy_renegotiation = allow_legacy;
}

#if defined(TTLS_SESSION_TICKETS)
#if defined(TTLS_CLI_C)
void ttls_conf_session_tickets(ttls_config *conf, int use_tickets)
{
	conf->session_tickets = use_tickets;
}
#endif

void ttls_conf_session_tickets_cb(ttls_config *conf,
		ttls_ticket_write_t *f_ticket_write,
		ttls_ticket_parse_t *f_ticket_parse,
		void *p_ticket)
{
	conf->f_ticket_write = f_ticket_write;
	conf->f_ticket_parse = f_ticket_parse;
	conf->p_ticket	 = p_ticket;
}
#endif /* TTLS_SESSION_TICKETS */

#if defined(TTLS_EXPORT_KEYS)
void ttls_conf_export_keys_cb(ttls_config *conf,
		ttls_export_keys_t *f_export_keys,
		void *p_export_keys)
{
	conf->f_export_keys = f_export_keys;
	conf->p_export_keys = p_export_keys;
}
#endif

/*
 * SSL get accessors
 */
uint32_t ttls_get_verify_result(const ttls_context *tls)
{
	if (tls->session != NULL)
		return(tls->session->verify_result);

	if (tls->session_negotiate != NULL)
		return(tls->session_negotiate->verify_result);

	return(0xFFFFFFFF);
}

const char *ttls_get_ciphersuite(const ttls_context *tls)
{
	if (tls == NULL || tls->session == NULL)
		return(NULL);

	return ttls_get_ciphersuite_name(tls->session->ciphersuite);
}

int ttls_get_record_expansion(const ttls_context *tls)
{
	size_t transform_expansion;
	const ttls_transform *transform = tls->transform_out;

	if (transform == NULL)
		return((int) ttls_hdr_len(tls));

	switch(ttls_cipher_get_cipher_mode(&transform->cipher_ctx_enc))
	{
		case TTLS_MODE_GCM:
		case TTLS_MODE_CCM:
		case TTLS_MODE_STREAM:
			transform_expansion = transform->minlen;
			break;

		case TTLS_MODE_CBC:
			transform_expansion = transform->maclen
				+ ttls_cipher_get_block_size(&transform->cipher_ctx_enc);
			break;

		default:
			TTLS_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_INTERNAL_ERROR);
	}

	return((int)(ttls_hdr_len(tls) + transform_expansion));
}

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
size_t ttls_get_max_frag_len(const ttls_context *tls)
{
	size_t max_len;

	/*
	 * Assume mfl_code is correct since it was checked when set
	 */
	max_len = mfl_code_to_length[tls->conf->mfl_code];

	/*
	 * Check if a smaller max length was negotiated
	 */
	if (tls->session_out != NULL &&
		mfl_code_to_length[tls->session_out->mfl_code] < max_len)
	{
		max_len = mfl_code_to_length[tls->session_out->mfl_code];
	}

	return max_len;
}
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

const ttls_x509_crt *ttls_get_peer_cert(const ttls_context *tls)
{
	if (tls == NULL || tls->session == NULL)
		return(NULL);

	return(tls->session->peer_cert);
}

#if defined(TTLS_CLI_C)
int ttls_get_session(const ttls_context *tls, ttls_ssl_session *dst)
{
	if (tls == NULL ||
		dst == NULL ||
		tls->session == NULL ||
		tls->conf->endpoint != TTLS_IS_CLIENT)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	return(ssl_session_copy(dst, tls->session));
}
#endif /* TTLS_CLI_C */

/**
 * Perform the TLS handshake.
 *
 * The state of the context (tls->state) will be at the next state after
 * execution of this function. Do not call this function if state is
 * TTLS_HANDSHAKE_OVER.
 *
 * If this function returns something other than 0 or TTLS_ERR_WANT_READ/WRITE,
 * then the TLS context becomes unusable, and you should either free it or call
 * ttls_session_reset() on it before re-using it for a new connection; the
 * current connection must be closed.
 *
 * @return 0 if successful, or TTLS_ERR_WANT_READ or TTLS_ERR_SSL_WANT_WRITE, or
 * a specific SSL error code.
 */
static int
ttls_handshake(TlsCtx *tls)
{
	int r = 0;

	if (tls->state == TTLS_HANDSHAKE_OVER)
		return 0;

	T_DBG3("handshake on state %d\n", tls->state);
#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT)
		return ttls_handshake_client_step(tls);
	else
#endif
	return ttls_handshake_server_step(tls);
}

/**
 * Main TLS receive routine.
 *
 * @buf and @len defines a chunk of ingress network data, probably containing
 * parts of several TLS messages, e.g. a tail of last message, a short full
 * message and a begin of a next message.
 *
 * @return T_POSTPONE during handshake and T_PASS is some data is ready for
 * upper layer protocol processing. Other negative values are returned on
 * errors.
 * The function adds the number of bytes parsed in @buf to @read.
 *
 * TODO AK	When this function return TTLS_ERR_CLIENT_RECONNECT
 *		(which can only happen server-side), it means that a client
 *		is initiating a new connection using the same source port.
 *		You can either treat that as a connection close and wait
 *		for the client to resend a ClientHello, or directly
 *		continue with \c ttls_handshake() with the same
 *		context (as it has beeen reset internally). Either way, you
 *		should make sure this is seen by the application as a new
 *		connection: application state, if any, should be reset, and
 *		most importantly the identity of the client must be checked
 *		again. WARNING: not validating the identity of the client
 *		again, or not transmitting the new identity to the
 *		application layer, would allow authentication bypass!
 */
int
ttls_recv(void *tls_data, unsigned char *buf, size_t len, unsigned int *read)
{
	int r;
	TlsCtx *tls = (TlsCtx *)tls_data;

	BUG_ON(!tls || !tls->conf);
	T_DBG3("%s: len=%lu read=%u\n", __func__, len, *read);

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM
	    && tls->hs
	    && tls->hs->retransmit_state == TTLS_RETRANS_SENDING
	    && (r = ttls_resend(tls)))
	{
		return r;
	}
#endif

	r = ttls_handshake(tls);
	if (r && r != TTLS_ERR_WAITING_SERVER_HELLO_RENEGO) {
		T_DBG("handshake error: %d\n", r);
		return r;
	}

	/* Start timer if not already running */
	if (tls->f_get_timer != NULL &&
		tls->f_get_timer(tls->p_timer) == -1)
	{
		ssl_set_timer(tls, tls->conf->read_timeout);
	}

	if ((r = ttls_read_record(tls, buf, len, read))) {
		if (r == TTLS_ERR_CONN_EOF)
			return 0;
		TTLS_DEBUG_RET(1, "ttls_read_record", r);
		return r;
	}

	if (!tls->in_msglen
	    && tls->in_msgtype == TTLS_MSG_APPLICATION_DATA)
	{
		/* OpenSSL sends empty messages to randomize the IV. */
		if ((r = ttls_read_record(tls, buf, len, read))) {
			if (r == TTLS_ERR_CONN_EOF)
				return 0;
			TTLS_DEBUG_RET(1, "ttls_read_record", r);
			return r;
		}
	}

	if (tls->in_msgtype == TTLS_MSG_HANDSHAKE) {
		TTLS_DEBUG_MSG(1, ("received handshake message"));

		/*
		 * - For client-side, expect SERVER_HELLO_REQUEST.
		 * - For server-side, expect CLIENT_HELLO.
		 * - Fail (TLS) or silently drop record (DTLS) in other cases.
		 */

#if defined(TTLS_CLI_C)
		if (tls->conf->endpoint == TTLS_IS_CLIENT &&
			(tls->in_msg[0] != TTLS_HS_HELLO_REQUEST ||
			 tls->in_hslen != ttls_hs_hdr_len(tls)))
		{
			T_DBG3("handshake received (not HelloRequest)");
			/*
			 * With DTLS, drop the packet
			 * (probably from last handshake).
			 */
#if defined(TTLS_PROTO_DTLS)
			if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
				return TTLS_ERR_WANT_READ;
#endif
			return TTLS_ERR_UNEXPECTED_MESSAGE;
		}
#endif /* TTLS_CLI_C */

		if (tls->conf->endpoint == TTLS_IS_SERVER
		    && tls->in_msg[0] != TTLS_HS_CLIENT_HELLO)
		{
			T_DBG3("handshake received (not ClientHello)");
			/*
			 * With DTLS, drop the packet
			 * (probably from last handshake).
			 */
#if defined(TTLS_PROTO_DTLS)
			if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
				return TTLS_ERR_WANT_READ;
#endif
			return TTLS_ERR_UNEXPECTED_MESSAGE;
		}

		/*
		 * Refuse renegotiation
		 */
		T_DBG3("refusing renegotiation, sending alert");
		WARN_ON_ONCE(tls->minor_ver < TTLS_MINOR_VERSION_1);

		r = ttls_send_alert_msg(tls,
				TTLS_ALERT_LEVEL_WARNING,
				TTLS_ALERT_MSG_NO_RENEGOTIATION);

		return r ? : TTLS_ERR_WANT_READ;
	}

	/* Fatal and closure alerts handled by ttls_read_record() */
	if (tls->in_msgtype == TTLS_MSG_ALERT) {
		T_DBG3("ignoring non-fatal non-closure alert");
		return TTLS_ERR_WANT_READ;
	}

	if (tls->in_msgtype != TTLS_MSG_APPLICATION_DATA) {
		T_DBG3("bad application data message");
		return TTLS_ERR_UNEXPECTED_MESSAGE;
	}

	/* We're going to return something now, cancel timer,
	 * except if handshake (renegotiation) is in progress */
	if (tls->state == TTLS_HANDSHAKE_OVER)
		ssl_set_timer(tls, 0);

	/*
	 * If we requested renego in DTLS but received AppData, resend
	 * HelloRequest. Do it now to avoid taking this
	 * branch again if ssl_write_hello_request() returns WANT_WRITE.
	 */

have_data:
	tls->in_msglen = len >= tls->in_msglen ? 0 : tls->in_msglen - len;
	if (!tls->in_msglen) {
		/* all bytes consumed */
		tls->keep_current_message = 0;
	}

	return len; // TODO AK: POSTPONE | OK ?
}
EXPORT_SYMBOL(ttls_recv);

/*
 * Send application data to be encrypted by the SSL layer,
 * taking care of max fragment length and buffer size
 */
static int ssl_write_real(ttls_context *tls,
		const unsigned char *buf, size_t len)
{
	int r;
#if defined(TTLS_MAX_FRAGMENT_LENGTH)
	size_t max_len = ttls_get_max_frag_len(tls);
#else
	size_t max_len = TTLS_MAX_CONTENT_LEN;
#endif /* TTLS_MAX_FRAGMENT_LENGTH */
	if (len > max_len)
	{
#if defined(TTLS_PROTO_DTLS)
		if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		{
			TTLS_DEBUG_MSG(1, ("fragment larger than the (negotiated) "
						"maximum fragment length: %d > %d",
						len, max_len));
			return(TTLS_ERR_BAD_INPUT_DATA);
		}
		else
#endif
			len = max_len;
	}

	tls->out_msglen = len;
	tls->out_msgtype = TTLS_MSG_APPLICATION_DATA;
	memcpy(tls->out_msg, buf, len);

	if ((r = ttls_write_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", r);
		return r;
	}

	return((int) len);
}

/**
 * Notify the peer that the connection is being closed.
 */
int
ttls_close_notify(TlsCtx *tls)
{
	int r = 0;

	BUG_ON(!tls || !tls->conf);
	T_DBG3("write close notify\n");

	if (tls->state == TTLS_HANDSHAKE_OVER)
		r = ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_WARNING,
					TTLS_ALERT_MSG_CLOSE_NOTIFY);

	return r;
}
EXPORT_SYMBOL(ttls_close_notify);

void ttls_transform_free(ttls_transform *transform)
{
	if (transform == NULL)
		return;

	ttls_cipher_free(&transform->cipher_ctx_enc);
	ttls_cipher_free(&transform->cipher_ctx_dec);

	ttls_md_free(&transform->md_ctx_enc);
	ttls_md_free(&transform->md_ctx_dec);

	bzero_fast(transform, sizeof(ttls_transform));
}

static void ssl_key_cert_free(ttls_key_cert *key_cert)
{
	ttls_key_cert *cur = key_cert, *next;

	while (cur != NULL)
	{
		next = cur->next;
		ttls_free(cur);
		cur = next;
	}
}

void
ttls_session_free(TlsSess *session)
{
	if (!session)
		return;

	if (session->peer_cert) {
		ttls_x509_crt_free(session->peer_cert);
		ttls_free(session->peer_cert);
	}

#if defined(TTLS_SESSION_TICKETS) && defined(TTLS_CLI_C)
	ttls_free(session->ticket);
#endif

	bzero_fast(session, sizeof(*session));
}

/*
 * Free an SSL context
 */
void ttls_ctx_free(TlsCtx *tls)
{
	if (tls == NULL)
		return;

	TTLS_DEBUG_MSG(2, ("=> free"));

	if (tls->out_buf != NULL)
	{
		bzero_fast(tls->out_buf, TTLS_BUF_LEN);
		ttls_free(tls->out_buf);
	}

	if (tls->in_buf != NULL)
	{
		bzero_fast(tls->in_buf, TTLS_BUF_LEN);
		ttls_free(tls->in_buf);
	}

	if (tls->transform)
	{
		ttls_transform_free(tls->transform);
		ttls_free(tls->transform);
	}

	if (tls->hs)
	{
		ttls_handshake_free(tls->hs);
		ttls_transform_free(tls->transform_negotiate);
		ttls_session_free(tls->session_negotiate);

		ttls_free(tls->hs);
		ttls_free(tls->transform_negotiate);
		ttls_free(tls->session_negotiate);
	}

	if (tls->session)
	{
		ttls_session_free(tls->session);
		ttls_free(tls->session);
	}

	if (tls->hostname != NULL)
	{
		bzero_fast(tls->hostname, strlen(tls->hostname));
		ttls_free(tls->hostname);
	}

#if defined(TTLS_DTLS_HELLO_VERIFY)
	ttls_free(tls->cli_id);
#endif

	TTLS_DEBUG_MSG(2, ("<= free"));

	/* Actually clear after last debug message */
	bzero_fast(tls, sizeof(ttls_context));
}
EXPORT_SYMBOL(ttls_ctx_free);

/*
 * Initialze ttls_config
 */
void ttls_config_init(ttls_config *conf)
{
	memset(conf, 0, sizeof(ttls_config));
}

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
static int ssl_preset_default_hashes[] = {
#if defined(TTLS_SHA512_C)
	TTLS_MD_SHA512,
	TTLS_MD_SHA384,
#endif
#if defined(TTLS_SHA256_C)
	TTLS_MD_SHA256,
	TTLS_MD_SHA224,
#endif
	TTLS_MD_NONE
};
#endif

static int ssl_preset_suiteb_ciphersuites[] = {
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	0
};

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
static int ssl_preset_suiteb_hashes[] = {
	TTLS_MD_SHA256,
	TTLS_MD_SHA384,
	TTLS_MD_NONE
};
#endif

static ttls_ecp_group_id ssl_preset_suiteb_curves[] = {
	TTLS_ECP_DP_SECP256R1,
	TTLS_ECP_DP_SECP384R1,
	TTLS_ECP_DP_NONE
};

/*
 * Load default in ttls_config
 */
int ttls_config_defaults(ttls_config *conf,
		int endpoint, int transport, int preset)
{
#if defined(TTLS_DHM_C)
	int r;
#endif

	/* Use the functions here so that they are covered in tests,
	 * but otherwise access member directly for efficiency */
	ttls_conf_endpoint(conf, endpoint);
	ttls_conf_transport(conf, transport);

	/*
	 * Things that are common to all presets
	 */
#if defined(TTLS_CLI_C)
	if (endpoint == TTLS_IS_CLIENT)
	{
		conf->authmode = TTLS_VERIFY_REQUIRED;
#if defined(TTLS_SESSION_TICKETS)
		conf->session_tickets = TTLS_SESSION_TICKETS_ENABLED;
#endif
	}
#endif

#if defined(TTLS_EXTENDED_MASTER_SECRET)
	conf->extended_ms = TTLS_EXTENDED_MS_ENABLED;
#endif

#if defined(TTLS_DTLS_HELLO_VERIFY)
	conf->f_cookie_write = ssl_cookie_write_dummy;
	conf->f_cookie_check = ssl_cookie_check_dummy;
#endif

#if defined(TTLS_DTLS_ANTI_REPLAY)
	conf->anti_replay = TTLS_ANTI_REPLAY_ENABLED;
#endif

	conf->cert_req_ca_list = TTLS_CERT_REQ_CA_LIST_ENABLED;

#if defined(TTLS_PROTO_DTLS)
	conf->hs_timeout_min = TTLS_DTLS_TIMEOUT_DFL_MIN;
	conf->hs_timeout_max = TTLS_DTLS_TIMEOUT_DFL_MAX;
#endif

#if defined(TTLS_DHM_C)
			if (endpoint == TTLS_IS_SERVER)
			{
				const unsigned char dhm_p[] =
					TTLS_DHM_RFC3526_MODP_2048_P_BIN;
				const unsigned char dhm_g[] =
					TTLS_DHM_RFC3526_MODP_2048_G_BIN;

				if ((r = ttls_conf_dh_param_bin(conf,
						 dhm_p, sizeof(dhm_p),
						 dhm_g, sizeof(dhm_g))) != 0)
				{
					return r;
				}
			}
#endif

	/*
	 * Preset-specific defaults
	 */
	switch(preset)
	{
		/*
		 * NSA Suite B
		 */
		case TTLS_PRESET_SUITEB:
			conf->min_major_ver = TTLS_MAJOR_VERSION_3;
			conf->min_minor_ver = TTLS_MINOR_VERSION_3; /* TLS 1.2 */
			conf->max_major_ver = TTLS_MAX_MAJOR_VERSION;
			conf->max_minor_ver = TTLS_MAX_MINOR_VERSION;

			conf->ciphersuite_list[TTLS_MINOR_VERSION_0] =
			conf->ciphersuite_list[TTLS_MINOR_VERSION_1] =
			conf->ciphersuite_list[TTLS_MINOR_VERSION_2] =
			conf->ciphersuite_list[TTLS_MINOR_VERSION_3] =
					 ssl_preset_suiteb_ciphersuites;

			conf->cert_profile = &ttls_x509_crt_profile_suiteb;

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
			conf->sig_hashes = ssl_preset_suiteb_hashes;
#endif

			conf->curve_list = ssl_preset_suiteb_curves;
			break;

		/*
		 * Default
		 */
		default:
			conf->min_major_ver = (TTLS_MIN_MAJOR_VERSION >
						TTLS_MIN_VALID_MAJOR_VERSION) ?
						TTLS_MIN_MAJOR_VERSION :
						TTLS_MIN_VALID_MAJOR_VERSION;
			conf->min_minor_ver = (TTLS_MIN_MINOR_VERSION >
						TTLS_MIN_VALID_MINOR_VERSION) ?
						TTLS_MIN_MINOR_VERSION :
						TTLS_MIN_VALID_MINOR_VERSION;
			conf->max_major_ver = TTLS_MAX_MAJOR_VERSION;
			conf->max_minor_ver = TTLS_MAX_MINOR_VERSION;

#if defined(TTLS_PROTO_DTLS)
			if (transport == TTLS_TRANSPORT_DATAGRAM)
				conf->min_minor_ver = TTLS_MINOR_VERSION_2;
#endif

			conf->ciphersuite_list[TTLS_MINOR_VERSION_0] =
			conf->ciphersuite_list[TTLS_MINOR_VERSION_1] =
			conf->ciphersuite_list[TTLS_MINOR_VERSION_2] =
			conf->ciphersuite_list[TTLS_MINOR_VERSION_3] =
					 ttls_list_ciphersuites();

			conf->cert_profile = &ttls_x509_crt_profile_default;

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
			conf->sig_hashes = ssl_preset_default_hashes;
#endif

			conf->curve_list = ttls_ecp_grp_id_list();

#if defined(TTLS_DHM_C) && defined(TTLS_CLI_C)
			conf->dhm_min_bitlen = 1024;
#endif
	}

	return 0;
}

/*
 * Free ttls_config
 */
void ttls_config_free(ttls_config *conf)
{
#if defined(TTLS_DHM_C)
	ttls_mpi_free(&conf->dhm_P);
	ttls_mpi_free(&conf->dhm_G);
#endif

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	if (conf->psk != NULL)
	{
		bzero_fast(conf->psk, conf->psk_len);
		bzero_fast(conf->psk_identity, conf->psk_identity_len);
		ttls_free(conf->psk);
		ttls_free(conf->psk_identity);
		conf->psk_len = 0;
		conf->psk_identity_len = 0;
	}
#endif

	ssl_key_cert_free(conf->key_cert);

	bzero_fast(conf, sizeof(ttls_config));
}

/*
 * Convert between TTLS_PK_XXX and SSL_SIG_XXX
 */
unsigned char ttls_sig_from_pk(ttls_pk_context *pk)
{
	if (ttls_pk_can_do(pk, TTLS_PK_RSA))
		return(TTLS_SIG_RSA);
#if defined(TTLS_ECDSA_C)
	if (ttls_pk_can_do(pk, TTLS_PK_ECDSA))
		return(TTLS_SIG_ECDSA);
#endif
	return(TTLS_SIG_ANON);
}

unsigned char ttls_sig_from_pk_alg(ttls_pk_type_t type)
{
	switch(type) {
		case TTLS_PK_RSA:
			return(TTLS_SIG_RSA);
		case TTLS_PK_ECDSA:
		case TTLS_PK_ECKEY:
			return(TTLS_SIG_ECDSA);
		default:
			return(TTLS_SIG_ANON);
	}
}

ttls_pk_type_t ttls_pk_alg_from_sig(unsigned char sig)
{
	switch(sig)
	{
		case TTLS_SIG_RSA:
			return(TTLS_PK_RSA);
#if defined(TTLS_ECDSA_C)
		case TTLS_SIG_ECDSA:
			return(TTLS_PK_ECDSA);
#endif
		default:
			return(TTLS_PK_NONE);
	}
}

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
ttls_md_type_t ttls_sig_hash_set_find(ttls_sig_hash_set_t *set,
		 ttls_pk_type_t sig_alg)
{
	switch(sig_alg)
	{
		case TTLS_PK_RSA:
			return(set->rsa);
		case TTLS_PK_ECDSA:
			return(set->ecdsa);
		default:
			return(TTLS_MD_NONE);
	}
}

/* Add a signature-hash-pair to a signature-hash set */
void ttls_sig_hash_set_add(ttls_sig_hash_set_t *set,
		 ttls_pk_type_t sig_alg,
		 ttls_md_type_t md_alg)
{
	switch(sig_alg)
	{
		case TTLS_PK_RSA:
			if (set->rsa == TTLS_MD_NONE)
				set->rsa = md_alg;
			break;

		case TTLS_PK_ECDSA:
			if (set->ecdsa == TTLS_MD_NONE)
				set->ecdsa = md_alg;
			break;

		default:
			break;
	}
}

/* Allow exactly one hash algorithm for each signature. */
void ttls_sig_hash_set_const_hash(ttls_sig_hash_set_t *set,
		 ttls_md_type_t md_alg)
{
	set->rsa = md_alg;
	set->ecdsa = md_alg;
}

#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * Convert from TTLS_HASH_XXX to TTLS_MD_XXX
 */
ttls_md_type_t ttls_md_alg_from_hash(unsigned char hash)
{
	switch(hash)
	{
#if defined(TTLS_SHA256_C)
		case TTLS_HASH_SHA224:
			return(TTLS_MD_SHA224);
		case TTLS_HASH_SHA256:
			return(TTLS_MD_SHA256);
#endif
#if defined(TTLS_SHA512_C)
		case TTLS_HASH_SHA384:
			return(TTLS_MD_SHA384);
		case TTLS_HASH_SHA512:
			return(TTLS_MD_SHA512);
#endif
		default:
			return(TTLS_MD_NONE);
	}
}

/*
 * Convert from TTLS_MD_XXX to TTLS_HASH_XXX
 */
unsigned char ttls_hash_from_md_alg(int md)
{
	switch(md)
	{
#if defined(TTLS_SHA256_C)
		case TTLS_MD_SHA224:
			return(TTLS_HASH_SHA224);
		case TTLS_MD_SHA256:
			return(TTLS_HASH_SHA256);
#endif
#if defined(TTLS_SHA512_C)
		case TTLS_MD_SHA384:
			return(TTLS_HASH_SHA384);
		case TTLS_MD_SHA512:
			return(TTLS_HASH_SHA512);
#endif
		default:
			return(TTLS_HASH_NONE);
	}
}

/*
 * Check if a curve proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int ttls_check_curve(const ttls_context *tls, ttls_ecp_group_id grp_id)
{
	const ttls_ecp_group_id *gid;

	if (tls->conf->curve_list == NULL)
		return(-1);

	for (gid = tls->conf->curve_list; *gid != TTLS_ECP_DP_NONE; gid++)
		if (*gid == grp_id)
			return 0;

	return(-1);
}

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Check if a hash proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int ttls_check_sig_hash(const ttls_context *tls,
		ttls_md_type_t md)
{
	const int *cur;

	if (tls->conf->sig_hashes == NULL)
		return(-1);

	for (cur = tls->conf->sig_hashes; *cur != TTLS_MD_NONE; cur++)
		if (*cur == (int) md)
			return 0;

	return(-1);
}
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

int ttls_check_cert_usage(const ttls_x509_crt *cert,
		 const ttls_ciphersuite_t *ciphersuite,
		 int cert_endpoint,
		 uint32_t *flags)
{
	int r = 0;
#if defined(TTLS_X509_CHECK_KEY_USAGE)
	int usage = 0;
#endif
#if defined(TTLS_X509_CHECK_EXTENDED_KEY_USAGE)
	const char *ext_oid;
	size_t ext_len;
#endif

#if !defined(TTLS_X509_CHECK_KEY_USAGE) &&		 \
	!defined(TTLS_X509_CHECK_EXTENDED_KEY_USAGE)
	((void) cert);
	((void) cert_endpoint);
	((void) flags);
#endif

#if defined(TTLS_X509_CHECK_KEY_USAGE)
	if (cert_endpoint == TTLS_IS_SERVER)
	{
		/* Server part of the key exchange */
		switch(ciphersuite->key_exchange)
		{
			case TTLS_KEY_EXCHANGE_RSA:
			case TTLS_KEY_EXCHANGE_RSA_PSK:
				usage = TTLS_X509_KU_KEY_ENCIPHERMENT;
				break;

			case TTLS_KEY_EXCHANGE_DHE_RSA:
			case TTLS_KEY_EXCHANGE_ECDHE_RSA:
			case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
				usage = TTLS_X509_KU_DIGITAL_SIGNATURE;
				break;

			case TTLS_KEY_EXCHANGE_ECDH_RSA:
			case TTLS_KEY_EXCHANGE_ECDH_ECDSA:
				usage = TTLS_X509_KU_KEY_AGREEMENT;
				break;

			/* Don't use default: we want warnings when adding new values */
			case TTLS_KEY_EXCHANGE_NONE:
			case TTLS_KEY_EXCHANGE_PSK:
			case TTLS_KEY_EXCHANGE_DHE_PSK:
			case TTLS_KEY_EXCHANGE_ECDHE_PSK:
			case TTLS_KEY_EXCHANGE_ECJPAKE:
				usage = 0;
		}
	}
	else
	{
		/* Client auth: we only implement rsa_sign and ttls_ecdsa_sign for now */
		usage = TTLS_X509_KU_DIGITAL_SIGNATURE;
	}

	if (ttls_x509_crt_check_key_usage(cert, usage) != 0)
	{
		*flags |= TTLS_X509_BADCERT_KEY_USAGE;
		r = -1;
	}
#else
	((void) ciphersuite);
#endif /* TTLS_X509_CHECK_KEY_USAGE */

#if defined(TTLS_X509_CHECK_EXTENDED_KEY_USAGE)
	if (cert_endpoint == TTLS_IS_SERVER)
	{
		ext_oid = TTLS_OID_SERVER_AUTH;
		ext_len = TTLS_OID_SIZE(TTLS_OID_SERVER_AUTH);
	}
	else
	{
		ext_oid = TTLS_OID_CLIENT_AUTH;
		ext_len = TTLS_OID_SIZE(TTLS_OID_CLIENT_AUTH);
	}

	if (ttls_x509_crt_check_extended_key_usage(cert, ext_oid, ext_len) != 0)
	{
		*flags |= TTLS_X509_BADCERT_EXT_KEY_USAGE;
		r = -1;
	}
#endif /* TTLS_X509_CHECK_EXTENDED_KEY_USAGE */

	return r;
}

int ttls_set_calc_verify_md(ttls_context *tls, int md)
{
	if (tls->minor_ver != TTLS_MINOR_VERSION_3)
		return TTLS_ERR_INVALID_VERIFY_HASH;

	switch(md)
	{
#if defined(TTLS_SHA512_C)
		case TTLS_HASH_SHA384:
			tls->hs->calc_verify = ssl_calc_verify_tls_sha384;
			break;
#endif
#if defined(TTLS_SHA256_C)
		case TTLS_HASH_SHA256:
			tls->hs->calc_verify = ssl_calc_verify_tls_sha256;
			break;
#endif
		default:
			return TTLS_ERR_INVALID_VERIFY_HASH;
	}

	return 0;
}

int ttls_get_key_exchange_md_tls1_2(ttls_context *tls,
		unsigned char *output,
		unsigned char *data, size_t data_len,
		ttls_md_type_t md_alg)
{
	int r = 0;
	ttls_md_context_t ctx;
	const ttls_md_info_t *md_info = ttls_md_info_from_type(md_alg);

	ttls_md_init(&ctx);

	/*
	 * digitally-signed struct {
	 *	 opaque client_random[32];
	 *	 opaque server_random[32];
	 *	 ServerDHParams params;
	 * };
	 */
	if ((r = ttls_md_setup(&ctx, md_info, 0)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_md_setup", r);
		goto exit;
	}
	if ((r = ttls_md_starts(&ctx)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_md_starts", r);
		goto exit;
	}
	if ((r = ttls_md_update(&ctx, tls->hs->randbytes, 64)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_md_update", r);
		goto exit;
	}
	if ((r = ttls_md_update(&ctx, data, data_len)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_md_update", r);
		goto exit;
	}
	if ((r = ttls_md_finish(&ctx, output)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_md_finish", r);
		goto exit;
	}

exit:
	ttls_md_free(&ctx);

	if (r != 0)
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_INTERNAL_ERROR);

	return r;
}

static int __init
ttls_init(void)
{
	int r;

	/* Bad configuration - protected record payload too large. */
	BUILD_BUG_ON(TTLS_PAYLOAD_LEN > 16384 + 2048);

	if ((r = ttls_mpi_modinit()))
		return r;
	ttls_hs_cache = kmem_cache_create("ttls_hs_cache", sizeof(TlsHandshake),
					  0, 0, NULL);
	if (!ttls_hs_cache) {
		ttls_mpi_modexit();
		return -ENOMEM;
	}

	return 0;
}

static void
ttls_exit(void)
{
	ttls_mpi_modexit();
	kmem_cache_destroy(ttls_hs_cache);
}

module_init(ttls_init);
module_exit(ttls_exit);
