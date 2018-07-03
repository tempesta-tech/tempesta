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

static void
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
	if (i == ep_len)
		T_WARN("%s message counter would wrap\n", iod);
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

static int tls_prf_sha256(const unsigned char *secret, size_t slen,
		 const char *label,
		 const unsigned char *random, size_t rlen,
		 unsigned char *dstbuf, size_t dlen)
{
	return(tls_prf_generic(TTLS_MD_SHA256, secret, slen,
			 label, random, rlen, dstbuf, dlen));
}

static int tls_prf_sha384(const unsigned char *secret, size_t slen,
		 const char *label,
		 const unsigned char *random, size_t rlen,
		 unsigned char *dstbuf, size_t dlen)
{
	return(tls_prf_generic(TTLS_MD_SHA384, secret, slen,
			 label, random, rlen, dstbuf, dlen));
}

static void ssl_update_checksum_start(ttls_context *, const unsigned char *, size_t);

static void ssl_update_checksum_sha256(ttls_context *, const unsigned char *, size_t);
static void ssl_calc_verify_tls_sha256(ttls_context *,unsigned char *);
static void ssl_calc_finished_tls_sha256(ttls_context *,unsigned char *, int);
static void ssl_update_checksum_sha384(ttls_context *, const unsigned char *, size_t);
static void ssl_calc_verify_tls_sha384(ttls_context *, unsigned char *);
static void ssl_calc_finished_tls_sha384(ttls_context *, unsigned char *, int);

int
ttls_derive_keys(TlsCtx *tls) // TODO AK cipher suites
{
	unsigned char keyblk[256];
	unsigned char tmp[64];
	unsigned char *key1, *key2, *mac_enc, *mac_dec;
	const ttls_cipher_info_t *ci;
	const ttls_md_info_t *md_info;
	size_t mac_key_len, iv_copy_len;
	int r = 0;
	TlsSess *session = &tls->sess;
	TlsXfrm *transform = &tls->xfrm;
	TlsHandshake *hs = tls->hs;

	ci = ttls_cipher_info_from_type(transform->ciphersuite_info->cipher);
	if (!ci) {
		T_DBG("cipher info for %d not found\n",
		      transform->ciphersuite_info->cipher);
		return TTLS_ERR_BAD_INPUT_DATA;
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
	if (tls->minor == TTLS_MINOR_VERSION_3 &&
		transform->ciphersuite_info->mac == TTLS_MD_SHA384)
	{
		hs->tls_prf = tls_prf_sha384;
		hs->calc_verify = ssl_calc_verify_tls_sha384;
		hs->calc_finished = ssl_calc_finished_tls_sha384;
	}
	else
	if (tls->minor == TTLS_MINOR_VERSION_3)
	{
		hs->tls_prf = tls_prf_sha256;
		hs->calc_verify = ssl_calc_verify_tls_sha256;
		hs->calc_finished = ssl_calc_finished_tls_sha256;
	}
	else
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	/* master = PRF(premaster, "master secret", randbytes)[0..47] */
	if (hs->resume == 0)
	{
		TTLS_DEBUG_BUF(3, "premaster secret", hs->premaster,
		 hs->pmslen);

		if (tls->hs->extended_ms) {
			unsigned char session_hash[48];
			size_t hash_len;

			TTLS_DEBUG_MSG(3, ("using extended master secret"));

			tls->hs->calc_verify(tls, session_hash);

			if (tls->minor == TTLS_MINOR_VERSION_3)
			{
				if (tls->transform_negotiate->ciphersuite_info->mac ==
		TTLS_MD_SHA384)
				{
		hash_len = 48;
				}
				else
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
		else {
			r = hs->tls_prf(hs->premaster, hs->pmslen,
		 "master secret",
		 hs->randbytes, 64,
		 session->master, 48);
		}
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

	if (tls->minor >= TTLS_MINOR_VERSION_1)
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

void
ttls_read_version(TlsCtx *tls, const unsigned char ver[2])
{
#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM) {
		tls->major = 255 - ver[0] + 2;
		tls->minor = 255 - ver[1] + 1;
		if (tls->minor == TTLS_MINOR_VERSION_1)
			/* DTLS 1.0 stored as TLS 1.1 internally */
			++tls->minor;
	} else
#endif
	{
		tls->major = ver[0];
		tls->minor = ver[1];
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

	ttls_ep_check(&tls->io_in, "incomming");

	return 0;
}

/**
 * Send a TLS record.
 * The record is assembled from @tls->hdr of length @tls->io_out.msglen and
 * page fragments from @sgt.
 */
int
ttls_write_record(TlsCtx *tls, struct sg_table *sgt)
{
	int r, msg_len = io->msglen;
	TlsIOCtx *io = &tls->io_out;

	T_DBG("write record: type=%d len=%d\n", io->msgtype, io->msglen);

	if (io->msgtype == TTLS_MSG_HANDSHAKE) {
		int i, msg_type;

		BUG_ON(!sgt || !sgt->sg || sgt->nents < 1);
		msg_type = ((unsigned char *)sg_virt(sgt->sgl))[0];
		WARN_ON_ONCE(msg_type != TTLS_HS_HELLO_REQUEST && !tls->hs);

		if (msg_type != TTLS_HS_HELLO_REQUEST) {
			struct scatterlist *sg;

			for_each_sg(sgt->sgl, sg, sgt->nents, i) {
				tls->hs->update_checksum(tls,
				 sg_virt(sg),
				 sg->length);
				msg_len += sg->length;
			}
		}
	}

	/*
	 * Write TLS header if the record should not be encrypted.
	 * Otherwise sk_write_xmit() call back does this for us.
	 */
	if (!io->xfrm)
		ttls_write_hdr(tls, io->msgtype, msg_len, io->hdr);

	T_DBG3("output record: type=%d ver=%d:%d hdr_len=%d sgn=%u\n" ,
		io->hdr[0], io->hdr[1], io->hdr[2], io->msglen, sgt->nents);
	ttls_ep_check(&tls->io_out, "outgoing");

	if ((r = ttls_send_cb(tls, sgt)))
		T_DBG("TLS send callback error %d\n", r);
	return r;
}

static int
ttls_hdr_check(TlsCtx *tls)
{
	TlsIOCtx *io = &tls->io_in;

	/* Check record type */
	if (unlikely(io->msgtype < TTLS_MSG_CHANGE_CIPHER_SPEC
		     || io->msgtype > TTLS_MSG_APPLICATION_DATA))
	{
		T_DBG("unknown record type %d\n", io->msgtype);
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
	/*
	 * According to RFC 5246 Appendix E.1, the version in ClientHello is
	 * typically "{03,00}, the lowest version number supported by
	 * the client, [or] the value of ClientHello.client_version",
	 * so the only meaningful check here is the major version
	 * shouldn't be less than 3.
	 */
	if (tls->major < TTLS_MAJOR_VERSION_3) {
		T_DBG("bad major version %d\n", tls->major);
		return T_DROP;
	}
	if (unlikely(tls->minor > tls->conf->max_minor_ver)) {
		T_DBG("minor version mismatch %d\n", minor);
		return T_DROP;
	}
	/* Check length against the size of our buffer */
	if (unlikely(io->msglen > TTLS_PAYLOAD_LEN)) {
		T_DBG("bad message length %u\n", io->msglen);
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
 * Read TLS message header and IV or handshake header:
 *
 *	ContentType type;
 *	ProtocolVersion version;
 *	uint16 epoch;		(TLS only)
 *	uint48 sequence_number;	(DTLS only)
 *	uint16 length;
 *	[uint128 IV | alert | handshake header];
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
 */
static int
ttls_parse_record_hdr(TlsCtx *tls, unsigned char *buf, size_t len,
		      unsigned int *read)
{
	int r, hlen, ivahs_len, n = 0;
	TlsIOCtx *io = &tls->io_in;

	/* Read TLS message header, probably fragmented. */
	hlen = ttls_hdr_len(tls);
	if (unlikely(io->hdr_cpsz + len < hlen)) {
		memcpy(io->hdr + io->hdr_cpsz, buf, len);
		*read += len;
		io->hdr_cpsz += len;
		return T_POSTPONE;
	}
	if (io->hdr_cpsz < hlen) {
		n = hlen - io->hdr_cpsz;
		memcpy(io->hdr + io->hdr_ib_cpsz, buf, n);
		*read += n;
		io->hdr_cpsz += n;
	}

	io->msgtype = io->hdr[0];
	ttls_read_version(tls, io->hdr + 1);
	io->msglen = ((unsigned short)io->hdr[3] << 8) | io->hdr[4];
	T_DBG3("input rec: type=%d ver=%d:%d len=%d\n",
	       io->msgtype, tls->major, tls->minor, io->msglen);

	if ((r = ttls_hdr_check(tls)))
		return r;
	switch (io->msgtype) {
	case TTLS_MSG_APPLICATION_DATA:
		ivahs_len = TTLS_IV_LEN;
		break;
	case TTLS_MSG_ALERT:
		ivahs_len = 2; /* level & description */
		if (io->msglen < ivahs_ken) {
			T_DBG("alert message too short: %d\n", io->msglen);
			return TTLS_ERR_INVALID_RECORD;
		}
		break;
	case TTLS_MSG_HANDSHAKE:
		/*
		 * Read handshake header:
		 *
		 *   0 . 0   handshake type
		 *   1 . 3   handshake length
		 */
		ivahs_len = ttls_hs_hdr_len();
		if (io->msglen < ivahs_len) {
			T_DBG("handshake message too short: %d\n", io->msglen);
			return TTLS_ERR_INVALID_RECORD;
		}
		break;
	default:
		io->st_flags |= TTLS_F_ST_HDRIV;
		return T_OK;
	}

	/* Read [IV | alert | handshake header] (probably fragmented). */
	len -= n;
	if (unlikely(io->hdr_cpsz + len < hlen + iva_len)) {
		memcpy(io->iv + io->hdr_cpsz - hlen, buf + n, len);
		*read += len;
		io->hdr_cpsz += len;
		return T_POSTPONE;
	}
	iva_len -= io->hdr_cpsz - hlen;
	memcpy(io->iv + io->hdr_cpsz - hlen, buf + n, iva_len);
	*read += iva_len;
	io->hdr_cpsz = 0;
	io->st_flags |= TTLS_F_ST_HDRIV;

	if (io->msgtype == TTLS_MSG_HANDSHAKE) {
		io->hstype = io->hs_hdr[0];
		io->hslen = ttls_hs_hdr_len(tls)
			    + ((io->hs_hdr[1] << 16) | (io->hs_hdr[2] << 8)
				| io->hs_hdr[3]);
		T_DBG("handshake message: msglen=%d type=%d hslen=%d\n",
	      		io->msglen, io->hstype, io->hslen);
		/* With TLS we don't handle fragmentation (for now) */
		if (io->msglen < io->hslen) {
			T_DBG("TLS handshake fragmentation not supported\n");
			return TTLS_ERR_FEATURE_UNAVAILABLE;
		}
	}

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

	if (!tls->io_in.xfrm) // TODO AK always not-NULL!
		return 0;

	if ((r = ttls_decrypt_buf(tls))) {
		/* Error out (and send alert) on invalid records */
		if (r == TTLS_ERR_INVALID_MAC)
			ttls_send_alert_msg(tls,
		    TTLS_ALERT_LEVEL_FATAL,
		    TTLS_ALERT_MSG_BAD_RECORD_MAC);
		return r;
	}
	if (tls->io_in.msglen > TTLS_MAX_CONTENT_LEN) {
		T_DBG("bad message length %u\n", tls->io_in.msglen);
		return T_DROP;
	}

#if defined(TTLS_DTLS_ANTI_REPLAY)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_dtls_replay_update(tls);
#endif

	return 0;
}

void
ttls_handshake_free(TlsHandshake *hs)
{
	if (!hs)
		return;

	ttls_sha256_free(&hs->fin_sha256);
	ttls_sha512_free(&hs->fin_sha512);
	ttls_dhm_free(&hs->dhm_ctx);
	ttls_ecdh_free(&hs->ecdh_ctx);

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

void
ttls_handshake_wrapup(TlsCtx *tls)
{
	int resume = tls->hs->resume;

	/* Add cache entry. */
	if (tls->conf->f_set_cache && tls->session->id_len && !resume
	    && tls->conf->f_set_cache(tls->conf->p_cache, tls->session))
		T_DBG("cache did not store session\n");

	/* Free our hs params. */
	ttls_handshake_free(tls->hs);
	tls->hs = NULL;
}

/**
 * Process TLS alerts.
 */
int
ttls_handle_alert(TlsIOCtx *io)
{
	T_DBG("got an alert message, type=%d:%d\n", io->alert[0], io->alert[1]);

	/* Ignore non-fatal alerts, except close_notify and no_renegotiation. */
	if (io->alert[0] == TTLS_ALERT_LEVEL_FATAL) {
		T_DBG("is a fatal alert message (msg %d)\n", io->alert[1]);
		return TTLS_ERR_FATAL_ALERT_MESSAGE;
	}
	if (io->alert[0] == TTLS_ALERT_LEVEL_WARNING
	    && io->alert[1] == TTLS_ALERT_MSG_CLOSE_NOTIFY)
	{
		T_DBG("is a close notify message\n");
		return TTLS_ERR_PEER_CLOSE_NOTIFY;
	}

	/* Silently ignore: fetch new message */
	return TTLS_ERR_NON_FATAL;
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

	return ttls_write_record(tls, NULL);
}

int
ttls_write_certificate(TlsCtx *tls)
{
	int r = TTLS_ERR_FEATURE_UNAVAILABLE;
	size_t i, n, cn, tot_len, cn_max = MAX_SKB_FRAGS / 2 - 1;
	const ttls_x509_crt *crt;
	TlsIOCtx *io = &tls->io_out;
	unsigned char *p;
	struct scatterlist sg[MAX_SKB_FRAGS];
	struct sg_table sgt = {
		.sgl	= sg,
		.nents	= 1,
	};

#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT && !tls->client_auth) {
		TTLS_DEBUG_MSG(2, ("<= skip write certificate"));
		tls->state++;
		return 0;
	}
#endif

	if (tls->conf->endpoint == TTLS_IS_SERVER && !ttls_own_cert(tls)) {
		T_DBG("got no certificate to send\n");
		return TTLS_ERR_CERTIFICATE_REQUIRED;
	}

	p = pg_skb_alloc(128, GFP_ATOMIC, NUMA_NO_NODE);
	if (!meta)
		return -ENOMEM;
	sg_set_page(&sg[0], virt_to_page(p), 128, (unsigned long)p & ~PAGE_MASK);

	/*
	 *   0 . 0	handshake type
	 *   1 . 3	handshake length
	 *   4 . 6	length of all certs
	 *   7 . 9	length of cert. 1
	 *  10 . n-1	peer certificate
	 *   n . n+2	length of cert. 2
	 * n+3 . ...	upper level cert, etc.
	 */
	*p = TTLS_HS_CERTIFICATE;

	tot_len = i = 7;
	for (cn = 0, crt = ttls_own_cert(tls); crt; ) {
		n = crt->raw.len;
		if (n > TTLS_MAX_CONTENT_LEN - 3 - i) {
			T_WARN("certificate too large, %d > %d\n",
			       i + 3 + n, TTLS_MAX_CONTENT_LEN);
			return TTLS_ERR_CERTIFICATE_TOO_LARGE;
		}

		p[i++] = (unsigned char)(n >> 16);
		p[i++] = (unsigned char)(n >> 8);
		p[i++] = (unsigned char)n;

		tot_len += 3 + n;
		/* Certificates are stored in separate pages. */
		WARN_ON_ONCE((unsigned long)crt->raw.p & ~PAGE_MASK);
		sg_set_page(&sg[sgt.nents++], virt_to_page(crt->raw.p), n, 0);
		crt = crt->next;
		/*
		 * Use part of first sg as separate fragment with next cert
		 * length.
		 */
		if (crt && ++cn < cn_max)
			sg_set_page(&sg[sgt.nents++], virt_to_page(p), 3,
				    ((unsigned long)p & ~PAGE_MASK) + i);
	}
	if (crt)
		T_WARN("Can not write full certificates chain\n");

	p[1] = (unsigned char)((tot_len - 7 + 3) >> 16);
	p[2] = (unsigned char)((tot_len - 7 + 3) >> 8);
	p[3] = (unsigned char)(tot_len - 7 + 3);
	p[4] = (unsigned char)((tot_len - 7) >> 16);
	p[5] = (unsigned char)((tot_len - 7) >> 8);
	p[6] = (unsigned char)(tot_len - 7);
	tls->out_msglen = 0;
	io->msgtype = TTLS_MSG_HANDSHAKE;

	if ((r = ttls_write_record(tls, &sgt)))
		put_page(virt_to_page(p));

	return r;
}

int
ttls_parse_certificate(TlsCtx *tls, unsigned char *buf, size_t len,
		       unsigned int *read)
{
	uint8_t alert;
	int r = 0, i = 0, n, authmode;
	TlsIOCtx *io = &tls->io_in;
	TlsSess *sess = &tls->sess;
	struct page *pg;
	unsigned char *p;
	T_FSM_INIT(ttls_substate(tls), "TLS ClientCertificate");

	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);
	if (io->hstype != TTLS_HS_CERTIFICATE
	    || io->hslen < ttls_hs_hdr_len(tls) + 3 + 3)
	{
		T_DBG("bad certificate message length %d\n", io->hslen);
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CERTIFICATE;
	}

	authmode = (tls->hs->sni_authmode != TTLS_VERIFY_UNSET)
		   ? tls->hs->sni_authmode
		   : tls->conf->authmode;

	T_FSM_START(ttls_substate(tls)) {

	/*
	 * #830 currently we don't support client certificates validation,
	 * so just allocate a buffer to fit the data and parse it.
	 * Don't care about copies for now.
	 */
	T_FSM_STATE(TTLS_CC_HS_ALLOC) {
		pg = alloc_pages(GFP_ATOMIC, 2);
		if (!pg)
			return -ENOMEM;
		p = (unsigned char *)page_address(pg);
		*(long *)tls->hs->tmp = (long)p;
		T_FSM_JMP(TTLS_CC_HS_READ);
	}
	T_FSM_STATE(TTLS_CC_HS_READ) {
		p = (unsigned char *)(*(long *)tls->hs->tmp);
		n = min(io->hslen - io->rlen, len);
		memcpy_fast(p + io->rlen, buf, n);
		*read += n;
		io->rlen += n;
		if (io->rlen == io->hslen)
			T_FSM_JMP(TTLS_CC_HS_PARSE);
		return T_POSTPONE;
	}
	T_FSM_STATE(TTLS_CC_HS_PARSE) {
		p = (unsigned char *)(*(long *)tls->hs->tmp);
		goto parse:
	}

	}
	TTLS_HS_FSM_FINISH();
parse:

	if (tls->conf->endpoint == TTLS_IS_SERVER
	    && io->hslen == 3 + ttls_hs_hdr_len(tls)
	    && io->msgtype == TTLS_MSG_HANDSHAKE
	    && io->hstype == TTLS_HS_CERTIFICATE
	    && !memcmp(p, "\0\0\0", 3))
	{
		T_DBG("TLSv1 client has no certificate\n");

		/*
		 * The client was asked for a certificate but didn't send
		 * one. The client should know what's going on, so we don't
		 * send an alert.
		 */
		sess->verify_result = TTLS_X509_BADCERT_MISSING;
		if (authmode != TTLS_VERIFY_OPTIONAL)
			r = TTLS_ERR_NO_CLIENT_CERTIFICATE;
		goto err;
	}

	/* Same message structure as in ttls_write_certificate(). */
	n = (p[i + 1] << 8) | p[i + 2];

	if (p[i] != 0 || tls->in_hslen != n + 3 + ttls_hs_hdr_len(tls)) {
		T_DBG("bad certificate message\n");
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		r = TTLS_ERR_BAD_HS_CERTIFICATE;
		goto err;
	}

	/* In case we tried to reuse a session but it failed */
	if (sess->peer_cert) {
		ttls_x509_crt_free(sess->peer_cert);
		ttls_free(sess->peer_cert);
	}
	sess->peer_cert = kmalloc(sizeof(ttls_x509_crt), GFP_KERNEL);
	if (!sess->per_cert) {
		T_DBG("can npt allocacte a certificate (%d bytes)\n",
		      sizeof(ttls_x509_crt));
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_INTERNAL_ERROR);
		r = TTLS_ERR_ALLOC_FAILED;
		goto err;
	}

	ttls_x509_crt_init(sess->peer_cert);

	for (i += 3; i < tls->in_hslen; i += n) {
		if (p[i]) {
			T_DBG("bad certificate message\n");
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
		    TTLS_ALERT_MSG_DECODE_ERROR);
			r = TTLS_ERR_BAD_HS_CERTIFICATE;
			goto err;
		}

		n = ((unsigned int) p[i + 1] << 8) | (unsigned int) p[i + 2];
		i += 3;

		if (n < 128 || i + n > tls->in_hslen) {
			T_DBG("bad certificate message\n");
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
		    TTLS_ALERT_MSG_DECODE_ERROR);
			r = TTLS_ERR_BAD_HS_CERTIFICATE;
			goto err;
		}

		r = ttls_x509_crt_parse_der(sess->peer_cert, p + i, n);
		switch(r) {
		case 0: /*ok*/
		case TTLS_ERR_X509_UNKNOWN_SIG_ALG + TTLS_ERR_OID_NOT_FOUND:
			/*
			 * Ignore certificate with an unknown algorithm: maybe a
			 * prior certificate was already trusted.
			 */
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
			T_DBG("cannot parse DER certificate, %d\n", r);
			goto err;
		}
	}
	TTLS_DEBUG_CRT(3, "peer certificate", sess->peer_cert);

	if (authmode != TTLS_VERIFY_NONE) {
		const ttls_pk_context *pk = &sess->peer_cert->pk;
		ttls_x509_crt *ca_chain;
		ttls_x509_crl *ca_crl;

		if (tls->hs->sni_ca_chain) {
			ca_chain = tls->hs->sni_ca_chain;
			ca_crl = tls->hs->sni_ca_crl;
		} else {
			ca_chain = tls->conf->ca_chain;
			ca_crl = tls->conf->ca_crl;
		}

		/* Main check: verify certificate */
		r = ttls_x509_crt_verify_with_profile(sess->peer_cert, ca_chain,
			      ca_crl,
			      tls->conf->cert_profile,
			      tls->hostname,
			      &sess->verify_result,
			      tls->conf->f_vrfy,
			      tls->conf->p_vrfy);
		if (r)
			T_DBG("client cert verification status: %d\n", r);

		/*
		 * Secondary checks: always done, but change 'r' only if it was
		 * 0. If certificate uses an EC key, make sure the curve is OK.
		 */
		if (ttls_pk_can_do(pk, TTLS_PK_ECKEY)
		    && ttls_check_curve(tls, ttls_pk_ec(*pk)->grp.id))
		{
			sess->verify_result |= TTLS_X509_BADCERT_BAD_KEY;
			T_DBG("bad certificate (EC key curve)\n");
			if (!r)
				r = TTLS_ERR_BAD_HS_CERTIFICATE;
		}

		if (ttls_check_cert_usage(sess->peer_cert,
		  tls->xfrm.ciphersuite_info,
		  !tls->conf->endpoint,
		  &sess->verify_result))
		{
			T_DBG("bad certificate (usage extensions)\n");
			if (!r)
				r = TTLS_ERR_BAD_HS_CERTIFICATE;
		}

		/*
		 * ttls_x509_crt_verify_with_profile() is supposed to report a
		 * verification failure through TTLS_ERR_X509_CERT_VERIFY_FAILED,
		 * with details encoded in the verification flags. All other
		 * kinds of error codes, including those from the user provided
		 * f_vrfy functions, are treated as fatal and lead to a failure
		 * of ssl_parse_certificate even if verification was optional.
		 */
		if (authmode == TTLS_VERIFY_OPTIONAL
		    && (r == TTLS_ERR_X509_CERT_VERIFY_FAILED
			|| r == TTLS_ERR_BAD_HS_CERTIFICATE))
		{
			r = 0;
		}

		if (!ca_chain && authmode == TTLS_VERIFY_REQUIRED) {
			T_DBG("got no CA chain\n");
			r = TTLS_ERR_CA_CHAIN_REQUIRED;
		}

		if (r) {
			/*
			 * The certificate may have been rejected for several
			 * reasons. Pick one and send the corresponding alert.
			 * Which alert to send may be a subject of debate in
			 * some cases.
			 */
			unsigned int vr = sess->verify_result;
			T_DBG3("Certificate verification flags %x\n", vr);
			if (vr & TTLS_X509_BADCERT_OTHER)
				alert = TTLS_ALERT_MSG_ACCESS_DENIED;
			else if (vr & TTLS_X509_BADCERT_CN_MISMATCH)
				alert = TTLS_ALERT_MSG_BAD_CERT;
			else if (vr & TTLS_X509_BADCERT_KEY_USAGE)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (vr & TTLS_X509_BADCERT_EXT_KEY_USAGE)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (vr & TTLS_X509_BADCERT_NS_CERT_TYPE)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (vr & TTLS_X509_BADCERT_BAD_PK)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (vr & TTLS_X509_BADCERT_BAD_KEY)
				alert = TTLS_ALERT_MSG_UNSUPPORTED_CERT;
			else if (vr & TTLS_X509_BADCERT_EXPIRED)
				alert = TTLS_ALERT_MSG_CERT_EXPIRED;
			else if (vr & TTLS_X509_BADCERT_REVOKED)
				alert = TTLS_ALERT_MSG_CERT_REVOKED;
			else if (vr & TTLS_X509_BADCERT_NOT_TRUSTED)
				alert = TTLS_ALERT_MSG_UNKNOWN_CA;
			else
				alert = TTLS_ALERT_MSG_CERT_UNKNOWN;
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
		    alert);
		}
	}
err:
	__free_pages(virt_to_page(p), 2);
	return r;
}

int
ttls_write_change_cipher_spec(ttls_context *tls)
{
	TlsIOCtx *io = &tls->io_out;

	io->msgtype = TTLS_MSG_CHANGE_CIPHER_SPEC;
	io->msglen = 1;
	io->hs_hdr[0] = 1;

	return ttls_write_record(tls, NULL);
}

int
ttls_parse_change_cipher_spec(ttls_context *tls, unsigned char *buf, size_t len,
			      unsigned int *read)
{
	TlsIOCtx *io = &tls->io_in;

	if (io->msgtype != TTLS_MSG_CHANGE_CIPHER_SPEC) {
		T_DBG("bad change cipher spec message type %u\n", io->msgtype);
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return TTLS_ERR_UNEXPECTED_MESSAGE;
	}
	if (io->msglen != 1 || io->hstype != 1) {
		T_DBG("bad change cipher spec message, len=%u type=%u\n",
		      io->msglen, io->hstype);
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC;
	}

	bzero_fast(io->ctr, 8);

	return 0;
}

void
ttls_optimize_checksum(TlsCtx *tls, const ttls_ciphersuite_t *ciphersuite_info)
{
	if (ciphersuite_info->mac == TTLS_MD_SHA384)
		tls->hs->update_checksum = ssl_update_checksum_sha384;
	else
		tls->hs->update_checksum = ssl_update_checksum_sha256;
}

void ttls_reset_checksum(ttls_context *tls)
{
	ttls_sha256_starts_ret(&tls->hs->fin_sha256, 0);
	ttls_sha512_starts_ret(&tls->hs->fin_sha512, 1);
}

static void ssl_update_checksum_start(ttls_context *tls,
			 const unsigned char *buf, size_t len)
{
	ttls_sha256_update_ret(&tls->hs->fin_sha256, buf, len);
	ttls_sha512_update_ret(&tls->hs->fin_sha512, buf, len);
}

static void ssl_update_checksum_sha256(ttls_context *tls,
			const unsigned char *buf, size_t len)
{
	ttls_sha256_update_ret(&tls->hs->fin_sha256, buf, len);
}

static void ssl_update_checksum_sha384(ttls_context *tls,
			const unsigned char *buf, size_t len)
{
	ttls_sha512_update_ret(&tls->hs->fin_sha512, buf, len);
}

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

int
ttls_write_finished(TlsCtx *tls)
{
	int r;
	TlsIOCtx *io = &tls->io_out;

	BUILD_BUG_ON(TTLS_IV_LEN < TLS_MAX_HASH_LEN + 4);

	tls->hs->calc_finished(tls, &tls->__msg[4], tls->conf->endpoint);

	io->msgtype = TTLS_MSG_HANDSHAKE;
	io->msglen = 4 + TLS_MAX_HASH_LEN;
	io->hs_hdr[0] = TTLS_HS_FINISHED;
	bzero_fast(&io->hs_hdr[1], 3);

	bzero_fast(io->ctr, 8);

	return ttls_write_record(tls, NULL);
}

int
ttls_parse_finished(TlsCtx *tls, unsigned char *buf, size_t len,
		    unsigned int *read)
{
	int r;
	unsigned int hash_len = TLS_MAX_HASH_LEN;
	TlsIOCtx *io = &tls->io_in;
	unsigned char hash[SSL_MAX_HASH_LEN];

	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);
	if (io->hstype != TTLS_HS_FINISHED || io->hslen != hash_len
	    || len < io->hslen) /* TODO process chunked data */
	{
		T_DBG("bad finished message, type=%u len=%u chunk_len=%lu\n",
		      io->hstype, io->hslen, len);
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_FINISHED;
	}

	tls->hs->calc_finished(tls, hash, tls->conf->endpoint ^ 1);
	if (crypto_memneq(buf, hash, hash_len)) {
		T_DBG("bad hash in finished message\n");
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_FINISHED;
	}

#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_recv_flight_completed(tls);
#endif

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
	ttls_sig_hash_set_init(&hs->hash_algs);

#if defined(TTLS_DHM_C)
	ttls_dhm_init(&hs->dhm_ctx);
#endif
#if defined(TTLS_ECDH_C)
	ttls_ecdh_init(&hs->ecdh_ctx);
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

/*
 * Set allowed/preferred hashes for hs signatures
 */
void ttls_conf_sig_hashes(ttls_config *conf,
		const int *hashes)
{
	conf->sig_hashes = hashes;
}

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

void ttls_conf_cert_req_ca_list(ttls_config *conf,
		char cert_req_ca_list)
{
	conf->cert_req_ca_list = cert_req_ca_list;
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
ttls_handshake(TlsCtx *tls, unsigned char *buf, size_t len, unsigned int *read)
{
	int r = 0;
	TlsIOCtx *io = &tls->io_in;

	T_DBG3("handshake message %u on state %d\n", io->msgtype, tls->state);

#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT)
		return ttls_handshake_client_step(tls, buf, len, read);
	else
#endif
	return ttls_handshake_server_step(tls, buf, len, read);
}

/**
 * Main TLS receive routine.
 *
 * Read a record, only one. A caller will call us again if a following record,
 * or it's part, is left in @buf.
 *
 * Silently ignore non-fatal alert (and for DTLS, invalid records as well,
 * RFC 6347 4.1.2.7) and continue reading until a valid record is found.
 *
 * @buf and @len defines a chunk of ingress network data, probably containing
 * parts of several TLS messages, e.g. a tail of last message, a short full
 * message and a begin of a next message.
 *
 * @return T_POSTPONE if there is no ready data for upper layer (e.g. during
 * handshake or current record isn't fully read) and T_PASS if a record is ready
 * for upper layer protocol processing. Other negative values are returned on
 * errors.
 * The function adds the number of bytes parsed in @buf to @read.
 */
int
ttls_recv(void *tls_data, unsigned char *buf, size_t len, unsigned int *read)
{
	int r;
	unsigned int parsed = *read;
	TlsCtx *tls = (TlsCtx *)tls_data;
	TlsIOCtx *io = &tls->io_in;

	BUG_ON(!tls || !tls->conf);
	T_DBG3("%s: len=%lu read=%u\n", __func__, len, *read);

next_record:
	if (!(io->st_flags & TTLS_F_ST_HDRIV))
		if ((r = ttls_parse_record_hdr(tls, buf, len, read)))
			return r;
	WARN_ON_ONCE(!io->msglen);
	parsed = *read - parsed;
	if (parsed == len)
		return TFW_POSTPONE;
	len -= parsed;
	buf += parsed;

	/*
	 * Current record is fully read and decrypted if necessary.
	 * Skip alerts and empty records and read a next one.
	 */
	switch (io->msgtype) {
	case TTLS_MSG_ALERT:
		r = ttls_handle_alert(io);
		if (r == TTLS_ERR_NON_FATAL)
			goto skip_record;
		return r;
	case TTLS_MSG_CHANGE_CIPHER_SPEC:
		/* Parsed as part of handshake FSM. */
	case TTLS_MSG_HANDSHAKE:
		if (tls->state == TTLS_HANDSHAKE_OVER) {
			T_DBG("refusing renegotiation, sending alert\n");
			ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_WARNING,
					    TTLS_ALERT_MSG_NO_RENEGOTIATION);
			return TTLS_ERR_UNEXPECTED_MESSAGE;
		}
		if (tls->state != TTLS_HANDSHAKE_OVER
		    && tls->state != TTLS_CERTIFICATE_VERIFY
		    && tls->hs)
		{
			tls->hs->update_checksum(tls, buf, len);
		}
		if ((r = ttls_handshake(tls, buf, len, read))) {
			if (r != T_POSTPONE)
				T_DBG("handshake error: %d\n", r);
			return r;
		}
		break;
	case TTLS_MSG_APPLICATION_DATA:
		if (!io->msglen) {
			/* OpenSSL sends empty messages to randomize the IV. */
			T_DBG("empty application TLS record - skip\n");
			goto skip_record;
		}
		if (io->msglen > io->rlen + len) {
			*read += len;
			io->rlen += len;
			return T_POSTPONE;
		}
		*read += io->msglen - io->rlen;
		if ((r = ttls_prepare_record_content(tls)))
			return r;
		/* Fall throught. */
	}

	/*
	 * At this point we have fully prepared data for the upper layer.
	 * Once we return the data is passed for processing to the upper layer,
	 * so we reinitialize I/O context for a next message.
	 */
	bzero_fast(io->__init_start,
		   sizeof(*io) - offsetof(TlsIOCtx, __init_start));

	return T_PASS;
skip_record:
	bzero_fast(io->__init_start,
		   sizeof(*io) - offsetof(TlsIOCtx, __init_start));
	if (len)
		goto next_record;
	return T_POSTPONE;
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
	size_t max_len = TTLS_MAX_CONTENT_LEN;
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
	BUG_ON(!tls || !tls->conf);
	T_DBG3("write close notify\n");

	if (tls->state != TTLS_HANDSHAKE_OVER)
		return 0;
	return ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_WARNING,
				   TTLS_ALERT_MSG_CLOSE_NOTIFY);
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

#if defined(TTLS_CLI_C)
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

		kmem_cache_free(ttls_hs_cache, tls->hs);
		ttls_free(tls->transform_negotiate);
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

static int ssl_preset_default_hashes[] = {
	TTLS_MD_SHA512,
	TTLS_MD_SHA384,
	TTLS_MD_SHA256,
	TTLS_MD_SHA224,
	TTLS_MD_NONE
};

static int ssl_preset_suiteb_ciphersuites[] = {
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	0
};

static int ssl_preset_suiteb_hashes[] = {
	TTLS_MD_SHA256,
	TTLS_MD_SHA384,
	TTLS_MD_NONE
};

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

	conf->cert_req_ca_list = 1;

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
			conf->sig_hashes = ssl_preset_suiteb_hashes;
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
			conf->sig_hashes = ssl_preset_default_hashes;
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

/**
 * Add a signature-hash-pair to a signature-hash set/
 */
void
ttls_sig_hash_set_add(ttls_sig_hash_set_t *set, ttls_pk_type_t sig_alg,
		      ttls_md_type_t md_alg)
{
	switch (sig_alg) {
		case TTLS_PK_RSA:
			if (set->rsa == TTLS_MD_NONE)
				set->rsa = md_alg;
			break;
		case TTLS_PK_ECDSA:
			if (set->ecdsa == TTLS_MD_NONE)
				set->ecdsa = md_alg;
			break;
	}
}

/**
 * Allow exactly one hash algorithm for each signature.
 */
void
ttls_sig_hash_set_const_hash(ttls_sig_hash_set_t *set, ttls_md_type_t md_alg)
{
	set->rsa = md_alg;
	set->ecdsa = md_alg;
}

/**
 * Convert from TTLS_HASH_XXX to TTLS_MD_XXX.
 */
ttls_md_type_t
ttls_md_alg_from_hash(unsigned char hash)
{
	switch (hash) {
		case TTLS_HASH_SHA224:
			return TTLS_MD_SHA224;
		case TTLS_HASH_SHA256:
			return TTLS_MD_SHA256;
		case TTLS_HASH_SHA384:
			return TTLS_MD_SHA384;
		case TTLS_HASH_SHA512:
			return TTLS_MD_SHA512;
		default:
			return TTLS_MD_NONE;
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

/**
 * Check if a hash proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int
ttls_check_sig_hash(const TlsCtx *tls, ttls_md_type_t md)
{
	const int *cur;

	if (!tls->conf->sig_hashes)
		return -1;

	for (cur = tls->conf->sig_hashes; *cur != TTLS_MD_NONE; cur++)
		if (*cur == (int)md)
			return 0;

	return -1;
}
	
/*
 * If there is no signature-algorithm extension present in ClientHello,
 * we need to fall back to the default values for allowed  signature-hash pairs.
 */
void
ttls_set_default_sig_hash(TlsCtx *tls)
{
	ttls_sig_hash_set_t *ha = &tls->hs->hash_algs;

	if (ha->rsa == TTLS_MD_NONE && ha->ecdsa == TTLS_MD_NONE) {
		/*
		 * Try to fall back to default hash SHA1 if the client
		 * hasn't provided any preferred signature-hash combinations.
		 */
		if (!ttls_check_sig_hash(tls, TTLS_MD_SHA256))
			ttls_sig_hash_set_const_hash(ha, TTLS_MD_SHA256);
	}
}

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
	if (tls->minor != TTLS_MINOR_VERSION_3)
		return TTLS_ERR_INVALID_VERIFY_HASH;

	switch(md)
	{
		case TTLS_HASH_SHA384:
			tls->hs->calc_verify = ssl_calc_verify_tls_sha384;
			break;
		case TTLS_HASH_SHA256:
			tls->hs->calc_verify = ssl_calc_verify_tls_sha256;
			break;
		default:
			return TTLS_ERR_INVALID_VERIFY_HASH;
	}

	return 0;
}

int
ttls_get_key_exchange_md_tls1_2(TlsCtx *tls, unsigned char *output,
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
	if ((r = ttls_md_setup(&ctx, md_info, 0))) {
		T_DBG("cannot setup digest context, %d\n", r);
		goto exit;
	}
	if ((r = ttls_md_starts(&ctx))) {
		T_DBG("cannot start digest context, %d\n", r);
		goto exit;
	}
	if ((r = ttls_md_update(&ctx, tls->hs->randbytes, 64))) {
		T_DBG("cannot update digest context for random, %d\n", r);
		goto exit;
	}
	if ((r = ttls_md_update(&ctx, data, data_len))) {
		T_DBG("cannot update digest context for data, %d\n", r);
		goto exit;
	}
	if ((r = ttls_md_finish(&ctx, output))) {
		T_DBG("cannot finish digest context, %d\n", r);
		goto exit;
	}

exit:
	ttls_md_free(&ctx);
	if (r != 0)
		ttls_send_alert_msg(tls, TTLS_ALERT_LEVEL_FATAL,
				    TLS_ALERT_MSG_INTERNAL_ERROR);
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
