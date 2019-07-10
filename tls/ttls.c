/*
 *		Tempesta TLS
 *
 * Main TLS shared functions for the server and client.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include <linux/types.h>
#include <asm/fpu/api.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <linux/module.h>
#include <net/tls.h>

#include "lib/str.h"
#include "config.h"
#include "debug.h"
#include "crypto.h"
#include "oid.h"
#include "tls_internal.h"
#include "ttls.h"

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta TLS");
MODULE_VERSION("0.2.4");
MODULE_LICENSE("GPL");

static DEFINE_PER_CPU(struct aead_request *, g_req) ____cacheline_aligned;

static struct kmem_cache *ttls_hs_cache = NULL;
static ttls_send_cb_t *ttls_send_cb;

static inline unsigned short
ttls_msg2crypt_len(const TlsIOCtx *io, const TlsXfrm *xfrm)
{
	return io->msglen - ttls_expiv_len(xfrm) - ttls_xfrm_taglen(xfrm);
}

static void
ttls_write_hdr(const TlsCtx *tls, unsigned char type, unsigned short len,
	       unsigned char *buf)
{
	buf[0] = type;
	ttls_write_version(tls, buf + 1);
	buf[3] = (unsigned char)(len >> 8);
	buf[4] = (unsigned char)len;

	T_DBG3("use record hdr: type=%d ver=%d:%d hdr_len=%d\n",
	       buf[0], buf[1], buf[2], ntohs(*(short *)(buf + 3)));
}

void
ttls_write_hshdr(unsigned char type, unsigned char *buf, unsigned short len)
{
	/*
	 * 0 . 0   handshake type
	 * 1 . 3   handshake length
	 */
	buf[0] = type;
	buf[1] = (unsigned char)((len - TTLS_HS_HDR_LEN) >> 16);
	buf[2] = (unsigned char)((len - TTLS_HS_HDR_LEN) >> 8);
	buf[3] = (unsigned char)(len - TTLS_HS_HDR_LEN);
	T_DBG3_BUF("Write handshake header", buf, TTLS_HS_HDR_LEN);
}

/**
 * Someway TLS AAD is `IV | tls_hdr`, so the function reorders IV and TLS
 * header in @buf, so it can be transmitter to network.
 */
void
ttls_aad2hdriv(TlsXfrm *xfrm, unsigned char *buf)
{
	unsigned short len, ivlen = ttls_expiv_len(xfrm);
	long iv = *(long *)buf;

	memmove(buf, buf + ivlen, TLS_HEADER_SIZE);
	*(long *)(buf + TLS_HEADER_SIZE) = iv;

	/*
	 * The generated AAD contains length of the plaintext, so add IV and
	 * TAG to the final record payload length.
	 */
	len = ((unsigned short)buf[3] << 8) + buf[4];
	len += ttls_expiv_len(xfrm) + ttls_xfrm_taglen(xfrm);
	buf[3] = (unsigned char)(len >> 8);
	buf[4] = (unsigned char)len;

	T_DBG3("write record hdr from AAD: type=%d ver=%d:%d hdr_len=%d\n",
	       buf[0], buf[1], buf[2], ntohs(*(short *)(buf + 3)));
}
EXPORT_SYMBOL(ttls_aad2hdriv);

/**
 * Called to build crypto request with scatterlist acceptable by the crypto
 * layer from collected skbs when TLS sees the end of current message or
 * @buf of length @len if it's non-NULL.
 *
 * @len - total length of the message data to be sent to crypto framework.
 * @sg	- pointer to allocated scatterlist;
 * @sgn - as ingress argument contains number of required additional segments
 *	  and returns number of chunks in the scatter list.
 */
static struct aead_request *
ttls_crypto_req_sglist(TlsCtx *tls, struct crypto_aead *tfm, unsigned int len,
		       unsigned char *buf, struct scatterlist **sg,
		       unsigned int *sgn)
{
	TlsIOCtx *io = &tls->io_in;
	struct scatterlist *sg_i;
	struct aead_request *req;
	struct sk_buff *skb = io->skb_list;
	unsigned int sz, aead_sz, to_read, off;
	int n;

	sz = aead_sz = sizeof(*req) + crypto_aead_reqsize(tfm);
	if (buf) {
		off = 0;
		n = *sgn + 1;
	} else {
		off = io->off;
		n = *sgn + io->chunks;
	}
	BUG_ON(!buf && (!skb || skb->len <= off)); /* nothing to decrypt */
	sz += n * sizeof(**sg);

	/* Don't use g_req for better spacial locality. */
	req = kmalloc(sz, GFP_ATOMIC);
	if (!req)
		return NULL;
	*sg = (struct scatterlist *)((char *)req + aead_sz);
	sg_init_table(*sg, n);
	sg_i = *sg + *sgn;

	if (buf) {
		sg_set_buf(sg_i++, buf, len);
	} else {
		/* The extra segments are allocated on the head. */
		for ( ; skb;
		     skb = (skb->next != io->skb_list) ? skb->next : NULL)
		{
			T_DBG3("build req sglist: skb=%pK next=%pK len=%u"
			       " off=%u\n", skb, skb->next, skb->len, off);
			if (unlikely(off >= skb->len)) {
				off -= skb->len;
				continue;
			}
			to_read = min(len, skb->len - off);
			n = skb_to_sgvec(skb, sg_i, off, to_read);
			if (n <= 0)
				goto err;
			sg_unmark_end(sg_i + n - 1);
			T_DBG3_SL("build req sglist", sg_i, n, 0, (size_t)len);
			len -= to_read;
			sg_i += n;
			if (WARN_ON_ONCE(sg_i > *sg + *sgn + io->chunks))
				goto err;
			off = 0;
		}
	}

	*sgn = sg_i - *sg;
	sg_mark_end(*sg + *sgn - 1);

	T_DBG3("%s: skb=%pK buf=%pK sg=%pK off=%u len=%u sgn=%u\n",
	       __func__, skb, buf, *sg, off, len, *sgn);

	return req;
err:
	kfree(req);
	return NULL;
}

/**
 * Extract alert body, from the decrypted skb chain.
 */
static int
ttls_skb_extract_alert(TlsIOCtx *io, TlsXfrm *xfrm)
{
	size_t n, copied = 0, off = ttls_payload_off(xfrm);
	struct sk_buff *skb = io->skb_list;

	for ( ; skb && copied != TTLS_ALERT_LEN; skb = skb->next) {
		if (unlikely(skb->len <= off)) {
			off -= skb->len;
			continue;
		}
		n = min(skb->len - off, TTLS_ALERT_LEN - copied);
		if (skb_copy_bits(skb, off, &io->alert[copied], n))
			return T_DROP;
		copied += n;
	}

	return skb ? 0 : T_DROP;
}

/**
 * Register I/O callbacks from the underlying network layer.
 */
void
ttls_register_bio(ttls_send_cb_t *send_cb)
{
	ttls_send_cb = send_cb;
}
EXPORT_SYMBOL(ttls_register_bio);

/**
 * Whether TLS context transformation is ready for crypto and we should encrypt
 * egress data and decrypt ingress data.
 * The first encrypted record is the record sent by a client just after
 * ChangeCipherSpec record in handshake. TTLS_CLIENT_FINISHED is the first
 * state after TTLS_MSG_CHANGE_CIPHER_SPEC, so we check it here to learn the
 * context state.
 */
bool
ttls_xfrm_ready(TlsCtx *tls)
{
	return tls->state >= TTLS_CLIENT_FINISHED
	       && tls->state != TTLS_SERVER_CHANGE_CIPHER_SPEC;
}
EXPORT_SYMBOL(ttls_xfrm_ready);

#if defined(TTLS_CLI_C)
static int
ssl_session_copy(TlsSess *dst, const TlsSess *src)
{
	memcpy_fast(dst, src, sizeof(TlsSess));

	if (src->peer_cert) {
		int r;

		dst->peer_cert = ttls_calloc(1, sizeof(ttls_x509_crt));
		if (dst->peer_cert == NULL)
			return(TTLS_ERR_ALLOC_FAILED);

		ttls_x509_crt_init(dst->peer_cert);

		r = ttls_x509_crt_parse_der(dst->peer_cert,
					    src->peer_cert->raw.p,
					    src->peer_cert->raw.len);
		if (r) {
			ttls_free(dst->peer_cert);
			dst->peer_cert = NULL;
			return r;
		}
	}

#if defined(TTLS_SESSION_TICKETS) && defined(TTLS_CLI_C)
	if (src->ticket) {
		dst->ticket = ttls_calloc(1, src->ticket_len);
		if (!dst->ticket)
			return TTLS_ERR_ALLOC_FAILED;

		memcpy_fast(dst->ticket, src->ticket, src->ticket_len);
	}
#endif

	return 0;
}
#endif

/*
 * Key material generation.
 * Pseudo-random function (PRF) in sense of TLS 1.1 (RFC 4346) was replaced
 * with cipher-suite-specified hashes.
 */
static int
tls_prf_generic(ttls_md_type_t md_type, const unsigned char *secret,
		size_t slen, const char *label, size_t llen,
		const unsigned char *random, size_t rlen,
		unsigned char *dstbuf, size_t dlen)
{
	int r;
	size_t i, k, md_len;
	const TlsMdInfo *md_info;
	TlsMdCtx md_ctx;
	unsigned char __buf[TTLS_MD_MAX_SIZE * 3] ____cacheline_aligned;
	unsigned char *tmp = __buf, *h_i = &__buf[TTLS_MD_MAX_SIZE * 2];

	if (!(md_info = ttls_md_info_from_type(md_type)))
		return TTLS_ERR_INTERNAL_ERROR;

	ttls_md_init(&md_ctx);

	md_len = ttls_md_get_size(md_info);
	if (TTLS_MD_MAX_SIZE * 2 < md_len + llen + rlen)
		return TTLS_ERR_BAD_INPUT_DATA;

	memcpy_fast(tmp + md_len, label, llen);
	memcpy_fast(tmp + md_len + llen, random, rlen);
	llen += rlen;

	/* Compute P_<hash>(secret, label + random)[0..dlen]. */
	if ((r = ttls_md_setup(&md_ctx, md_info, 1)))
		return r;

	ttls_md_hmac_starts(&md_ctx, secret, slen);
	ttls_md_hmac_update(&md_ctx, tmp + md_len, llen);
	ttls_md_hmac_finish(&md_ctx, tmp);

	for (i = 0; i < dlen; i += md_len) {
		ttls_md_hmac_reset(&md_ctx);
		ttls_md_hmac_update(&md_ctx, tmp, md_len + llen);
		ttls_md_hmac_finish(&md_ctx, h_i);

		ttls_md_hmac_reset(&md_ctx);
		ttls_md_hmac_update(&md_ctx, tmp, md_len);
		ttls_md_hmac_finish(&md_ctx, tmp);

		k = (i + md_len > dlen) ? dlen % md_len : md_len;
		memcpy_fast(dstbuf + i, h_i, k);
	}

	ttls_md_free(&md_ctx);
	bzero_fast(__buf, TTLS_MD_MAX_SIZE * 3);

	return 0;
}

static int
tls_prf_sha256(const unsigned char *secret, size_t slen, const char *label,
	       size_t llen, const unsigned char *random, size_t rlen,
	       unsigned char *dstbuf, size_t dlen)
{
	return tls_prf_generic(TTLS_MD_SHA256, secret, slen, label, llen,
			       random, rlen, dstbuf, dlen);
}

static int
tls_prf_sha384(const unsigned char *secret, size_t slen, const char *label,
	       size_t llen, const unsigned char *random, size_t rlen,
	       unsigned char *dstbuf, size_t dlen)
{
	return tls_prf_generic(TTLS_MD_SHA384, secret, slen, label, llen,
			       random, rlen, dstbuf, dlen);
}

void
ttls_update_checksum(TlsCtx *tls, const unsigned char *buf, size_t len)
{
	int r;
	TlsHandshake *hs = tls->hs;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;
	ttls_md_type_t mac;

	if (unlikely(!len))
		return;

	/*
	 * Initialize the hash context on first call to avoid double
	 * hash calculation.
	 *
	 * We may find empty ciphersuite_info here only if we process a part of
	 * ClientHello message, when we hadn't read the extension yet. If so,
	 * then do a trick: compute both the checksums for the chunk and use
	 * hs->ecdh_ctx to store SHA256 checksum data.
	 */
	if (unlikely(IS_ERR_OR_NULL(ci))) {
		ttls_sha256_context *sha256 = &hs->tmp_sha256;
		WARN_ON_ONCE(tls->state >= TTLS_SERVER_HELLO);
		BUILD_BUG_ON(sizeof(ttls_ecdh_context)
			     < sizeof(ttls_sha256_context));

		if (!ci) {
			if (WARN_ON_ONCE(ttls_sha256_init_start(sha256)))
				return;
			tls->xfrm.ciphersuite_info = ERR_PTR(-1);
		}
		r = crypto_shash_update((struct shash_desc *)sha256, buf, len);
		if (WARN_ON_ONCE(r))
			return;
		mac = TTLS_MD_SHA384;
	} else {
		mac = ci->mac;
		/*
		 * This is, after ttls_choose_ciphersuite() call but still at
		 * ClientHello state, the earliest time when we know which hash
		 * function to use. If the hash context is initialized, then
		 * there were ClientHello chunks and probably we need to copy
		 * the hash context.
		 */
		if (unlikely(tls->state < TTLS_SERVER_HELLO && hs->desc.tfm
			     && mac == TTLS_MD_SHA256))
		{
			ttls_sha256_context *sha256 = &hs->tmp_sha256;
			crypto_free_shash(hs->desc.tfm);
			memcpy_fast(&tls->hs->fin_sha256, sha256,
				    sizeof(*sha256));
		}
	}
	if (unlikely(!hs->desc.tfm)) {
		if (mac == TTLS_MD_SHA384)
			r = ttls_sha384_init_start(&hs->fin_sha512);
		else
			r = ttls_sha256_init_start(&hs->fin_sha256);
		if (WARN_ON_ONCE(r))
			return;
	}

	T_DBG2("update checksum on buf %pK len=%ld, hash=%d\n",
	       buf, len, mac);
	T_DBG3_BUF("hash buf ", buf, len);

	WARN_ON_ONCE(crypto_shash_update(&tls->hs->desc, buf, len));
}

static void
ttls_calc_verify_tls_sha256(TlsCtx *tls, unsigned char hash[32])
{
	ttls_sha256_context sha256;

	memcpy_fast(&sha256, &tls->hs->fin_sha256, sizeof(sha256));
	crypto_shash_final(&sha256.desc, hash);

	T_DBG3_BUF("calculated verify sha256 result", hash, 32);

	bzero_fast(&sha256, sizeof(sha256));
}

static void
ttls_calc_verify_tls_sha384(TlsCtx *tls, unsigned char hash[48])
{
	ttls_sha512_context sha512;

	memcpy_fast(&sha512, &tls->hs->fin_sha512, sizeof(sha512));
	crypto_shash_final(&sha512.desc, hash);

	T_DBG3_BUF("calculated verify sha384 result", hash, 48);

	bzero_fast(&sha512, sizeof(sha512));
}

#define TTLS_PRF(hs, sec, slen, lbl, rnd, rlen, buf, blen)		\
({									\
	BUILD_BUG_ON(!__builtin_constant_p(lbl));			\
	(hs)->tls_prf(sec, slen, lbl, sizeof(lbl) - 1, rnd, rlen, buf, blen);\
})

static void
ttls_calc_finished_tls_sha256(TlsCtx *tls, unsigned char *buf, int from)
{
	const int len = 12;
	const char *sender;
	size_t slen;
	TlsSess *sess = &tls->sess;
	ttls_sha256_context sha256;
	unsigned char padbuf[SHA256_DIGEST_SIZE];

	memcpy_fast(&sha256, &tls->hs->fin_sha256, sizeof(sha256));

	/* TLSv1.2: hash = PRF(master, finished_label, Hash(handshake))[0.11] */
	T_DBG3_BUF("finished sha256 state",
		   ((struct sha256_state *)shash_desc_ctx(&sha256.desc))->state,
		   SHA256_DIGEST_SIZE);

	sender = (from == TTLS_IS_CLIENT)
		 ? "client finished"
		 : "server finished";
	slen = sizeof("client finished") - 1;

	crypto_shash_final(&sha256.desc, padbuf);
	tls->hs->tls_prf(sess->master, 48, sender, slen, padbuf,
			 SHA256_DIGEST_SIZE, buf, len);

	T_DBG3_BUF("calc finished sha256 result", buf, len);

	bzero_fast(&sha256, sizeof(sha256));
	bzero_fast(padbuf, sizeof(padbuf));
}

static void
ttls_calc_finished_tls_sha384(TlsCtx *tls, unsigned char *buf, int from)
{
	const int len = 12;
	const char *sender;
	size_t slen;
	TlsSess *sess = &tls->sess;
	ttls_sha512_context sha512;
	unsigned char padbuf[SHA384_DIGEST_SIZE];

	memcpy_fast(&sha512, &tls->hs->fin_sha512, sizeof(sha512));

	/* TLSv1.2: hash = PRF(master, finished_label, Hash(handshake))[0.11] */
	T_DBG3_BUF("finished sha512 state",
		   ((struct sha512_state *)shash_desc_ctx(&sha512.desc))->state,
		   SHA512_DIGEST_SIZE);

	sender = (from == TTLS_IS_CLIENT)
		 ? "client finished"
		 : "server finished";
	slen = sizeof("client finished") - 1;

	crypto_shash_final(&sha512.desc, padbuf);
	tls->hs->tls_prf(sess->master, 48, sender, slen, padbuf,
			 SHA384_DIGEST_SIZE, buf, len);

	T_DBG3_BUF("calc finished sha512 result", buf, len);

	bzero_fast(&sha512, sizeof(sha512));
	bzero_fast(padbuf, sizeof(padbuf));
}

int
ttls_derive_keys(TlsCtx *tls)
{
	unsigned char keyblk[256] ____cacheline_aligned;
	unsigned char tmp[32];
	unsigned char *key1, *key2, *mac_enc, *mac_dec;
	const TlsCipherInfo *ci;
	const TlsMdInfo *md_info;
	size_t mac_key_len, iv_copy_len;
	int r = 0, tag_size;
	TlsSess *sess = &tls->sess;
	TlsXfrm *xfrm = &tls->xfrm;
	TlsHandshake *hs = tls->hs;

	ci = ttls_cipher_info_from_type(xfrm->ciphersuite_info->cipher);
	if (!ci) {
		T_DBG("cipher info for %d not found\n",
		      xfrm->ciphersuite_info->cipher);
		return TTLS_ERR_BAD_INPUT_DATA;
	}
	md_info = ttls_md_info_from_type(xfrm->ciphersuite_info->mac);
	if (!md_info) {
		T_DBG("mac info for %d not found\n",
		      xfrm->ciphersuite_info->mac);
		return TTLS_ERR_BAD_INPUT_DATA;
	}
	tag_size = ttls_xfrm_taglen(xfrm);

	/* Set appropriate PRF function and other TLS 1.2 functions. */
	if (xfrm->ciphersuite_info->mac == TTLS_MD_SHA384) {
		hs->tls_prf = tls_prf_sha384;
		hs->calc_verify = ttls_calc_verify_tls_sha384;
		hs->calc_finished = ttls_calc_finished_tls_sha384;
	} else {
		hs->tls_prf = tls_prf_sha256;
		hs->calc_verify = ttls_calc_verify_tls_sha256;
		hs->calc_finished = ttls_calc_finished_tls_sha256;
	}

	/* master = PRF(premaster, "master secret", randbytes)[0..47] */
	if (!hs->resume) {
		T_DBG3_BUF("premaster secret", hs->premaster, hs->pmslen);
		if (tls->hs->extended_ms) {
			unsigned char session_hash[48];
			size_t hash_len;

			tls->hs->calc_verify(tls, session_hash);

			if (tls->xfrm.ciphersuite_info->mac == TTLS_MD_SHA384)
				hash_len = 48;
			else
				hash_len = 32;

			r = TTLS_PRF(hs, hs->premaster, hs->pmslen,
				     "extended master secret", session_hash,
				     hash_len, sess->master, 48);
		} else {
			r = TTLS_PRF(hs, hs->premaster, hs->pmslen,
				     "master secret", hs->randbytes,
				     64, sess->master, 48);
		}
		if (r) {
			T_DBG("prf master secret error, %d\n", r);
			return r;
		}
		bzero_fast(hs->premaster, sizeof(hs->premaster));
	}
	else {
		T_DBG("no premaster (session resumed)\n");
	}

	/* Swap the client and server random values. */
	memcpy_fast(tmp, hs->randbytes, 32);
	memcpy_fast(hs->randbytes, hs->randbytes + 32, 32);
	memcpy_fast(hs->randbytes + 32, tmp, 32);
	bzero_fast(tmp, sizeof(tmp));

	/* key block = PRF(master, "key expansion", randbytes). */
	r = TTLS_PRF(hs, sess->master, 48, "key expansion", hs->randbytes, 64,
		     keyblk, 256);
	if (r) {
		T_DBG("prf key expansion error, %d\n", r);
		return r;
	}

	T_DBG("ciphersuite = %s\n",
	      ttls_get_ciphersuite_name(sess->ciphersuite));
	T_DBG3_BUF("master secret", sess->master, 48);
	T_DBG3_BUF("random bytes", hs->randbytes, 64);
	T_DBG3_BUF("key block", keyblk, 256);

	bzero_fast(hs->randbytes, sizeof(hs->randbytes));

	/* Determine the appropriate key, IV and MAC length. */
	xfrm->keylen = ci->key_len;
	if (ci->mode == TTLS_MODE_GCM || ci->mode == TTLS_MODE_CCM) {
		xfrm->maclen = 0;
		mac_key_len = 0;
		xfrm->ivlen = 12;
		xfrm->fixed_ivlen = 4;
		WARN_ON_ONCE(ttls_expiv_len(xfrm) != TTLS_IV_LEN);
		/* Minimum length is expicit IV + tag */
		xfrm->minlen = ttls_expiv_len(xfrm)
				+ ((xfrm->ciphersuite_info->flags
				    & TTLS_CIPHERSUITE_SHORT_TAG) ? 8 : 16);
	} else {
		BUG_ON(ci->mode != TTLS_MODE_STREAM);
		/*
		 * TODO #1031: Initialize HMAC contexts - do we need this for
		 * CHACHA20_POLY1305?
		 */
		if ((r = ttls_md_setup(&xfrm->md_ctx_enc, md_info, 1))
		    || (r = ttls_md_setup(&xfrm->md_ctx_dec, md_info, 1)))
		{
			return r;
		}

		/* Get MAC length */
		mac_key_len = ttls_md_get_size(md_info);
		xfrm->maclen = mac_key_len;

		/* IV length */
		xfrm->ivlen = ci->iv_size;
		WARN_ON_ONCE(xfrm->ivlen > 16);

		/* Minimum length */
		xfrm->minlen = xfrm->maclen;
	}
	T_DBG("keylen=%u minlen=%u ivlen=%u maclen=%u tagsize=%d"
	      " mac_key_len=%lu\n", xfrm->keylen, xfrm->minlen, xfrm->ivlen,
	      xfrm->maclen, tag_size, mac_key_len);

	/* Finally setup the cipher contexts, IVs and MAC secrets. */
	if (tls->conf->endpoint == TTLS_IS_CLIENT) {
		key1 = keyblk + mac_key_len * 2;
		key2 = keyblk + mac_key_len * 2 + xfrm->keylen;
		mac_enc = keyblk;
		mac_dec = keyblk + mac_key_len;
		iv_copy_len = xfrm->fixed_ivlen ? : xfrm->ivlen;
		memcpy_fast(xfrm->iv_enc, key2 + xfrm->keylen, iv_copy_len);
		memcpy_fast(xfrm->iv_dec, key2 + xfrm->keylen + iv_copy_len,
			    iv_copy_len);
	} else {
		key1 = keyblk + mac_key_len * 2 + xfrm->keylen;
		key2 = keyblk + mac_key_len * 2;
		mac_enc = keyblk + mac_key_len;
		mac_dec = keyblk;
		iv_copy_len = xfrm->fixed_ivlen ? : xfrm->ivlen;
		memcpy_fast(xfrm->iv_dec, key1 + xfrm->keylen, iv_copy_len);
		memcpy_fast(xfrm->iv_enc, key1 + xfrm->keylen + iv_copy_len,
			    iv_copy_len);
	}
	T_DBG3_BUF("derive keys: IV_enc fixed", xfrm->iv_enc, iv_copy_len);
	T_DBG3_BUF("derive keys: key_enc", key1, ci->key_len);
	T_DBG3_BUF("derive keys: IV_dec fixed", xfrm->iv_dec, iv_copy_len);
	T_DBG3_BUF("derive keys: key_dec", key2, ci->key_len);

	if (mac_key_len) {
		ttls_md_hmac_starts(&xfrm->md_ctx_enc, mac_enc, mac_key_len);
		ttls_md_hmac_starts(&xfrm->md_ctx_dec, mac_dec, mac_key_len);
	}

	if ((r = ttls_cipher_setup(&xfrm->cipher_ctx_enc, ci, tag_size))) {
		T_DBG("cannot setup encryption cipher, %d\n", r);
		return r;
	}
	if ((r = ttls_cipher_setup(&xfrm->cipher_ctx_dec, ci, tag_size))) {
		T_DBG("cannot setup decryption cipher, %d\n", r);
		return r;
	}

	r = crypto_aead_setkey(xfrm->cipher_ctx_enc.cipher_ctx, key1, ci->key_len);
	if (r) {
		T_DBG("cannot set encryption key, %d\n", r);
		return r;
	}

	r = crypto_aead_setkey(xfrm->cipher_ctx_dec.cipher_ctx, key2, ci->key_len);
	if (r) {
		T_DBG("cannot set decryption key, %d\n", r);
		return r;
	}

	bzero_fast(keyblk, sizeof(keyblk));

	return 0;
}

void
ttls_read_version(TlsCtx *tls, const unsigned char ver[2])
{
	tls->major = ver[0];
	tls->minor = ver[1];
}

/*
 * Fill in the buffer with additional authentication data for AES-GCM,
 * RFC 5246 6.2.3.3.
 * TODO replace with standard tls_make_aad() defined in include/net/tls.h in
 * modern kernels.
 */
static void
ttls_make_aad(TlsCtx *tls, TlsIOCtx *io, unsigned char *aad_buf)
{
	unsigned short elen = ttls_msg2crypt_len(io, &tls->xfrm);

	*(unsigned long *)aad_buf = __cpu_to_be64(io->ctr);
	ttls_write_hdr(tls, io->msgtype, elen, aad_buf + 8);
	T_DBG3_BUF("additional data used for AEAD", aad_buf,
		   TLS_AAD_SPACE_SIZE);
}

/**
 * Use per-cpu AEAD crypto requests in static memory instead of allocating them
 * each time from the heap. Tempesta TLS works in softirq context, so there are
 * no concurrent crypto requests on the same CPU and there is no preemption.
 * Fallabck to kmalloc() if we use not enough reserved memory in TlsReq and
 * print a warning to reserve bit more memory.
 */
static struct aead_request *
ttls_aead_req_alloc(struct crypto_aead *tfm)
{
	size_t need = sizeof(struct aead_request) + crypto_aead_reqsize(tfm);

	WARN_ON_ONCE(!in_serving_softirq());
	if (WARN_ON_ONCE(ttls_aead_reqsize() < need))
		return kzalloc(need, GFP_ATOMIC);

	return *this_cpu_ptr(&g_req);
}

static void
ttls_aead_req_free(struct crypto_aead *tfm, struct aead_request *req)
{
	size_t need = sizeof(struct aead_request) + crypto_aead_reqsize(tfm);

	if (WARN_ON_ONCE(ttls_aead_reqsize() < need))
		kfree(req);
	else
		bzero_fast(req, ttls_aead_reqsize());
}

/**
 * This TLS records encryption function can be called synchronously, on
 * handshake finished, or asynchronously, on callback from the TCP/IP stack. We
 * can use TLS context very carefully - many records can be processed before a
 * record is encrypted on TCP transmission.
 *
 * @sgt must have enough room for AAD header and a TAG.
 *
 * We (as well as mbed TLS) use egress record ID as IV. OpenSSL uses random for
 * IV, which is considered a good, but not mandatory practice. Each TLS session
 * has its own key, so similar plain text blocks, either in the same or
 * different sessions, always have different ciphertexts.
 */
int
ttls_encrypt(TlsCtx *tls, struct sg_table *sgt, struct sg_table *out_sgt)
{
	int r, elen;
	TlsXfrm *xfrm = &tls->xfrm;
	TlsIOCtx *io = &tls->io_out;
	TlsCipherCtx *c_ctx = &xfrm->cipher_ctx_enc;
	unsigned long iv = __cpu_to_be64(io->ctr);
	struct aead_request *req;

	WARN_ON_ONCE(!ttls_xfrm_ready(tls));
	WARN_ON_ONCE(io->msglen > TLS_MAX_PAYLOAD_SIZE + TLS_MAX_OVERHEAD
				  - TLS_HEADER_SIZE);

	req = ttls_aead_req_alloc(c_ctx->cipher_ctx);
	if (unlikely(!req))
		return -ENOMEM;

	*(long *)(xfrm->iv_enc + xfrm->fixed_ivlen) = iv;
	T_DBG3_BUF("IV used", xfrm->iv_enc, xfrm->ivlen);

	elen = ttls_msg2crypt_len(io, xfrm);
	ttls_make_aad(tls, io, sg_virt(out_sgt->sgl));
	aead_request_set_tfm(req, c_ctx->cipher_ctx);
	aead_request_set_ad(req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(req, sgt->sgl, out_sgt->sgl, elen, xfrm->iv_enc);

	T_DBG3("%s encryption: tfm=%pK(req->tfm=%pK req=%pK) reqsize=%u"
		" key_len=%u data_len=%d\n",
	       c_ctx->cipher_info->name, c_ctx->cipher_ctx,
	       crypto_aead_reqtfm(req), req,
	       crypto_aead_reqsize(c_ctx->cipher_ctx),
	       c_ctx->cipher_info->key_len, elen);
	T_DBG3_SL("plaintext buf for encryption (first 256 bytes)",
		  sgt->sgl, sgt->nents, 0,
		  min_t(size_t, 256, io->msglen + TLS_HEADER_SIZE));

	if ((r = crypto_aead_encrypt(req))) {
		T_WARN("AEAD encryption failed: %d\n", r);
		goto err;
	}
	T_DBG3_SL("encrypted buf (first 64 bytes)", sgt->sgl, sgt->nents, 0,
		  min_t(size_t, 64, io->msglen + TLS_HEADER_SIZE));

	if (unlikely(++io->ctr > (~0UL >> 1)))
		T_WARN("outgoing message counter would wrap\n");

err:
	ttls_aead_req_free(c_ctx->cipher_ctx, req);

	return r;
}
EXPORT_SYMBOL(ttls_encrypt);

static int
__ttls_decrypt(TlsCtx *tls, unsigned char *buf)
{
	size_t expiv_len, dec_msglen;
	int r;
	ttls_cipher_mode_t mode;
	TlsXfrm *xfrm = &tls->xfrm;
	TlsIOCtx *io = &tls->io_in;
	struct crypto_aead *tfm = xfrm->cipher_ctx_dec.cipher_ctx;
	unsigned int sgn = 1;
	unsigned char taglen;
	struct aead_request *req;
	struct scatterlist *sg = NULL;
	unsigned char aad_buf[TLS_AAD_SPACE_SIZE];

	if (unlikely(io->msglen < xfrm->minlen)) {
		T_DBG("%s msglen (%u) < minlen (%u)\n", __func__,
		      io->msglen, xfrm->minlen);
		return TTLS_ERR_INVALID_MAC;
	}

	expiv_len = ttls_expiv_len(xfrm);
	taglen = ttls_xfrm_taglen(xfrm);
	mode = xfrm->cipher_ctx_enc.cipher_info->mode;

	WARN_ON_ONCE(mode != TTLS_MODE_GCM && mode != TTLS_MODE_CCM);
	T_DBG2("decrypt input record from network: hdr=%pK msglen=%d chunks=%u"
	       " taglen=%u eiv_len=%lu\n",
	       io->hdr, io->msglen, io->chunks, taglen, expiv_len);
	if (unlikely(io->msglen < expiv_len + taglen)) {
		T_DBG("%s: msglen (%u) < expiv_len (%lu) + taglen (%u)\n",
		      __func__, io->msglen, expiv_len, taglen);
		return TTLS_ERR_INVALID_MAC;
	}

	dec_msglen = io->msglen - expiv_len - taglen;
	/* Build decryption request starting from the offset. */
	io->off = ttls_payload_off(xfrm);

	memcpy_fast(xfrm->iv_dec + xfrm->fixed_ivlen, io->iv, sizeof(io->iv));
	req = ttls_crypto_req_sglist(tls, tfm, dec_msglen + taglen, buf,
				     &sg, &sgn);
	if (!req || WARN_ON_ONCE(sgn < 2))
		return TTLS_ERR_INTERNAL_ERROR;
	ttls_make_aad(tls, io, aad_buf);
	sg_set_buf(sg, aad_buf, TLS_AAD_SPACE_SIZE);

	T_DBG3_BUF("IV used", xfrm->iv_dec, xfrm->ivlen);
	T_DBG3_SL("decrypt: AAD|msg|TAG", sg, sgn, 0, dec_msglen + taglen);

	/*
	 * Decrypt and authenticate.
	 * Write decrypted data in-place to the original skb by offset of IV.
	 *
	 * TODO it seems actually the kernel unable to decrypt scatterlist
	 * w/o copies since gcmaes_decrypt() requires input and output segments
	 * to be marked as ends.
	 */
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, TLS_AAD_SPACE_SIZE);
	/* The crypto layer expects AAD segment in output scatter list. */
	aead_request_set_crypt(req, sg, sg, dec_msglen + taglen,
			       xfrm->iv_dec);
	r = crypto_aead_decrypt(req);

	T_DBG3_SL("raw buffer after decryption", sg + 1, sgn - 1, 0,
		  dec_msglen);

	if (unlikely(++io->ctr > (~0UL >> 1)))
		T_WARN("incoming message counter would wrap\n");

	kfree(req);

	return r;
}

static int
ttls_decrypt(TlsCtx *tls, unsigned char *buf)
{
	int r;
	TlsIOCtx *io = &tls->io_in;

	if ((r = __ttls_decrypt(tls, buf))) {
		/* Error out (and send alert) on invalid records */
		if (r == TTLS_ERR_INVALID_MAC)
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_BAD_RECORD_MAC);
		T_DBG2("decryption failed: %d", r);
		return T_DROP;
	}

	/*
	 * Three or more empty messages may be a DoS attack
	 * (excessive CPU consumption).
	 */
	if (unlikely(!io->msglen && ++tls->nb_zero > 3)) {
		T_WARN("received four consecutive empty messages,"
		       " possible DoS attack\n");
		return T_DROP;
	} else {
		tls->nb_zero = 0;
	}
	if (io->msglen > TLS_MAX_PAYLOAD_SIZE) {
		T_DBG("bad message length %u\n", io->msglen);
		return T_DROP;
	}

	if (io->msgtype == TTLS_MSG_ALERT)
		return ttls_skb_extract_alert(io, &tls->xfrm);

	return 0;
}

/**
 * Form a TLS record from segments in @sgt starting at @sg_i.
 *
 * If @hdr_buf != NULL, then it's expected that it's at the begin of @sgt
 * segments.
 */
void
__ttls_add_record(TlsCtx *tls, struct sg_table *sgt, int sg_i,
		  unsigned char *hdr_buf)
{
	TlsIOCtx *io = &tls->io_out;

	T_DBG("write record: type=%d len=%d hslen=%u sgt=%pK/%u sg_i=%d\n",
	      io->msgtype, io->msglen, io->hslen, sgt, sgt ? sgt->nents : 0,
	      sg_i);

	if (io->msgtype == TTLS_MSG_HANDSHAKE
	    && io->hstype != TTLS_HS_HELLO_REQUEST
	    && io->hstype != TTLS_HS_FINISHED)
	{
		int d = hdr_buf ? TLS_HEADER_SIZE : 0;

		/*
		 * Update handshake checksum with handshake messages, not
		 * including any HelloRequest messages, body excluding TLS
		 * record header (RFC 5246 7.4.9).
		 * @sgt must be present or io->hs_hdr must be used for
		 * checksumming.
		 */
		BUG_ON(!io->hslen && (!sgt || !sgt->sgl || sgt->nents < 1));
		WARN_ON_ONCE(!tls->hs);

		if (io->hslen && d < io->hslen)
			ttls_update_checksum(tls, io->hs_hdr + d,
					     io->hslen - d);
		if (sgt) {
			struct scatterlist *sg;
			for (sg = &sgt->sgl[sg_i]; sg_i < sgt->nents;
			     sg_i++, sg = sg_next(sg))
			{
				if (unlikely(d >= sg->length)) {
					d -= sg->length;
					continue;
				}
				ttls_update_checksum(tls, sg_virt(sg) + d,
						     sg->length - d);
				d = 0;
			}
		}
	}

	/*
	 * Write TLS header if the record should not be encrypted.
	 * Otherwise sk_write_xmit() call back does this for us.
	 */
	if (!hdr_buf)
		hdr_buf = io->hdr;
	if (!ttls_xfrm_ready(tls))
		ttls_write_hdr(tls, io->msgtype, io->msglen, hdr_buf);
}

int
__ttls_send_record(TlsCtx *tls, struct sg_table *sgt, bool close)
{
	int r;

	if ((r = ttls_send_cb(tls, sgt, close)))
		T_DBG("TLS send callback error %d\n", r);
	return r;
}

static int
ttls_write_record(TlsCtx *tls, struct sg_table *sgt, bool close)
{
	/* Change __ttls_add_record() call if you need it for handshakes. */
	WARN_ON_ONCE(tls->io_out.msgtype == TTLS_MSG_HANDSHAKE);

	__ttls_add_record(tls, NULL, 0, NULL);

	return __ttls_send_record(tls, sgt, close);
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
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
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
		T_DBG("minor version mismatch %d\n", tls->minor);
		return T_DROP;
	}
	/* Check length against the size of our buffer */
	if (unlikely(io->msglen > TTLS_PAYLOAD_LEN)) {
		T_DBG("too big message length: %u\n", io->msglen);
		return T_DROP;
	}
	/* Drop unexpected ChangeCipherSpec messages. */
	if (io->msgtype == TTLS_MSG_CHANGE_CIPHER_SPEC
	    && ttls_state(tls) != TTLS_CLIENT_CHANGE_CIPHER_SPEC
	    && ttls_state(tls) != TTLS_SERVER_CHANGE_CIPHER_SPEC)
	{
		T_DBG("dropping unexpected ChangeCipherSpec\n");
		return T_DROP;
	}
	/* Check length against bounds of the current transform and version */
	if (!ttls_xfrm_ready(tls)) {
		if (io->msglen < 1 || io->msglen > TLS_MAX_PAYLOAD_SIZE) {
			T_DBG("bad message length %u\n", io->msglen);
			return T_DROP;
		}
	} else {
		/*
		 * TLS encrypted messages can have up to 256 bytes of padding.
		 */
		if (io->msglen < tls->xfrm.minlen
		    || io->msglen
		       > tls->xfrm.minlen + TLS_MAX_PAYLOAD_SIZE + 256)
		{
			T_DBG("bad message length %u\n", io->msglen);
			return T_DROP;
		}
	}

	return T_OK;
}

/**
 * Read TLS message header and IV or handshake header:
 *
 *	uint8 type;
 *	uint16 version;
 *	uint16 length;
 *	[explicit IV | alert | handshake header];
 *
 * While IV and alert message aren't a part of TLS message header, we read it
 * here for application data messages to simplify further decryption logic.
 * TLS header and IV are quite small, so it's more efficiently just to always
 * copy it instead of manipulating with fragmented data.
 *
 * Return 0 if header looks sane TTLS_ERR_INVALID_RECORD if the header looks
 * bad, and T_POSTPONE if we need more data for the header.
 */
static int
ttls_parse_record_hdr(TlsCtx *tls, unsigned char *buf, size_t len,
		      unsigned int *read)
{
	int r, ivahs_len, n = 0;
	bool ready = ttls_xfrm_ready(tls);
	TlsIOCtx *io = &tls->io_in;

	/* Read TLS message header, probably fragmented. */
	if (unlikely(io->hdr_cpsz + len < TLS_HEADER_SIZE)) {
		memcpy_fast(io->hdr + io->hdr_cpsz, buf, len);
		*read += len;
		io->hdr_cpsz += len;
		return T_POSTPONE;
	}
	if (io->hdr_cpsz < TLS_HEADER_SIZE) {
		n = TLS_HEADER_SIZE - io->hdr_cpsz;
		memcpy_fast(io->hdr + io->hdr_cpsz, buf, n);
		*read += n;
		io->hdr_cpsz += n;
	}

	io->msgtype = io->hdr[0];
	ttls_read_version(tls, io->hdr + 1);
	io->msglen = ((unsigned short)io->hdr[3] << 8) | io->hdr[4];

	T_DBG3("input rec: type=%d ver=%d:%d msglen=%d read=%u xfrm_ready=%d\n",
	       io->msgtype, tls->major, tls->minor, io->msglen, *read, ready);

	if ((r = ttls_hdr_check(tls)))
		return r;
	switch (io->msgtype) {
	case TTLS_MSG_ALERT:
		/* Alerts are unencrypted during handshake only. */
		if (!ready) {
			ivahs_len = 2; /* level & description */
			if (io->msglen < ivahs_len) {
				T_DBG("alert message too short: %d\n",
				      io->msglen);
				return TTLS_ERR_INVALID_RECORD;
			}
			break;
		}
		/*
		 * Read IV for the encrypted alert as we do this for
		 * application data records.
		 */

	case TTLS_MSG_APPLICATION_DATA:
		ivahs_len = ttls_expiv_len(&tls->xfrm);
		break;

	case TTLS_MSG_CHANGE_CIPHER_SPEC:
		/* Read 1 byte equal to 0x1. */
		ivahs_len = 1;
		if (io->msglen < ivahs_len) {
			T_DBG("ChangeCipherSpec message too short: %d\n",
			      io->msglen);
			return TTLS_ERR_INVALID_RECORD;
		}
		break;

	case TTLS_MSG_HANDSHAKE:
		/*
		 * Read handshake header if it's unencrypted:
		 *
		 *   0 . 0   handshake type
		 *   1 . 3   handshake length
		 */
		if (!ready) {
			ivahs_len = TTLS_HS_HDR_LEN;
			if (io->msglen < ivahs_len) {
				T_DBG("handshake message too short: %d\n",
				      io->msglen);
				return TTLS_ERR_INVALID_RECORD;
			}
		} else {
			ivahs_len = ttls_expiv_len(&tls->xfrm);
		}
		break;

	default:
		return TTLS_ERR_INVALID_RECORD;
	}

	/* Read [IV | alert | handshake header] (probably fragmented). */
	len -= n;
	if (unlikely(io->hdr_cpsz + len < TLS_HEADER_SIZE + ivahs_len)) {
		memcpy(io->__msg + io->hdr_cpsz - TLS_HEADER_SIZE,
		       buf + n, len);
		*read += len;
		io->hdr_cpsz += len;
		return T_POSTPONE;
	}
	if (io->msgtype == TTLS_MSG_APPLICATION_DATA
	    || (ready && io->msgtype == TTLS_MSG_ALERT))
	{
		BUG_ON(io->rlen);
		io->rlen = ivahs_len;
	}
	ivahs_len -= io->hdr_cpsz - TLS_HEADER_SIZE;
	memcpy(io->__msg + io->hdr_cpsz - TLS_HEADER_SIZE, buf + n, ivahs_len);
	*read += ivahs_len;
	io->hdr_cpsz = 0;
	io->st_flags |= TTLS_F_ST_HDRIV;

	if (io->msgtype == TTLS_MSG_CHANGE_CIPHER_SPEC) {
		io->hstype = io->hs_hdr[0];
		T_DBG("change cipher spec message:"
		      " msglen=%d type=%d hslen=%d read=%u\n",
		      io->msglen, io->hstype, io->hslen, *read);
	}
	/* Don't try to read encrypted handshake header. */
	else if (io->msgtype == TTLS_MSG_HANDSHAKE && !ready) {
		io->hstype = io->hs_hdr[0];
		io->hslen = (io->hs_hdr[1] << 16) | (io->hs_hdr[2] << 8)
			    | io->hs_hdr[3];
		T_DBG("handshake message: msglen=%d type=%d hslen=%d read=%u\n",
		      io->msglen, io->hstype, io->hslen, *read);

		/*
		 * Minimal length of the ClientHello with everything empty and
		 * extensions omitted is 2 + 32 + 1 + 2 + 1 = 38 bytes.
		 */
		if (unlikely(io->hstype == TTLS_HS_CLIENT_HELLO &&
			     io->hslen < 38))
		{
			T_DBG("too short client handshake message: %u\n",
			      io->hslen);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}

		/* With TLS we don't handle fragmentation (for now) */
		if (io->msglen < io->hslen) {
			T_DBG("TLS handshake fragmentation not supported\n");
			return TTLS_ERR_FEATURE_UNAVAILABLE;
		}
	}

	return T_OK;
}

static void
ttls_handshake_free(TlsHandshake *hs, const TlsCiphersuite *ci)
{
	if (!hs)
		return;

	/*
	 * Free only the linked list wrapper, not the keys themselves
	 * since they belong to the SNI callback.
	 */
	if (hs->sni_key_cert) {
		ttls_key_cert *cur = hs->sni_key_cert, *next;
		while (cur) {
			next = cur->next;
			kfree(cur);
			cur = next;
		}
	}

	crypto_free_shash(hs->desc.tfm);

	if (!IS_ERR_OR_NULL(ci)) {
		if (ttls_ciphersuite_uses_ecdh(ci) ||
		    ttls_ciphersuite_uses_ecdhe(ci))
		{
			ttls_ecdh_free(&hs->ecdh_ctx);
		}

#if defined(TTLS_DHM_C)
		if (ttls_ciphersuite_uses_dhe(ci))
			ttls_dhm_free(&hs->dhm_ctx);
#endif
	}

	bzero_fast(hs, sizeof(TlsHandshake));
	kmem_cache_free(ttls_hs_cache, hs);
}

void
ttls_handshake_wrapup(TlsCtx *tls)
{
	int resume = tls->hs->resume;

	/* Add cache entry. */
	if (tls->conf->f_set_cache && tls->sess.id_len && !resume
	    && tls->conf->f_set_cache(tls->conf->p_cache, &tls->sess))
		T_DBG("cache did not store session\n");

	/* Free our hs params. */
	ttls_handshake_free(tls->hs, tls->xfrm.ciphersuite_info);
	tls->hs = NULL;
}

/**
 * Process TLS alerts.
 */
int
ttls_handle_alert(TlsIOCtx *io)
{
	T_DBG("got an alert message, type=%d:%d\n", io->alert[0], io->alert[1]);

	/* Ignore non-fatal alerts, except close_notify. */
	if (io->alert[0] == TTLS_ALERT_LEVEL_FATAL) {
		T_DBG2("is a fatal alert message (msg %d)\n", io->alert[1]);
		return T_DROP;
	}
	if (io->alert[0] == TTLS_ALERT_LEVEL_WARNING
	    && io->alert[1] == TTLS_ALERT_MSG_CLOSE_NOTIFY)
	{
		T_DBG2("is a close notify message\n");
		return T_DROP;
	}

	/* Silently ignore: fetch new message */
	return 0;
}

/**
 * Send an alert message.
 *
 * @lvl	- the alert level of the message (TTLS_ALERT_LEVEL_WARNING or
 * 	  TTLS_ALERT_LEVEL_FATAL)
 * @msg	- the alert message (SSL_ALERT_MSG_*)
 */
int
ttls_send_alert(TlsCtx *tls, unsigned char lvl, unsigned char msg)
{
	bool close = false;
	TlsIOCtx *io = &tls->io_out;

	T_DBG("send alert level=%u message=%u\n", lvl, msg);

	io->msgtype = TTLS_MSG_ALERT;
	io->hstype = TTLS_HS_INVALID;
	/* Set hslen just in case of non-critical handshake alert. */
	io->msglen = io->hslen = 2;
	io->alert[0] = lvl;
	io->alert[1] = msg;

	if (msg == TTLS_ALERT_MSG_CLOSE_NOTIFY)
		close = true;

	return ttls_write_record(tls, NULL, close);
}

int
ttls_write_certificate(TlsCtx *tls, struct sg_table *sgt,
		       unsigned char **in_buf)
{
	unsigned int sg_i;
	size_t i, n, cn, tot_len, cn_max = MAX_SKB_FRAGS / 2 - 1;
	const ttls_x509_crt *crt;
	TlsIOCtx *io = &tls->io_out;
	unsigned char *p = *in_buf;

#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT && !tls->client_auth) {
		T_DBG2("<= skip write certificate");
		tls->state++;
		return 0;
	}
#endif

	/* Leave the sg for the record header and certs descriptor. */
	sg_i = sgt->nents++;

	if (tls->conf->endpoint == TTLS_IS_SERVER && !ttls_own_cert(tls)) {
		T_DBG("got no certificate to send\n");
		return TTLS_ERR_CERTIFICATE_REQUIRED;
	}

	/*
	 *   7 . 9	length of cert. 1
	 *  10 . n-1	peer certificate
	 *   n . n+2	length of cert. 2
	 * n+3 . ...	upper level cert, etc.
	 */
	tot_len = 7;
	i = tot_len + TLS_HEADER_SIZE;
	for (cn = 0, crt = ttls_own_cert(tls); crt; ) {
		n = crt->raw.len;
		if (n > TLS_MAX_PAYLOAD_SIZE - 3 - i) {
			T_WARN("certificate too large, %lu > %lu\n",
			       i + 3 + n, TLS_MAX_PAYLOAD_SIZE);
			return TTLS_ERR_CERTIFICATE_TOO_LARGE;
		}

		p[i++] = (unsigned char)(n >> 16);
		p[i++] = (unsigned char)(n >> 8);
		p[i++] = (unsigned char)n;

		tot_len += 3 + n;
		get_page(virt_to_page(crt->raw.p));
		sg_set_buf(&sgt->sgl[sgt->nents++], crt->raw.p, n);
		WARN_ON_ONCE((unsigned long)crt->raw.p & ~PAGE_MASK);
		WARN_ON_ONCE(sgt->nents >= MAX_SKB_FRAGS);
		T_DBG3("add cert page %pK,len=%lu,off=%lu seg=%u\n",
		       crt->raw.p, n, (unsigned long)crt->raw.p & ~PAGE_MASK,
		       sgt->nents - 1);
		crt = crt->next;
		/*
		 * Use part of first sg as separate fragment with next cert
		 * length.
		 */
		if (crt && ++cn < cn_max) {
			get_page(virt_to_page(p));
			sg_set_buf(&sgt->sgl[sgt->nents++], p, 3);
			WARN_ON_ONCE(sgt->nents >= MAX_SKB_FRAGS);
		}
	}
	if (crt)
		T_WARN("Can not write full certificates chain\n");

	/*
	 * Write thr handshake headers on our own.
	 *
	 *  0 . 4	record header (to be written in __ttls_add_record()
	 *  5 . 5	handshake type
	 *  6 . 8	handshake length
	 *  9 . 11	length of all certs
	 */
	io->msglen = tot_len;
	ttls_write_hshdr(TTLS_HS_CERTIFICATE, p + TLS_HEADER_SIZE, tot_len);
	p[9] = (unsigned char)((tot_len - 7) >> 16);
	p[10] = (unsigned char)((tot_len - 7) >> 8);
	p[11] = (unsigned char)(tot_len - 7);
	T_DBG3("cert desc %pK,len=%lu segs=%u\n", p, i, sgt->nents);

	*in_buf = p + i;
	sg_set_buf(&sgt->sgl[sg_i], p, i);
	get_page(virt_to_page(p));
	__ttls_add_record(tls, sgt, sg_i, p);

	return 0;
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
	unsigned char *p = buf;
	unsigned char *state_p = buf;
	T_FSM_INIT(ttls_substate(tls), "TLS ClientCertificate");

	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);
	if (io->hstype != TTLS_HS_CERTIFICATE
	    || io->hslen < 3 + 3)
	{
		T_DBG("bad certificate message length %d\n", io->hslen);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CERTIFICATE;
	}

	authmode = (tls->hs->sni_authmode != TTLS_VERIFY_UNSET)
		   ? tls->hs->sni_authmode
		   : tls->conf->authmode;

	T_FSM_START(ttls_substate(tls)) {

	/*
	 * TODO #830 currently we don't support client certificates validation,
	 * so just allocate a buffer to fit the data and parse it.
	 * Don't care about copies for now.
	 *
	 * TODO call ttls_update_checksum() for the message as well.
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
		n = min_t(size_t, io->hslen - io->rlen, len);
		memcpy_fast(p + io->rlen, buf, n);
		*read += n;
		io->rlen += n;
		if (io->rlen == io->hslen)
			T_FSM_JMP(TTLS_CC_HS_PARSE);
		return T_POSTPONE;
	}
	T_FSM_STATE(TTLS_CC_HS_PARSE) {
		p = (unsigned char *)(*(long *)tls->hs->tmp);
		goto parse;
	}

	}
	TTLS_HS_FSM_FINISH();
parse:

	if (tls->conf->endpoint == TTLS_IS_SERVER
	    && io->hslen == 3
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

	if (p[i] != 0 || io->hslen != n + 3) {
		T_DBG("bad certificate message\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
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
	if (!sess->peer_cert) {
		T_DBG("can npt allocacte a certificate (%lu bytes)\n",
		      sizeof(ttls_x509_crt));
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_INTERNAL_ERROR);
		r = TTLS_ERR_ALLOC_FAILED;
		goto err;
	}

	ttls_x509_crt_init(sess->peer_cert);

	for (i += 3; i < io->hslen; i += n) {
		if (p[i]) {
			T_DBG("bad certificate message\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					    TTLS_ALERT_MSG_DECODE_ERROR);
			r = TTLS_ERR_BAD_HS_CERTIFICATE;
			goto err;
		}

		n = ((unsigned int) p[i + 1] << 8) | (unsigned int) p[i + 2];
		i += 3;

		if (n < 128 || i + n > io->hslen) {
			T_DBG("bad certificate message\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
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
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL, alert);
			T_DBG("cannot parse DER certificate, %d\n", r);
			goto err;
		}
	}
	TTLS_DEBUG_CRT("peer certificate", sess->peer_cert);

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
						      &sess->verify_result);
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
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL, alert);
		}
	}
err:
	__free_pages(virt_to_page(p), 2);
	return r;
}
void
ttls_write_change_cipher_spec(ttls_context *tls)
{
	TlsIOCtx *io = &tls->io_out;

	io->msglen = io->hslen = 1;
	io->msgtype = TTLS_MSG_CHANGE_CIPHER_SPEC;
	io->hstype = TTLS_HS_INVALID;
	io->hs_hdr[0] = 1;

	__ttls_add_record(tls, NULL, 0, NULL);
}

int
ttls_parse_change_cipher_spec(ttls_context *tls, unsigned char *buf, size_t len,
			      unsigned int *read)
{
	TlsIOCtx *io = &tls->io_in;

	if (io->msgtype != TTLS_MSG_CHANGE_CIPHER_SPEC) {
		T_DBG("bad change cipher spec message type %u\n", io->msgtype);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return TTLS_ERR_UNEXPECTED_MESSAGE;
	}
	if (io->msglen != 1 || io->hstype != 1) {
		T_DBG("bad change cipher spec message, len=%u type=%u\n",
		      io->msglen, io->hstype);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC;
	}

	/*
	 * @read was incremented by ttls_parse_record_hdr() as part of handshake
	 * message header.
	 */
	io->ctr = 0;

	return 0;
}

int
ttls_write_finished(TlsCtx *tls, struct sg_table *sgt, unsigned char **in_buf)
{
	int r;
	TlsIOCtx *io = &tls->io_out;
	TlsXfrm *xfrm = &tls->xfrm;
	unsigned char *msg, *p = *in_buf;
	struct scatterlist sg;
	struct sg_table enc_sgt = {
		.sgl	= &sg,
		.nents	= 1,
	};

	io->ctr = 0;
	io->msglen = TTLS_HS_FINISHED_BODY_LEN;
	io->msgtype = TTLS_MSG_HANDSHAKE;
	msg = p + ttls_payload_off(xfrm);

	ttls_write_hshdr(TTLS_HS_FINISHED, msg, TTLS_HS_HDR_LEN + TLS_HASH_LEN);
	tls->hs->calc_finished(tls, msg + TTLS_HS_HDR_LEN, tls->conf->endpoint);

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, p, TLS_HEADER_SIZE + TTLS_HS_FINISHED_BODY_LEN);
	if ((r = ttls_encrypt(tls, &enc_sgt, &enc_sgt)))
		return r;

	ttls_aad2hdriv(xfrm, p);

	*in_buf += TLS_HEADER_SIZE + TTLS_HS_FINISHED_BODY_LEN;
	sg_set_buf(&sgt->sgl[sgt->nents++], p, *in_buf - p);
	get_page(virt_to_page(p));

	return 0;
}

int
ttls_parse_finished(TlsCtx *tls, unsigned char *buf, size_t len,
		    unsigned int *read)
{
	unsigned int n, ct_len;
	TlsIOCtx *io = &tls->io_in;
	TlsXfrm *xfrm = &tls->xfrm;
	TlsHandshake *hs = tls->hs;
	unsigned char hash[TLS_HASH_LEN];

	T_DBG("%s: msglen=%u(rlen=%u len=%lu)\n", __func__,
	      io->msglen, io->rlen, len);
	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);

	if (unlikely(!ttls_xfrm_ready(tls))) {
		T_WARN("TLS context isn't ready on Finished\n");
		return TTLS_ERR_BAD_HS_FINISHED;
	}
	if (unlikely(io->msglen != TTLS_HS_FINISHED_BODY_LEN)) {
		T_DBG("wrong ClientFinished message length: %u\n", io->msglen);
		return TTLS_ERR_BAD_HS_FINISHED;
	}

	ct_len = io->msglen - ttls_expiv_len(xfrm);
	T_DBG3_BUF("Client finished msg body", buf, ct_len);

	/* Copy small chunks to the temporary buffer. */
	n = min_t(unsigned int, ct_len - io->rlen, len);
	memcpy_fast(hs->finished + io->rlen, buf, n);
	io->rlen += n;
	*read += n;
	if (unlikely(io->rlen < ct_len))
		return T_POSTPONE;

	if (ttls_decrypt(tls, hs->finished))
		return T_DROP;
	/* Verify the handshake header. */
	if (unlikely(hs->finished[0] != TTLS_HS_FINISHED
		     || hs->finished[1] || hs->finished[2]
		     || hs->finished[3] != TLS_HASH_LEN))
	{
		T_DBG3_BUF("bad finished message: ",
			   hs->finished, TTLS_HS_HDR_LEN);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_FINISHED;
	}

	tls->hs->calc_finished(tls, hash, tls->conf->endpoint ^ 1);
	if (crypto_memneq(&hs->finished[TTLS_HS_HDR_LEN], hash, TLS_HASH_LEN)) {
		T_DBG("bad hash in finished message\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				    TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_FINISHED;
	}

	/*
	 * Calculate final message checksum before going to
	 * TTLS_HANDSHAKE_OVER state. According to RFC 5246 7.4.9 we need
	 * to add the message to a checksum sent to a client.
	 *
	 * There are two Finished messages, one from a client, and one from a
	 * server. At this point, we've verified the client's Finished using
	 * checksum of everything up to that Finished. To calculate our (server)
	 * Finished, we are continuing to checksum data, including this
	 * (client's) Finished.
	 */
	ttls_update_checksum(tls, hs->finished, TTLS_HS_HDR_LEN + TLS_HASH_LEN);

	return 0;
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

static void
ttls_handshake_params_init(TlsHandshake *hs)
{
	bzero_fast(hs, sizeof(*hs));

	ttls_sig_hash_set_const_hash(&hs->hash_algs, TTLS_MD_NONE);

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
	ttls_handshake_params_init(tls->hs);

	return 0;
}
EXPORT_SYMBOL(ttls_ctx_init);

void
ttls_conf_authmode(ttls_config *conf, int authmode)
{
	conf->authmode = authmode;
}

#if defined(TTLS_CLI_C)
int ttls_set_session(ttls_context *tls, const ttls_ssl_session *session)
{
	int r;

	if (tls == NULL ||
		session == NULL ||
		tls->conf->endpoint != TTLS_IS_CLIENT)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	if ((r = ssl_session_copy(&tls->sess, session)) != 0)
		return r;

	tls->hs->resume = 1;

	return 0;
}
#endif /* TTLS_CLI_C */

void
ttls_conf_ciphersuites_for_version(ttls_config *conf, const int *ciphersuites,
				   int minor)
{
	WARN_ON(minor < TTLS_MINOR_VERSION_3 || minor > TTLS_MINOR_VERSION_4);
	conf->ciphersuite_list[minor] = ciphersuites;
}

void
ttls_conf_cert_profile(ttls_config *conf, const ttls_x509_crt_profile *profile)
{
	conf->cert_profile = profile;
}

/**
 * Append a new keycert entry to a (possibly empty) list.
 * Called in process context on the startup.
 */
static int
ttls_append_key_cert(ttls_key_cert **head, ttls_x509_crt *cert,
		     ttls_pk_context *key)
{
	ttls_key_cert *new;

	if (!(new = kmalloc(sizeof(ttls_key_cert), GFP_KERNEL)))
		return TTLS_ERR_ALLOC_FAILED;

	new->cert = cert;
	new->key = key;
	new->next = NULL;

	/* Update head is the list was null, else add to the end */
	if (!*head) {
		*head = new;
	} else {
		ttls_key_cert *cur = *head;
		while (cur->next)
			cur = cur->next;
		cur->next = new;
	}

	return 0;
}

int
ttls_conf_own_cert(ttls_config *conf, ttls_x509_crt *own_cert,
		   ttls_pk_context *pk_key)
{
	return ttls_append_key_cert(&conf->key_cert, own_cert, pk_key);
}
EXPORT_SYMBOL(ttls_conf_own_cert);

void
ttls_conf_ca_chain(ttls_config *conf, ttls_x509_crt *ca_chain,
		   ttls_x509_crl *ca_crl)
{
	conf->ca_chain = ca_chain;
	conf->ca_crl = ca_crl;
}
EXPORT_SYMBOL(ttls_conf_ca_chain);

int
ttls_set_hs_own_cert(ttls_context *tls, ttls_x509_crt *own_cert,
		     ttls_pk_context *pk_key)
{
	return ttls_append_key_cert(&tls->hs->sni_key_cert, own_cert, pk_key);
}

void
ttls_set_hs_ca_chain(ttls_context *tls, ttls_x509_crt *ca_chain,
		     ttls_x509_crl *ca_crl)
{
	tls->hs->sni_ca_chain = ca_chain;
	tls->hs->sni_ca_crl = ca_crl;
}

void
ttls_set_hs_authmode(ttls_context *tls, int authmode)
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
void
ttls_conf_sig_hashes(ttls_config *conf, const int *hashes)
{
	conf->sig_hashes = hashes;
}

/*
 * Set the allowed elliptic curves
 */
void
ttls_conf_curves(ttls_config *conf, const ttls_ecp_group_id *curve_list)
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

void
ttls_conf_sni(ttls_config *conf,
	      int (*f_sni)(void *, ttls_context *, const unsigned char *,
			   size_t),
	      void *p_sni)
{
	conf->f_sni = f_sni;
	conf->p_sni = p_sni;
}

int
ttls_conf_alpn_protocols(ttls_config *conf, const char **protos)
{
	size_t cur_len, tot_len = 0;
	const char **p;

	/*
	 * RFC 7301 3.1: "Empty strings MUST NOT be included and byte strings
	 * MUST NOT be truncated."
	 * We check lengths now rather than later.
	 */
	for (p = protos; *p; p++) {
		cur_len = strlen(*p);
		tot_len += cur_len;

		if (!cur_len || cur_len > 255 || tot_len > 65535)
			return TTLS_ERR_BAD_INPUT_DATA;
	}
	conf->alpn_list = protos;

	return 0;
}

const char *
ttls_get_alpn_protocol(const TlsCtx *tls)
{
	return tls->alpn_chosen;
}

void
ttls_conf_version(ttls_config *conf, int min_minor, int max_minor)
{
	conf->min_minor_ver = min_minor;
	conf->max_minor_ver = max_minor;
}

#if defined(TTLS_SESSION_TICKETS)
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

#if defined(TTLS_CLI_C)
int ttls_get_session(const ttls_context *tls, ttls_ssl_session *dst)
{
	if (tls == NULL ||
		dst == NULL ||
		tls->conf->endpoint != TTLS_IS_CLIENT)
	{
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	return(ssl_session_copy(dst, &tls->sess));
}
#endif /* TTLS_CLI_C */

static bool
ttls_hs_checksumable(TlsCtx *tls)
{
	/*
	 * Checksumming is currently spread through the code, but if we happen
	 * to receive only part of the data, is performed here too. To avoid
	 * calculating it twice, some states are omitted. Aside from completed
	 * handshake and CertificateVerify message, Finished message is skipped
	 * too: we may fall out of the parser if for some reason only some bytes
	 * of a Finished are received.
	 */
	return tls->state != TTLS_HANDSHAKE_OVER
	       && tls->state != TTLS_CERTIFICATE_VERIFY
	       && tls->state != TTLS_CLIENT_FINISHED;
}

/**
 * Perform the TLS handshake. The function is called for each ingress TLS
 * record and can send a bunch of TLS records.
 *
 * The state of the context (tls->state) will be at the next state after
 * execution of this function. Do not call this function if state is
 * TTLS_HANDSHAKE_OVER.
 *
 * The step callees must return T_POSTPONE if more input data is required to
 * completely read current ingress record and 0 (T_OK) if current FSM state
 * finished successfully. All other return codes are treated as errors.
 *
 * @hh_len is pure optimization argument: it defines a backward offset in
 * @buf of size of hadshake header if the header is in the @buf, so this way
 * we can compute the whole message checksum in one shot. Only handshake steps
 * reading ingress data use the argument.
 */
static int
ttls_handshake_step(TlsCtx *tls, unsigned char *buf, size_t len, size_t hh_len,
		    unsigned int *read)
{
	T_DBG3("handshake message %u on state %x\n",
	       tls->io_in.msgtype, tls->state);

#if defined(TTLS_CLI_C)
	if (tls->conf->endpoint == TTLS_IS_CLIENT)
		return ttls_handshake_client_step(tls, buf, len, hh_len,
						  read);
#endif
	return ttls_handshake_server_step(tls, buf, len, hh_len, read);
}

/**
 * Main TLS receive routine.
 *
 * Read a record, only one. A caller will call us again if a following record,
 * or it's part, is left in @buf.
 *
 * Silently ignore non-fatal alert and continue reading until a valid record is
 * found.
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
	unsigned int delta = 0, hh_len = 0, parsed = *read;
	TlsCtx *tls = (TlsCtx *)tls_data;
	TlsIOCtx *io = &tls->io_in;

	BUG_ON(!tls || !tls->conf);
	T_DBG3("%s: tls=%pK len=%lu read=%u\n", __func__, tls, len, *read);

next_record:
	if (!(io->st_flags & TTLS_F_ST_HDRIV)) {
		if ((r = ttls_parse_record_hdr(tls, buf, len, read)))
			return r;
		if (io->msgtype == TTLS_MSG_HANDSHAKE
		    && ttls_hs_checksumable(tls))
		{
			if (likely(*read - parsed >= TTLS_HS_HDR_LEN)) {
				/*
				 * Compute handshake checksum for the message
				 * body and handshake header in one shot.
				 */
				hh_len = TTLS_HS_HDR_LEN;
			} else {
				ttls_update_checksum(tls, io->hs_hdr,
						     TTLS_HS_HDR_LEN);
			}
		}
	}
	WARN_ON_ONCE(!io->msglen);
	delta = *read - parsed;
	if (delta == len)
		return T_POSTPONE;
	len -= delta;
	buf += delta;
	parsed = *read;

	/*
	 * Current record is fully read and decrypted if necessary.
	 * Skip alerts and empty records and read a next one.
	 */
	switch (io->msgtype) {
	case TTLS_MSG_ALERT:
		if (unlikely(!ttls_xfrm_ready(tls))) {
			if (!(r = ttls_handle_alert(io)))
				goto skip_record;
			return T_DROP;
		}
		break;

	case TTLS_MSG_CHANGE_CIPHER_SPEC:
		/* Parsed as part of handshake FSM. */
	case TTLS_MSG_HANDSHAKE:
		if (unlikely(tls->state == TTLS_HANDSHAKE_OVER)) {
			T_DBG("refusing renegotiation, sending alert\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_WARNING,
					TTLS_ALERT_MSG_NO_RENEGOTIATION);
			return TTLS_ERR_UNEXPECTED_MESSAGE;
		}

		/*
		 * We add ingress messages to the handhsake session checksum
		 * in two different places: here for message chunks and inside
		 * the handshake state machine. @hh_len is used for the
		 * checksumming only. We can not compute checksum for complete
		 * messages here (either before or after the FSM call) because
		 * before Hello message we have no idea which hash algorithm
		 * we should use, but key derieval on KeyExchange phase may
		 * require complete checksum for all the messages including
		 * the KeyExchange one.
		 */
		r = ttls_handshake_step(tls, buf, len, hh_len, read);
		if (!r)
			goto skip_record;
		if (r == T_POSTPONE) {
			/* Add the handshake message chunk to the checksum. */
			BUG_ON(!tls->hs && tls->state != TTLS_HANDSHAKE_OVER);
			if (ttls_hs_checksumable(tls)) {
				size_t n = *read - (int)parsed + hh_len;
				ttls_update_checksum(tls, buf - hh_len, n);
			}
		} else {
			T_DBG("handshake error: %d\n", r);
		}
		return r;

	case TTLS_MSG_APPLICATION_DATA:
		if (!io->msglen) {
			/* OpenSSL sends empty messages to randomize the IV. */
			T_DBG("empty application TLS record - skip\n");
			goto skip_record;
		}
	}

	/* After the handshake the crypto context must be ready. */
	if (unlikely(!ttls_xfrm_ready(tls))) {
		T_WARN("TLS context isn't ready after handshake\n");
		return T_DROP;
	}

	/* Encrypted data. */
	if (io->msglen > io->rlen + len) {
		/*
		 * Store offset of begin of current message. The most generic
		 * case is 0-RTT with a data message after some handshake
		 * messages: we don't know whether there are different messages
		 * at begin of the skb_list or there is only one incomplete
		 * data message, io->off resolves the ambiguity.
		 */
		io->off = *read;
		*read += len;
		io->rlen += len;
		return T_POSTPONE;
	}
	*read += io->msglen - io->rlen;
	if ((r = ttls_decrypt(tls, NULL))) {
		T_DBG("cannot decrypt msg on state %x, ret=%d%s\n",
		      tls->state, r, r == -EBADMSG ? "(bad ciphertext)" : "");
		return T_DROP;
	}

	if (io->msgtype == TTLS_MSG_ALERT) {
		if (!(r = ttls_handle_alert(io)))
			goto skip_record;
		return T_DROP;
	}

	/*
	 * At this point we have fully prepared data for the upper layer.
	 * Once we return the data is passed for processing to the upper layer,
	 * so we reinitialize I/O context for a next message.
	 */
	bzero_fast(io->__initoff, sizeof(*io) - offsetof(TlsIOCtx, __initoff));

	return T_OK;
skip_record:
	T_DBG3("skip record: read=%u parsed=%u len=%lu\n", *read, parsed, len);
	bzero_fast(io->__initoff, sizeof(*io) - offsetof(TlsIOCtx, __initoff));

	delta = *read - parsed;
	WARN_ON_ONCE(delta > len);
	len -= delta;
	if (len) {
		buf += delta;
		parsed = *read;
		goto next_record;
	}

	return T_POSTPONE;
}
EXPORT_SYMBOL(ttls_recv);

/**
 * Notify the peer that the connection is being closed.
 */
int
ttls_close_notify(TlsCtx *tls)
{
	BUG_ON(!tls || !tls->conf);
	T_DBG("write close notify\n");

	if (tls->state != TTLS_HANDSHAKE_OVER)
		return -EINVAL;
	return ttls_send_alert(tls, TTLS_ALERT_LEVEL_WARNING,
			       TTLS_ALERT_MSG_CLOSE_NOTIFY);
}
EXPORT_SYMBOL(ttls_close_notify);

static void
ttls_key_cert_free(ttls_key_cert *key_cert)
{
	ttls_key_cert *cur = key_cert, *next;

	while (cur) {
		next = cur->next;
		ttls_free(cur);
		cur = next;
	}
}

void
ttls_ctx_clear(TlsCtx *tls)
{
	if (!tls)
		return;

	ttls_handshake_free(tls->hs, tls->xfrm.ciphersuite_info);

	if (tls->hostname) {
		bzero_fast(tls->hostname, strlen(tls->hostname));
		ttls_free(tls->hostname);
	}

	ttls_cipher_free(&tls->xfrm.cipher_ctx_enc);
	ttls_cipher_free(&tls->xfrm.cipher_ctx_dec);

	if (tls->sess.peer_cert) {
		ttls_x509_crt_free(tls->sess.peer_cert);
		ttls_free(tls->sess.peer_cert);
	}

	bzero_fast(tls, sizeof(TlsCtx));
}
EXPORT_SYMBOL(ttls_ctx_clear);

void
ttls_config_init(ttls_config *conf)
{
	bzero_fast(conf, sizeof(ttls_config));
}
EXPORT_SYMBOL(ttls_config_init);

static int ttls_default_ciphersuites[] = {
	/* All AES-128 ephemeral suites */
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	TTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	TTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,

	/* All AES-256 ephemeral suites */
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	TTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	TTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,

	/* All AES-256 suites */
	TTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_RSA_WITH_AES_256_CCM,
	TTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_RSA_WITH_AES_256_CCM_8,

	/* All AES-128 suites */
	TTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_RSA_WITH_AES_128_CCM,
	TTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_RSA_WITH_AES_128_CCM_8,

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

/**
 * Load reasonable default TLS configuration values.
 * Use NSA Suite B as a preset-specific defaults.
 */
int
ttls_config_defaults(ttls_config *conf, int endpoint)
{
	conf->endpoint = endpoint;

	/* Things that are common to all presets. */
#if defined(TTLS_CLI_C)
	if (endpoint == TTLS_IS_CLIENT) {
		conf->authmode = TTLS_VERIFY_REQUIRED;
#if defined(TTLS_SESSION_TICKETS)
		conf->session_tickets = TTLS_SESSION_TICKETS_ENABLED;
#endif
	}
#endif

	conf->cert_req_ca_list = 0;

#if defined(TTLS_DHM_C)
	if (endpoint == TTLS_IS_SERVER) {
		int r;
		const unsigned char dhm_p[] = TTLS_DHM_RFC3526_MODP_2048_P_BIN;
		const unsigned char dhm_g[] = TTLS_DHM_RFC3526_MODP_2048_G_BIN;

		r = ttls_conf_dh_param_bin(conf, dhm_p, sizeof(dhm_p), dhm_g,
					   sizeof(dhm_g));
		if (r)
				return r;
	}
#endif

	conf->min_minor_ver = TTLS_MINOR_VERSION_3; /* TLS 1.2 */
	conf->max_minor_ver = TTLS_MAX_MINOR_VERSION;

	ttls_conf_ciphersuites_for_version(conf, ttls_default_ciphersuites,
					   TTLS_MINOR_VERSION_3);

	conf->cert_profile = &ttls_x509_crt_profile_suiteb;
	conf->sig_hashes = ssl_preset_suiteb_hashes;
	conf->curve_list = ssl_preset_suiteb_curves;

	return 0;
}
EXPORT_SYMBOL(ttls_config_defaults);

void
ttls_config_free(ttls_config *conf)
{
	ttls_key_cert_free(conf->key_cert);
	bzero_fast(conf, sizeof(ttls_config));
}
EXPORT_SYMBOL(ttls_config_free);

unsigned char
ttls_sig_from_pk_alg(ttls_pk_type_t type)
{
	switch (type) {
	case TTLS_PK_RSA:
		return TTLS_SIG_RSA;
	case TTLS_PK_ECDSA:
	case TTLS_PK_ECKEY:
		return TTLS_SIG_ECDSA;
	default:
		return TTLS_SIG_ANON;
	}
}

ttls_pk_type_t
ttls_pk_alg_from_sig(unsigned char sig)
{
	switch (sig) {
	case TTLS_SIG_RSA:
		return TTLS_PK_RSA;
	case TTLS_SIG_ECDSA:
		return TTLS_PK_ECDSA;
	default:
		return TTLS_PK_NONE;
	}
}

/* Find an entry in a signature-hash set matching a given hash algorithm. */
ttls_md_type_t
ttls_sig_hash_set_find(ttls_sig_hash_set_t *set, ttls_pk_type_t sig_alg)
{
	switch (sig_alg) {
	case TTLS_PK_RSA:
		return set->rsa;
	case TTLS_PK_ECDSA:
		return set->ecdsa;
	default:
		return TTLS_MD_NONE;
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
	default:
		return;
	}
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

/**
 * Convert from TTLS_MD_XXX to TTLS_HASH_XXX
 */
unsigned char
ttls_hash_from_md_alg(int md)
{
	switch (md) {
	case TTLS_MD_SHA224:
		return TTLS_HASH_SHA224;
	case TTLS_MD_SHA256:
		return TTLS_HASH_SHA256;
	case TTLS_MD_SHA384:
		return TTLS_HASH_SHA384;
	case TTLS_MD_SHA512:
		return TTLS_HASH_SHA512;
	default:
		return TTLS_HASH_NONE;
	}
}

/*
 * Check if a curve proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int
ttls_check_curve(const ttls_context *tls, ttls_ecp_group_id grp_id)
{
	const ttls_ecp_group_id *gid;

	if (!tls->conf->curve_list)
		return -1;

	for (gid = tls->conf->curve_list; *gid != TTLS_ECP_DP_NONE; gid++)
		if (*gid == grp_id)
			return 0;

	return -1;
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
		 * Try to fall back to default hash SHA256 if the client
		 * hasn't provided any preferred signature-hash combinations.
		 */
		if (!ttls_check_sig_hash(tls, TTLS_MD_SHA256))
			ttls_sig_hash_set_const_hash(ha, TTLS_MD_SHA256);
	}
}

int
ttls_check_cert_usage(const ttls_x509_crt *cert,
		      const TlsCiphersuite *ciphersuite, int cert_endpoint,
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

#if defined(TTLS_X509_CHECK_KEY_USAGE)
	if (cert_endpoint == TTLS_IS_SERVER) {
		/* Server part of the key exchange */
		switch (ciphersuite->key_exchange) {
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
			usage = 0;
		}
	} else {
		/*
		 * Client auth: we only implement rsa_sign and ttls_ecdsa_sign
		 * for now.
		 */
		usage = TTLS_X509_KU_DIGITAL_SIGNATURE;
	}

	if (ttls_x509_crt_check_key_usage(cert, usage)) {
		*flags |= TTLS_X509_BADCERT_KEY_USAGE;
		r = -1;
	}
#endif /* TTLS_X509_CHECK_KEY_USAGE */

#if defined(TTLS_X509_CHECK_EXTENDED_KEY_USAGE)
	if (cert_endpoint == TTLS_IS_SERVER) {
		ext_oid = TTLS_OID_SERVER_AUTH;
		ext_len = TTLS_OID_SIZE(TTLS_OID_SERVER_AUTH);
	} else {
		ext_oid = TTLS_OID_CLIENT_AUTH;
		ext_len = TTLS_OID_SIZE(TTLS_OID_CLIENT_AUTH);
	}

	if (ttls_x509_crt_check_extended_key_usage(cert, ext_oid, ext_len)) {
		*flags |= TTLS_X509_BADCERT_EXT_KEY_USAGE;
		r = -1;
	}
#endif /* TTLS_X509_CHECK_EXTENDED_KEY_USAGE */

	return r;
}

int
ttls_set_calc_verify_md(TlsCtx *tls, int md)
{
	switch (md) {
	case TTLS_HASH_SHA384:
		tls->hs->calc_verify = ttls_calc_verify_tls_sha384;
		break;
	case TTLS_HASH_SHA256:
		tls->hs->calc_verify = ttls_calc_verify_tls_sha256;
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
	TlsMdCtx ctx;
	const TlsMdInfo *md_info = ttls_md_info_from_type(md_alg);

	ttls_md_init(&ctx);

	/*
	 * digitally-signed struct {
	 *	 opaque client_random[32];
	 *	 opaque server_random[32];
	 *	 ServerDHParams params;
	 * };
	 */
	if ((r = ttls_md_setup(&ctx, md_info, 0)))
		goto exit;
	if ((r = ttls_md_starts(&ctx)))
		goto exit;
	if ((r = ttls_md_update(&ctx, tls->hs->randbytes, 64)))
		goto exit;
	if ((r = ttls_md_update(&ctx, data, data_len)))
		goto exit;
	if ((r = ttls_md_finish(&ctx, output)))
		goto exit;

exit:
	ttls_md_free(&ctx);
	if (r != 0)
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_INTERNAL_ERROR);
	return r;
}

#if defined(DEBUG) && (DEBUG >= 3)
unsigned long
ttls_time_debug(void)
{
	static atomic64_t curr_time = ATOMIC_INIT(0);

	return atomic64_inc_return(&curr_time);
}
#endif

static void
ttls_exit(void)
{
	int cpu;

	kmem_cache_destroy(ttls_hs_cache);

	for_each_possible_cpu(cpu) {
		struct aead_request **req = per_cpu_ptr(&g_req, cpu);
		kfree(*req);
	}

	ttls_mpi_modexit();
}

static int __init
ttls_init(void)
{
	int cpu, r;

	/* Bad configuration - protected record payload too large. */
	BUILD_BUG_ON(TTLS_PAYLOAD_LEN > 16384 + 2048);

	if ((r = ttls_mpi_modinit()))
		return r;

	if ((r = ttls_crypto_modinit())) {
		ttls_mpi_modexit();
		return r;
	}

	for_each_possible_cpu(cpu) {
		struct aead_request **req = per_cpu_ptr(&g_req, cpu);
		*req = kmalloc(ttls_aead_reqsize(), GFP_KERNEL);
		if (!*req)
			goto err_free;
	}

	ttls_hs_cache = kmem_cache_create("ttls_hs_cache", sizeof(TlsHandshake),
					  0, 0, NULL);
	if (!ttls_hs_cache)
		goto err_free;

	return 0;
err_free:
	ttls_exit();
	return -ENOMEM;
}

module_init(ttls_init);
module_exit(ttls_exit);
