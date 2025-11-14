/**
 *		Tempesta TLS
 *
 * Main TLS shared functions for the server and client.
 *
 * See RFC 5246 for TLS 1.2 specification.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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

#include <linux/types.h>
#include <asm/fpu/api.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <linux/module.h>
#include <net/tls.h>

#include "crypto.h"
#include "mpool.h"
#include "oid.h"
#include "tls_internal.h"
#include "ttls.h"
#include "tls_ticket.h"
#include "lib/alloc.h"

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta TLS");
MODULE_VERSION("0.3.3");
MODULE_LICENSE("GPL");

/*
 * L parameter for CCM algorithm (see NIST SP800-38C, RFC 3610 and OpenSSL's
 * crypto/modes/ccm128.c and mbed TLS's library/ccm.c).
 * The NIST defines it as q, the maximum payload length in octets, i.e. payload
 * must be shorter than 2 ** (8 * (q - 1)). Since TLS operates with records not
 * more than 16KB, L (or q) is always 3.
 * Invariant: IV len = 15 - L = 12.
 * IV encoding:
 *   byte 0 (xfrm->fixed_shift): L - 1 value (2)
 *   bytes 1 - 15-L (xfrm->fixed_ivlen): nonce (peer's IV)
 *   bytes 16-L - 16: sequence number (the counter)
 */
#define TTLS_CCM_L 				3

static DEFINE_PER_CPU(struct aead_request *, g_req) ____cacheline_aligned;

static struct kmem_cache *ttls_hs_cache = NULL;
static ttls_tft_limit_rec_cb_t *ttls_tft_limit_rec_cb;
static ttls_send_cb_t *ttls_send_cb;
extern ttls_sni_cb_t *ttls_sni_cb;
extern ttls_hs_over_cb_t *ttls_hs_over_cb;
extern ttls_cli_id_t *ttls_cli_id_cb;
extern ttls_alpn_match_t *ttls_alpn_match_cb;
extern ttls_tft_limit_conn_cb_t *ttls_tft_limit_conn_cb;

static inline size_t
ttls_max_ciphertext_len(const TlsXfrm *xfrm)
{
	/*
	 * Although RFC 5246 6.2.3 allows ciphertexts to be as large as
	 * (2^14 + 2048) bytes, actual limits are specific to particular
	 * cipher suites. We are supporting only AEAD ciphers (GCM and CCM).
	 * Their transforms increase data size by a constant amount of bytes.
	 * To be specific, those are explicit part of IV and a tag.
	 */
	return TLS_MAX_PAYLOAD_SIZE + xfrm->minlen;
}

static inline unsigned short
ttls_msg2crypt_len(const TlsIOCtx *io, const TlsXfrm *xfrm)
{
	return io->msglen - ttls_expiv_len(xfrm) - TTLS_TAG_LEN;
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
 * header in @buf, so it can be transmitted to network.
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
	len += ttls_expiv_len(xfrm) + TTLS_TAG_LEN;
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

	WARN_ON_ONCE(len == 0); /* nothing to decrypt */
	WARN_ON_ONCE(!buf && !skb);

	sz = aead_sz = sizeof(*req) + crypto_aead_reqsize(tfm);
	if (buf) {
		off = 0;
		n = *sgn + 1;
	} else {
		off = ttls_payload_off(&tls->xfrm);
		n = *sgn + io->chunks;
	}
	sz += n * sizeof(**sg);

	/* Don't use g_req for better spacial locality. */
	req = tfw_kmalloc(sz, GFP_ATOMIC);
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
	int r = 0;
	size_t n, copied = 0, off = ttls_payload_off(xfrm);
	struct sk_buff *skb = io->skb_list;

	for ( ; skb && copied != TTLS_ALERT_LEN; skb = skb->next) {
		if (unlikely(skb->len <= off)) {
			off -= skb->len;
			continue;
		}
		n = min(skb->len - off, TTLS_ALERT_LEN - copied);
		if ((r = skb_copy_bits(skb, off, &io->alert[copied], n)))
			return r;
		copied += n;
	}

	return skb ? 0 : T_BAD;
}

/**
 * Register I/O callbacks from the underlying network layer.
 */
void
ttls_register_callbacks(ttls_send_cb_t *send_cb, ttls_sni_cb_t *sni_cb,
			ttls_hs_over_cb_t *hs_over_cb, ttls_cli_id_t *cli_id_cb,
			ttls_alpn_match_t *alpn_match_cb,
			ttls_tft_limit_conn_cb_t *tft_limit_conn_cb,
			ttls_tft_limit_rec_cb_t *tft_limit_rec_cb)
{
	ttls_send_cb = send_cb;
	ttls_sni_cb = sni_cb;
	ttls_hs_over_cb = hs_over_cb;
	ttls_cli_id_cb = cli_id_cb;
	ttls_alpn_match_cb = alpn_match_cb;
	ttls_tft_limit_conn_cb = tft_limit_conn_cb;
	ttls_tft_limit_rec_cb = tft_limit_rec_cb;
}
EXPORT_SYMBOL(ttls_register_callbacks);

/**
 * Returns true if handshake is fully processed.
 */
bool
ttls_hs_done(TlsCtx *tls)
{
	return tls->state == TTLS_HANDSHAKE_OVER;
}
EXPORT_SYMBOL(ttls_hs_done);

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

/*
 * There are states in which encryption is not used or performed in advance, as
 * with TTLS_SERVER_FINISHED
 */
bool
ttls_xfrm_need_encrypt(TlsCtx *tls)
{
	return ttls_xfrm_ready(tls) && tls->state != TTLS_SERVER_FINISHED;
}
EXPORT_SYMBOL(ttls_xfrm_need_encrypt);

/**
 * Client-side only.
 *
 * TODO #769: the dst->peer_cert is not released on errors.
 */
static int
ttls_session_copy(TlsSess *dst, const TlsSess *src)
{
	memcpy_fast(dst, src, sizeof(TlsSess));
#if 0
	if (src->peer_cert) {
		int r;

		dst->peer_cert = ttls_x509_crt_alloc();
		if (!dst->peer_cert)
			return -ENOMEM;

		/* TODO: parse the session from the chunked raw certificate? */
		r = ttls_x509_crt_parse_der(dst->peer_cert,
					    ttls_x509_crt_raw(src->peer_cert),
					    src->peer_cert->raw.len);
		if (r) {
			kfree(dst->peer_cert);
			dst->peer_cert = NULL;
			return r;
		}
	}

	if (src->ticket) {
		dst->ticket = tfw_kmalloc(src->ticket_len, GFP_ATOMIC);
		if (!dst->ticket)
			return -ENOMEM;

		memcpy_fast(dst->ticket, src->ticket, src->ticket_len);
	}
#endif

	return 0;
}

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
	int r = 0;
	size_t i, k, md_len;
	const TlsMdInfo *md_info;
	TlsMdCtx md_ctx;
	unsigned char __buf[HASH_MAX_DIGESTSIZE * 3] ____cacheline_aligned;
	unsigned char *tmp = __buf, *h_i = &__buf[HASH_MAX_DIGESTSIZE * 2];

	ttls_md_init(&md_ctx);

	md_info = ttls_md_info_from_type(md_type);
	md_len = ttls_md_get_size(md_info);
	BUG_ON(HASH_MAX_DIGESTSIZE * 2 < md_len + llen + rlen);

	memcpy_fast(tmp + md_len, label, llen);
	memcpy_fast(tmp + md_len + llen, random, rlen);
	llen += rlen;

	/* Compute P_<hash>(secret, label + random)[0..dlen]. */
	r = ttls_md_setup(&md_ctx, md_info, 1);
	if (unlikely(r))
		return r;

	r = ttls_md_hmac_starts(&md_ctx, secret, slen);
	if (unlikely(r))
		goto exit;
	r = ttls_md_hmac_update(&md_ctx, tmp + md_len, llen);
	if (unlikely(r))
		goto exit;
	r = ttls_md_hmac_finish(&md_ctx, tmp);
	if (unlikely(r))
		goto exit;

	for (i = 0; i < dlen; i += md_len) {
		r = ttls_md_hmac_reset(&md_ctx);
		if (unlikely(r))
			goto exit;
		r = ttls_md_hmac_update(&md_ctx, tmp, md_len + llen);
		if (unlikely(r))
			goto exit;
		r = ttls_md_hmac_finish(&md_ctx, h_i);
		if (unlikely(r))
			goto exit;

		r = ttls_md_hmac_reset(&md_ctx);
		if (unlikely(r))
			goto exit;
		r = ttls_md_hmac_update(&md_ctx, tmp, md_len);
		if (unlikely(r))
			goto exit;
		r = ttls_md_hmac_finish(&md_ctx, tmp);
		if (unlikely(r))
			goto exit;

		k = (i + md_len > dlen) ? dlen % md_len : md_len;
		memcpy_fast(dstbuf + i, h_i, k);
	}

exit:
	ttls_md_free(&md_ctx);
	bzero_fast(__buf, HASH_MAX_DIGESTSIZE * 3);

	return r;
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

int
ttls_update_checksum(TlsCtx *tls, const unsigned char *buf, size_t len)
{
	TlsHandshake *hs = tls->hs;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;
	ttls_md_type_t mac;
	int r;

	if (unlikely(!len))
		return 0;

	/*
	 * Initialize the hash context on first call to avoid double
	 * hash calculation.
	 */
	if (unlikely(IS_ERR_OR_NULL(ci))) {
		ttls_sha256_context *sha256 = &hs->tmp_sha256;
		WARN_ON_ONCE(tls->state >= TTLS_SERVER_HELLO);

		if (!ci) {
			if (unlikely(r = ttls_sha256_init_start(sha256)))
				return r;
			tls->xfrm.ciphersuite_info = ERR_PTR(-1);
		}
		r = crypto_shash_update((struct shash_desc *)sha256, buf, len);
		if (unlikely(r))
			return r;
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
			bzero_fast(sha256, sizeof(*sha256));
		}
	}
	if (unlikely(!hs->desc.tfm)) {
		if (mac == TTLS_MD_SHA384)
			r = ttls_sha384_init_start(&hs->fin_sha512);
		else
			r = ttls_sha256_init_start(&hs->fin_sha256);
		if (unlikely(r))
			return r;
	}

	T_DBG2("update checksum on buf %pK len=%ld, hash=%d\n",
	       buf, len, mac);
	T_DBG3_BUF("hash buf ", buf, len);

	return crypto_shash_update(&tls->hs->desc, buf, len);
}

static int
ttls_calc_verify_tls_sha256(TlsCtx *tls, unsigned char hash[32])
{
	ttls_sha256_context sha256;
	int r;

	memcpy_fast(&sha256, &tls->hs->fin_sha256, sizeof(sha256));

	r = crypto_shash_final(&sha256.desc, hash);
	if (likely(!r))
		T_DBG3_BUF("calculated verify sha256 result", hash, 32);

	bzero_fast(&sha256, sizeof(sha256));

	return r;
}

static int
ttls_calc_verify_tls_sha384(TlsCtx *tls, unsigned char hash[48])
{
	ttls_sha512_context sha512;
	int r;

	memcpy_fast(&sha512, &tls->hs->fin_sha512, sizeof(sha512));

	r = crypto_shash_final(&sha512.desc, hash);
	if (likely(!r))
		T_DBG3_BUF("calculated verify sha384 result", hash, 48);

	bzero_fast(&sha512, sizeof(sha512));

	return r;
}

#define TTLS_PRF(hs, sec, slen, lbl, rnd, rlen, buf, blen)		\
({									\
	BUILD_BUG_ON(!__builtin_constant_p(lbl));			\
	(hs)->tls_prf(sec, slen, lbl, sizeof(lbl) - 1, rnd, rlen, buf, blen);\
})

static int
ttls_calc_finished_tls_sha256(TlsCtx *tls, unsigned char *buf, int from)
{
	const int len = 12;
	const char *sender;
	size_t slen;
	TlsSess *sess = &tls->sess;
	ttls_sha256_context sha256;
	unsigned char padbuf[SHA256_DIGEST_SIZE];
	int r;

	memcpy_fast(&sha256, &tls->hs->fin_sha256, sizeof(sha256));

	/* TLSv1.2: hash = PRF(master, finished_label, Hash(handshake))[0.11] */
	T_DBG3_BUF("finished sha256 state",
		   ((struct sha256_state *)shash_desc_ctx(&sha256.desc))->state,
		   SHA256_DIGEST_SIZE);

	sender = (from == TTLS_IS_CLIENT)
		 ? "client finished"
		 : "server finished";
	slen = sizeof("client finished") - 1;

	r = crypto_shash_final(&sha256.desc, padbuf);
	if (unlikely(r))
		goto exit;

	r = tls->hs->tls_prf(sess->master, 48, sender, slen, padbuf,
			     SHA256_DIGEST_SIZE, buf, len);
	if (likely(r))
		T_DBG3_BUF("calc finished sha256 result", buf, len);

exit:
	bzero_fast(&sha256, sizeof(sha256));
	bzero_fast(padbuf, sizeof(padbuf));

	return r;
}

static int
ttls_calc_finished_tls_sha384(TlsCtx *tls, unsigned char *buf, int from)
{
	const int len = 12;
	const char *sender;
	size_t slen;
	TlsSess *sess = &tls->sess;
	ttls_sha512_context sha512;
	unsigned char padbuf[SHA384_DIGEST_SIZE];
	int r;

	memcpy_fast(&sha512, &tls->hs->fin_sha512, sizeof(sha512));

	/* TLSv1.2: hash = PRF(master, finished_label, Hash(handshake))[0.11] */
	T_DBG3_BUF("finished sha512 state",
		   ((struct sha512_state *)shash_desc_ctx(&sha512.desc))->state,
		   SHA512_DIGEST_SIZE);

	sender = (from == TTLS_IS_CLIENT)
		 ? "client finished"
		 : "server finished";
	slen = sizeof("client finished") - 1;

	r = crypto_shash_final(&sha512.desc, padbuf);
	if (unlikely(r))
		goto exit;

	r = tls->hs->tls_prf(sess->master, 48, sender, slen, padbuf,
			     SHA384_DIGEST_SIZE, buf, len);
	if (likely(!r))
		T_DBG3_BUF("calc finished sha512 result", buf, len);

exit:
	bzero_fast(&sha512, sizeof(sha512));
	bzero_fast(padbuf, sizeof(padbuf));

	return r;
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
	int r = 0;
	TlsSess *sess = &tls->sess;
	TlsXfrm *xfrm = &tls->xfrm;
	TlsHandshake *hs = tls->hs;

	ci = ttls_cipher_info_from_type(xfrm->ciphersuite_info->cipher);
	md_info = ttls_md_info_from_type(xfrm->ciphersuite_info->mac);

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

			r = tls->hs->calc_verify(tls, session_hash);
			if (unlikely(r))
				return r;

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
			T_WARN("prf master secret error, %d\n", r);
			return r;
		}
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
		T_WARN("prf key expansion error, %d\n", r);
		return r;
	}

	T_DBG("ciphersuite = %s\n",
	      ttls_get_ciphersuite_name(sess->ciphersuite));
	T_DBG3_BUF("master secret", sess->master, 48);
	T_DBG3_BUF("random bytes", hs->randbytes, 64);
	T_DBG3_BUF("key block", keyblk, 256);

	/* We'll reuse the memory area on ClientFinished, so clean it up now. */
	bzero_fast(hs->randbytes, sizeof(hs->randbytes));

	/* Determine the appropriate key, IV and MAC length. */
	xfrm->keylen = ci->key_len;
	if (ci->mode == TTLS_MODE_GCM || ci->mode == TTLS_MODE_CCM) {
		xfrm->maclen = 0;
		mac_key_len = 0;
		xfrm->ivlen = 12;
		xfrm->fixed_ivlen = 4;
		xfrm->fixed_shift = (ci->mode == TTLS_MODE_CCM ? 1 : 0);
		WARN_ON_ONCE(ttls_expiv_len(xfrm) != TTLS_IV_LEN);
		/* Minimum length is expicit IV + tag */
		xfrm->minlen = ttls_expiv_len(xfrm) + TTLS_TAG_LEN;
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
	T_DBG("keylen=%u minlen=%u ivlen=%u maclen=%u mac_key_len=%lu\n",
	      xfrm->keylen, xfrm->minlen, xfrm->ivlen, xfrm->maclen, mac_key_len);

	/* Finally setup the cipher contexts, IVs and MAC secrets. */
	if (tls->conf->endpoint == TTLS_IS_CLIENT) {
		key1 = keyblk + mac_key_len * 2;
		key2 = keyblk + mac_key_len * 2 + xfrm->keylen;
		mac_enc = keyblk;
		mac_dec = keyblk + mac_key_len;
		iv_copy_len = xfrm->fixed_ivlen ? : xfrm->ivlen;
		memcpy_fast(xfrm->iv_enc + xfrm->fixed_shift,
			    key2 + xfrm->keylen,
			    iv_copy_len);
		memcpy_fast(xfrm->iv_dec + xfrm->fixed_shift,
			    key2 + xfrm->keylen + iv_copy_len,
			    iv_copy_len);
	} else {
		key1 = keyblk + mac_key_len * 2 + xfrm->keylen;
		key2 = keyblk + mac_key_len * 2;
		mac_enc = keyblk + mac_key_len;
		mac_dec = keyblk;
		iv_copy_len = xfrm->fixed_ivlen ? : xfrm->ivlen;
		memcpy_fast(xfrm->iv_dec + xfrm->fixed_shift,
			    key1 + xfrm->keylen,
			    iv_copy_len);
		memcpy_fast(xfrm->iv_enc + xfrm->fixed_shift,
			    key1 + xfrm->keylen + iv_copy_len,
			    iv_copy_len);
	}

	if (ci->mode == TTLS_MODE_CCM)
		xfrm->iv_dec[0] = xfrm->iv_enc[0] = TTLS_CCM_L - 1;

	T_DBG3_BUF("derive keys: IV_enc fixed", xfrm->iv_enc, iv_copy_len);
	T_DBG3_BUF("derive keys: key_enc", key1, ci->key_len);
	T_DBG3_BUF("derive keys: IV_dec fixed", xfrm->iv_dec, iv_copy_len);
	T_DBG3_BUF("derive keys: key_dec", key2, ci->key_len);

	if (mac_key_len) {
		r = ttls_md_hmac_starts(&xfrm->md_ctx_enc, mac_enc,
					mac_key_len);
		if (unlikely(r))
			return r;
		r = ttls_md_hmac_starts(&xfrm->md_ctx_dec, mac_dec,
					mac_key_len);
		if (unlikely(r))
			return r;
	}

	if ((r = ttls_cipher_setup(&xfrm->cipher_ctx_enc, ci, TTLS_TAG_LEN))) {
		T_WARN("cannot setup encryption cipher, %d\n", r);
		return r;
	}
	if ((r = ttls_cipher_setup(&xfrm->cipher_ctx_dec, ci, TTLS_TAG_LEN))) {
		T_WARN("cannot setup decryption cipher, %d\n", r);
		return r;
	}

	r = crypto_aead_setkey(xfrm->cipher_ctx_enc.cipher_ctx, key1, ci->key_len);
	if (r) {
		T_WARN("cannot set encryption key, %d\n", r);
		return r;
	}

	r = crypto_aead_setkey(xfrm->cipher_ctx_dec.cipher_ctx, key2, ci->key_len);
	if (r) {
		T_WARN("cannot set decryption key, %d\n", r);
		return r;
	}

	bzero_fast(keyblk, sizeof(keyblk));

	return 0;
}

/*
 * Fill in the buffer with additional authentication data for AES-GCM,
 * RFC 5246 6.2.3.3.
 * TODO replace with standard tls_make_aad() defined in include/net/tls.h in
 * modern kernels.
 */
static void
ttls_make_aad(const TlsCtx *tls, TlsIOCtx *io, unsigned char *aad_buf)
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
 * Fallback to kmalloc() if we use not enough reserved memory in TlsReq and
 * print a warning to reserve bit more memory.
 */
struct aead_request *
ttls_aead_req_alloc(struct crypto_aead *tfm)
{
	size_t need = sizeof(struct aead_request) + crypto_aead_reqsize(tfm);

	WARN_ON_ONCE(!in_serving_softirq());
	if (WARN_ON_ONCE(ttls_aead_reqsize() < need))
		return tfw_kzalloc(need, GFP_ATOMIC);

	return *this_cpu_ptr(&g_req);
}

void
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
	if (unlikely(!req)) {
		T_WARN("Cannot allocate a request for TLS encryption\n");
		return -ENOMEM;
	}

	*(long *)(xfrm->iv_enc + xfrm->fixed_shift + xfrm->fixed_ivlen) = iv;
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
		T_WARN("AEAD encryption failed while record encryption: %d\n", r);
		goto err;
	}
	T_DBG3_SL("encrypted buf (first 64 bytes)", sgt->sgl, sgt->nents, 0,
		  min_t(size_t, 64, io->msglen + TLS_HEADER_SIZE));

	if (unlikely(++io->ctr > (~0UL >> 1)))
		TTLS_WARN(tls, "outgoing message counter would wrap\n");

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
	struct aead_request *req;
	struct scatterlist *sg = NULL;
	unsigned char aad_buf[TLS_AAD_SPACE_SIZE];

	if (unlikely(io->msglen < xfrm->minlen)) {
		T_WARN("message lenght (%u) < min. ciphertext length (%u)\n",
		       io->msglen, xfrm->minlen);
		return TTLS_ERR_INVALID_MAC;
	}

	expiv_len = ttls_expiv_len(xfrm);
	mode = xfrm->cipher_ctx_enc.cipher_info->mode;

	WARN_ON_ONCE(mode != TTLS_MODE_GCM && mode != TTLS_MODE_CCM);
	T_DBG2("decrypt input record from network: hdr=%pK msglen=%d chunks=%u"
	       " eiv_len=%lu\n", io->hdr, io->msglen, io->chunks, expiv_len);
	if (unlikely(io->msglen < expiv_len + TTLS_TAG_LEN)) {
		T_WARN("message lenght (%u) < explicit IV length (%lu) + "
		       "tag length (16)\n", io->msglen, expiv_len);
		return TTLS_ERR_INVALID_MAC;
	}

	dec_msglen = io->msglen - expiv_len - TTLS_TAG_LEN;

	memcpy_fast(xfrm->iv_dec + xfrm->fixed_shift + xfrm->fixed_ivlen,
		    io->iv, sizeof(io->iv));
	req = ttls_crypto_req_sglist(tls, tfm, dec_msglen + TTLS_TAG_LEN, buf,
				     &sg, &sgn);
	if (!req)
		return TTLS_ERR_INTERNAL_ERROR;
	if (WARN_ON_ONCE(sgn < 2)) {
		r = TTLS_ERR_INTERNAL_ERROR;
		goto out;
	}
	ttls_make_aad(tls, io, aad_buf);
	sg_set_buf(sg, aad_buf, TLS_AAD_SPACE_SIZE);

	T_DBG3_BUF("IV used", xfrm->iv_dec, xfrm->ivlen);
	T_DBG3_SL("decrypt: AAD|msg|TAG", sg, sgn, 0, TLS_AAD_SPACE_SIZE +
		  dec_msglen + TTLS_TAG_LEN);

	/*
	 * Decrypt and authenticate.
	 * Write decrypted data in-place to the original skb by offset of IV.
	 *
	 * TODO #1064 it seems actually the kernel unable to decrypt scatterlist
	 * w/o copies since gcmaes_decrypt() requires input and output segments
	 * to be marked as ends.
	 */
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, TLS_AAD_SPACE_SIZE);
	/* The crypto layer expects AAD segment in output scatter list. */
	aead_request_set_crypt(req, sg, sg, dec_msglen + TTLS_TAG_LEN,
			       xfrm->iv_dec);
	r = crypto_aead_decrypt(req);

	T_DBG3_SL("raw buffer after decryption", sg + 1, sgn - 1, 0,
		  dec_msglen);

	if (unlikely(++io->ctr > (~0UL >> 1)))
		T_WARN("incoming message counter would wrap\n");

out:
	kfree(req);

	return r;
}

static int
ttls_decrypt(TlsCtx *tls, unsigned char *buf)
{
	int r;
	TlsIOCtx *io = &tls->io_in;

	if (io->msglen > ttls_max_ciphertext_len(&tls->xfrm)) {
		T_WARN("message length (%u) > max. ciphertext length\n",
		       io->msglen);
		return -EINVAL;
	}

	if ((r = __ttls_decrypt(tls, buf))) {
		/* Error out (and send alert) on invalid records */
		if (r == TTLS_ERR_INVALID_MAC)
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_BAD_RECORD_MAC,
					TTLS_F_ST_CLOSE);
		T_DBG2("decryption failed: %d", r);
		return r;
	}

	/*
	 * Three or more empty messages may be a DoS attack
	 * (excessive CPU consumption).
	 */
	if (unlikely(!io->msglen && ++tls->nb_zero > 3)) {
		T_WARN("received four consecutive empty messages,"
		       " possible DoS attack\n");
		return T_BLOCK_WITH_RST;
	} else {
		tls->nb_zero = 0;
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
int
__ttls_add_record(TlsCtx *tls, struct sg_table *sgt, int sg_i,
		  unsigned char *hdr_buf)
{
	TlsIOCtx *io = &tls->io_out;
	int r;

	T_DBG("write record: type=%d len=%d hslen=%u sgt=%pK/%u sg_i=%d"
	      " ready=%d\n", io->msgtype, io->msglen, io->hslen, sgt,
	      sgt ? sgt->nents : 0, sg_i, ttls_xfrm_ready(tls));

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

		if (io->hslen && d < io->hslen) {
			r = ttls_update_checksum(tls, io->hs_hdr + d,
						 io->hslen - d);
			if (unlikely(r))
				return r;
		}
		if (sgt) {
			struct scatterlist *sg;
			for (sg = &sgt->sgl[sg_i]; sg_i < sgt->nents;
			     sg_i++, sg = sg_next(sg))
			{
				if (unlikely(d >= sg->length)) {
					d -= sg->length;
					continue;
				}
				r = ttls_update_checksum(tls, sg_virt(sg) + d,
							 sg->length - d);
				if (unlikely(r))
					return r;
				d = 0;
			}
		}
	}

	/*
	 * Write TLS header if the record should not be encrypted.
	 * Otherwise tfw_tls_encrypt() -> ttls_aad2hdriv(), called from
	 * sk_write_xmit(), will do this for us.
	 */
	if (!ttls_xfrm_ready(tls))
		ttls_write_hdr(tls, io->msgtype, io->msglen,
			       hdr_buf ? : io->hdr);
	return 0;
}

int
__ttls_send_record(TlsCtx *tls, struct sg_table *sgt)
{
	int r;

	if ((r = ttls_send_cb(tls, sgt)))
		T_DBG("TLS send callback error %d\n", r);
	return r;
}

static int
ttls_write_record(TlsCtx *tls, struct sg_table *sgt)
{
	int r;

	/* Change __ttls_add_record() call if you need it for handshakes. */
	WARN_ON_ONCE(tls->io_out.msgtype == TTLS_MSG_HANDSHAKE);

	if (unlikely(r = __ttls_add_record(tls, NULL, 0, NULL)))
		return r;

	return __ttls_send_record(tls, sgt);
}

static int
ttls_hdr_check(TlsCtx *tls)
{
	TlsIOCtx *io = &tls->io_in;

	/* Check record type */
	if (unlikely(io->msgtype < TTLS_MSG_CHANGE_CIPHER_SPEC
		     || io->msgtype > TTLS_MSG_APPLICATION_DATA))
	{
		T_WARN("unknown record type %d\n", io->msgtype);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_UNEXPECTED_MESSAGE,
				TTLS_F_ST_CLOSE);

		return -EINVAL;
	}
	/* Drop unexpected ChangeCipherSpec messages. */
	if (io->msgtype == TTLS_MSG_CHANGE_CIPHER_SPEC
	    && ttls_state(tls) != TTLS_CLIENT_CHANGE_CIPHER_SPEC
	    && ttls_state(tls) != TTLS_SERVER_CHANGE_CIPHER_SPEC)
	{
		T_WARN("dropping unexpected ChangeCipherSpec\n");
		return -EINVAL;
	}
	/* Check length against bounds of the current transform and version */
	if (!ttls_xfrm_ready(tls)) {
		/* Cipher's not ready yet, plaintext limits apply. */
		if (io->msglen < 1 || io->msglen > TLS_MAX_PAYLOAD_SIZE) {
			T_WARN("message length (%u) > max payload size\n",
			       io->msglen);
			return -EINVAL;
		}
	} else {
		if (io->msglen < tls->xfrm.minlen ||
		    io->msglen > ttls_max_ciphertext_len(&tls->xfrm))
		{
			T_WARN("bad message length %u\n", io->msglen);
			return -EINVAL;
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
	/*
	 * The only valid major version accordingly to RFC 5246 (TLS 1.2) and
	 * RFC 8446 (TLS 1.3) is 0x03, so treat any different values as an
	 * attempt to confuse us and block such records.
	 *
	 * However RFC 8446 5.1 and D.2 suggest to tolerate minor versions
	 * 0x01 in ClientHello for compatibility reasons and 5.1 requres to
	 * ignore the legacy_record_version field in the record header.
	 * In fact, OpenSSL may send 0x0301 with ClientHello.
	 * The higher minor version is still 0x03.
	 */
	if (unlikely(io->hdr[1] != 3 || io->hdr[2] < 1 || io->hdr[2] > 3)) {
		T_WARN("bad TLS version %u:%u\n", io->hdr[1], io->hdr[2]);
		return T_BLOCK_WITH_RST;
	}
	io->msglen = ((unsigned short)io->hdr[3] << 8) | io->hdr[4];

	T_DBG3("input rec: type=%d ver=%u:%u msglen=%d read=%u xfrm_ready=%d\n",
	       io->msgtype, io->hdr[1], io->hdr[2], io->msglen, *read, ready);

	if ((r = ttls_hdr_check(tls)))
		return r;
	switch (io->msgtype) {
	case TTLS_MSG_ALERT:
		/* Alerts are unencrypted during handshake only. */
		if (!ready) {
			ivahs_len = 2; /* level & description */
			if (io->msglen != ivahs_len) {
				/* TODO: multiple alerts in one record? */
				T_WARN("unexpected alert message length: %d,"
				       " expected: %d\n",
				       io->msglen, ivahs_len);
				return TTLS_ERR_INVALID_RECORD;
			}
			break;
		}
		/*
		 * Read IV for the encrypted alert as we do this for
		 * application data records.
		 */
		fallthrough;

	case TTLS_MSG_APPLICATION_DATA:
		if (unlikely(!ready))
			return TTLS_ERR_INVALID_RECORD;
		ivahs_len = ttls_expiv_len(&tls->xfrm);
		break;

	case TTLS_MSG_CHANGE_CIPHER_SPEC:
		/* Read 1 byte equal to 0x1. */
		ivahs_len = 1;
		if (io->msglen != ivahs_len) {
			T_WARN("unexpected ChangeCipherSpec message length: "
			       "%d, expected: %d\n", io->msglen, ivahs_len);
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
				T_WARN("handshake message too short: %d, "
				       "expected: ivahs_len\n", io->msglen);
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
		memcpy_fast(io->__msg + io->hdr_cpsz - TLS_HEADER_SIZE,
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
	memcpy_fast(io->__msg + io->hdr_cpsz - TLS_HEADER_SIZE, buf + n,
		    ivahs_len);
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
			TTLS_WARN(tls, "too short client handshake message: %u\n",
			      io->hslen);
			return -EINVAL;
		}

		/* With TLS we don't handle fragmentation (for now) */
		if (io->msglen < io->hslen) {
			T_WARN("TLS handshake fragmentation not supported\n");
			return TTLS_ERR_FEATURE_UNAVAILABLE;
		}
	}

	return T_OK;
}

static void
ttls_handshake_free(TlsHandshake *hs)
{
	if (unlikely(!hs))
		return;

	if (!IS_ERR_OR_NULL(hs->desc.tfm))
		crypto_free_shash(hs->desc.tfm);
	if (!IS_ERR_OR_NULL(hs->tmp_sha256.desc.tfm))
		crypto_free_shash(hs->tmp_sha256.desc.tfm);

	if (hs->crypto_ctx)
		ttls_mpi_pool_free(hs->crypto_ctx);

	bzero_fast(hs, sizeof(TlsHandshake));
	kmem_cache_free(ttls_hs_cache, hs);
}

void
ttls_handshake_wrapup(TlsCtx *tls)
{
	/* Free our hs params. */
	ttls_handshake_free(tls->hs);
	tls->hs = NULL;
}

/**
 * Process TLS alerts.
 */
static int
ttls_handle_alert(TlsCtx *tls)
{
	TlsIOCtx *io = &tls->io_in;

	T_DBG("got an alert message, type=%d:%d\n", io->alert[0], io->alert[1]);

	/* Ignore non-fatal alerts, except close_notify. */
	if (io->alert[0] == TTLS_ALERT_LEVEL_FATAL) {
		T_DBG2("is a fatal alert message (msg %d)\n", io->alert[1]);
		return T_BAD;
	}
	if (io->alert[0] == TTLS_ALERT_LEVEL_WARNING
	    && io->alert[1] == TTLS_ALERT_MSG_CLOSE_NOTIFY)
	{
		T_DBG2("is a close notify message\n");
		ttls_close_notify(tls, TTLS_F_ST_CLOSE);
		return T_BAD;
	}

	/* Silently ignore: fetch new message */
	return T_OK;
}

/**
 * Send an alert message.
 *
 * @lvl	- the alert level of the message (TTLS_ALERT_LEVEL_WARNING or
 * 	  TTLS_ALERT_LEVEL_FATAL)
 * @msg	- the alert message (SSL_ALERT_MSG_*)
 */
int
ttls_send_alert(TlsCtx *tls, unsigned char lvl, unsigned char msg,
		int close_type)
{
	int r;
	TlsIOCtx *io = &tls->io_out;

	T_DBG("send alert level=%u message=%u\n", lvl, msg);
	BUG_ON(close_type != TTLS_F_ST_SHUTDOWN
	       && close_type != TTLS_F_ST_CLOSE);

	io->msgtype = TTLS_MSG_ALERT;
	io->hstype = TTLS_HS_INVALID;
	io->st_flags |= close_type;
	/* Set hslen just in case of non-critical handshake alert. */
	io->msglen = io->hslen = 2;
	io->alert[0] = lvl;
	io->alert[1] = msg;

	if ((r = ttls_write_record(tls, NULL)))
		T_WARN("Cannot send TLS alert %d:%d, %d\n", msg, lvl, r);

	return r;
}

int
ttls_write_certificate(TlsCtx *tls, struct sg_table *sgt,
		       unsigned char **in_buf)
{
	unsigned int i, sg_i;
	size_t tot_len = 0;
	const TlsX509Crt *crt;
	TlsIOCtx *io = &tls->io_out;
	unsigned char *p = *in_buf;
	int r;

	if (tls->conf->endpoint == TTLS_IS_CLIENT && !tls->client_auth) {
		T_DBG2("<= skip write certificate");
		tls->state++;
		return 0;
	}

	/*
	 * Remember the sg index for record checksum update.
	 * Set the fragment now, but write the certificate record later, when
	 * we have the final record legth - if we fail somwhere at the middle,
	 * let the called to cleanup all the frags.
	 */
	sg_i = sgt->nents++;
	sg_set_buf(&sgt->sgl[sg_i], p, TLS_HEADER_SIZE + 7);
	get_page(virt_to_page(p));

	if (tls->conf->endpoint == TTLS_IS_SERVER && !ttls_own_cert(tls)) {
		TTLS_WARN(tls, "got no certificate to send\n");
		return TTLS_ERR_CERTIFICATE_REQUIRED;
	}

	/*
	 * Write the certifictes chain.
	 * All the certificates are placed in separate pages by the x509 parser.
	 *
	 *   7 . 9	length of cert. 1
	 *  10 . n-1	peer certificate
	 *   n . n+2	length of cert. 2
	 * n+3 . ...	upper level cert, etc.
	 */
	crt = ttls_own_cert(tls);
	BUG_ON(crt->raw.tot_len > TLS_MAX_PAYLOAD_SIZE - 7);
	for (i = 0; i < (crt->raw.tot_len + PAGE_SIZE - 1) / PAGE_SIZE; ++i) {
		void *frag_p = (char *)crt->raw.pages + i * PAGE_SIZE;
		size_t frag_sz = min(PAGE_SIZE, crt->raw.tot_len - i * PAGE_SIZE);

		if (unlikely(sgt->nents >= MAX_SKB_FRAGS)) {
			T_WARN("Too many certfificates\n");
			return -ENOSPC;
		}

		get_page(virt_to_page(frag_p));
		sg_set_buf(&sgt->sgl[sgt->nents++], frag_p, frag_sz);
		T_DBG3("add cert page %pK,len=%lu order=%u seg=%u\n",
		       frag_p, frag_sz, crt->raw.order, sgt->nents - 1);
	}
	tot_len += crt->raw.tot_len;

	/*
	 * Write thr handshake headers on our own (TLS_HEADER_SIZE + 7 bytes).
	 *
	 *  0 . 4	record header (to be written in __ttls_add_record()
	 *  5 . 5	handshake type (certificate)
	 *  6 . 8	handshake length
	 *  9 . 11	length of all certs
	 */
	io->msglen = tot_len + 7;
	ttls_write_hshdr(TTLS_HS_CERTIFICATE, p + TLS_HEADER_SIZE, tot_len + 7);
	p[9] = (unsigned char)(tot_len >> 16);
	p[10] = (unsigned char)(tot_len >> 8);
	p[11] = (unsigned char)tot_len;
	r = __ttls_add_record(tls, sgt, sg_i, p);
	*in_buf = p + TLS_HEADER_SIZE + 7;

	return r;
}

/**
 * Client-side only.
 *
 * TODO #769: the dst->peer_cert is not released on errors.
 */
int
ttls_parse_certificate(TlsCtx *tls, unsigned char *buf, size_t len,
		       unsigned int *read)
{
#if 0
	uint8_t alert;
	unsigned int vr = 0;
	int r = 0, i = 0, n, authmode;
	TlsIOCtx *io = &tls->io_in;
	TlsSess *sess = &tls->sess;
	struct page *pg = NULL;
	unsigned char *p = buf;
	unsigned char *state_p = buf;
	T_FSM_INIT(ttls_substate(tls), "TLS ClientCertificate");

	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);
	if (io->hstype != TTLS_HS_CERTIFICATE
	    || io->hslen < 3 + 3)
	{
		TTLS_WARN(tls, "bad certificate message length %d\n", io->hslen);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR,
				TTLS_F_ST_CLOSE);
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
		int order = get_order(io->hslen);
		gfp_t flags = order > 0 ? GFP_ATOMIC | __GFP_COMP : GFP_ATOMIC;

		if (!(pg = alloc_pages(flags, order))) {
			T_WARN("TLS: cannot allocate pages for a certificate\n");
			return -ENOMEM;
		}
		p = (unsigned char *)page_address(pg);
		tls->hs->cert_page_address = p;
		T_FSM_JMP(TTLS_CC_HS_READ);
	}
	T_FSM_STATE(TTLS_CC_HS_READ) {
		p = tls->hs->cert_page_address;
		n = min_t(size_t, io->hslen - io->rlen, len);
		memcpy_fast(p + io->rlen, buf, n);
		*read += n;
		io->rlen += n;
		if (io->rlen == io->hslen)
			T_FSM_JMP(TTLS_CC_HS_PARSE);
		tls->state = ttls_state(tls) + TTLS_CC_HS_READ;
		return T_POSTPONE;
	}
	T_FSM_STATE(TTLS_CC_HS_PARSE) {
		p = tls->hs->cert_page_address;
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
		TTLS_WARN(tls, "TLS client has no certificate\n");

		/*
		 * The client was asked for a certificate but didn't send
		 * one. The client should know what's going on, so we don't
		 * send an alert.
		 */
		vr = TTLS_X509_BADCERT_MISSING;
		if (authmode != TTLS_VERIFY_OPTIONAL)
			r = TTLS_ERR_NO_CLIENT_CERTIFICATE;
		goto err;
	}

	/* Same message structure as in ttls_write_certificate(). */
	n = (p[i + 1] << 8) | p[i + 2];

	if (p[i] != 0 || io->hslen != n + 3) {
		TTLS_WARN(tls, "bad certificate message\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR,
				TTLS_F_ST_CLOSE);
		r = TTLS_ERR_BAD_HS_CERTIFICATE;
		goto err;
	}

	/* In case we tried to reuse a session but it failed */
	ttls_x509_crt_destroy(&sess->peer_cert);
	sess->peer_cert = ttls_x509_crt_alloc();
	if (!sess->peer_cert) {
		TTLS_WARN(tls, "can not allocate a certificate\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_INTERNAL_ERROR,
				TTLS_F_ST_CLOSE);
		r = TTLS_ERR_ALLOC_FAILED;
		goto err;
	}

	for (i += 3; i < io->hslen; i += n) {
		if (p[i]) {
			TTLS_WARN(tls, "bad certificate message\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR,
					TTLS_F_ST_CLOSE);
			r = TTLS_ERR_BAD_HS_CERTIFICATE;
			goto err;
		}

		n = ((unsigned int)p[i + 1] << 8) | (unsigned int)p[i + 2];
		i += 3;

		if (n < 128 || i + n > io->hslen) {
			TTLS_WARN(tls, "bad certificate message\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR,
					TTLS_F_ST_CLOSE);
			r = TTLS_ERR_BAD_HS_CERTIFICATE;
			goto err;
		}

		r = ttls_x509_crt_parse_der(sess->peer_cert, p + i, n);
		switch(r) {
		case 0: /*ok*/
		case TTLS_ERR_X509_UNKNOWN_SIG_ALG:
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
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL, alert,
					TTLS_F_ST_CLOSE);
			TTLS_WARN(tls, "cannot parse DER certificate, %d\n", r);
			goto err;
		}
	}

	if (authmode != TTLS_VERIFY_NONE) {
		unsigned int vr_tmp;
		const TlsPkCtx *pk = &sess->peer_cert->pk;
		TlsX509Crt *ca_chain = tls->hs->key_cert->ca_chain;
		ttls_x509_crl *ca_crl = tls->hs->key_cert->ca_crl;

		/* Main check: verify certificate */
		r = ttls_x509_crt_verify(sess->peer_cert, ca_chain, ca_crl,
					 tls->hostname, &vr);
		if (r)
			TTLS_WARN(tls, "client cert verification failed, %d\n", r);

		/*
		 * Secondary checks: always done, but change 'r' only if it was
		 * 0. If certificate uses an EC key, make sure the curve is OK.
		 */
		if (ttls_pk_can_do(pk, TTLS_PK_ECKEY)
		    && ttls_check_curve(tls, ttls_pk_ec(*pk)->grp->id))
		{
			vr |= TTLS_X509_BADCERT_BAD_KEY;
			TTLS_WARN(tls, "bad certificate (EC key curve)\n");
			if (!r)
				r = TTLS_ERR_BAD_HS_CERTIFICATE;
		}

		vr_tmp = ttls_check_cert_usage(sess->peer_cert,
					       tls->xfrm.ciphersuite_info,
					       !tls->conf->endpoint);
		if (vr_tmp) {
			TTLS_WARN(tls, "bad certificate (usage extensions), %x\n",
				  vr_tmp);
			vr |= vr_tmp;
			if (!r)
				r = TTLS_ERR_BAD_HS_CERTIFICATE;
		}

		/*
		 * ttls_x509_crt_verify() is supposed to report a
		 * verification failure through TTLS_ERR_X509_CERT_VERIFY_FAILED,
		 * with details encoded in the verification flags. All other
		 * kinds of error codes, are treated as fatal and lead to a
		 * failure of ssl_parse_certificate even if verification was
		 * optional.
		 */
		if (authmode == TTLS_VERIFY_OPTIONAL
		    && (r == TTLS_ERR_X509_CERT_VERIFY_FAILED
			|| r == TTLS_ERR_BAD_HS_CERTIFICATE))
		{
			r = 0;
		}

		if (!ca_chain && authmode == TTLS_VERIFY_REQUIRED) {
			TTLS_WARN(tls, "got no CA chain\n");
			r = TTLS_ERR_CA_CHAIN_REQUIRED;
		}

		if (r) {
			/*
			 * The certificate may have been rejected for several
			 * reasons. Pick one and send the corresponding alert.
			 * Which alert to send may be a subject of debate in
			 * some cases.
			 */
			TTLS_WARN(tls, "Rejected certificate verification flags"
				  " %x\n", vr);
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
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL, alert,
					TTLS_F_ST_CLOSE);
		}
	}
err:
	if (pg)
		__free_pages(pg, 2);
	return r;
#else
	return 0;
#endif
}

int
ttls_write_change_cipher_spec(TlsCtx *tls, struct sg_table *sgt,
			      unsigned char **in_buf)
{
	/*
	 * The ChangeCipherSpec message is added after another message:
	 * NewSessionTicket on full handshake or ServerHello on abbreviated one.
	 */
	if (likely(in_buf)) {
		ttls_write_hdr(tls, TTLS_MSG_CHANGE_CIPHER_SPEC, 1, *in_buf);
		get_page(virt_to_page(*in_buf));
		sg_set_buf(&sgt->sgl[sgt->nents++], *in_buf, TLS_HEADER_SIZE + 1);
		(*in_buf)[TLS_HEADER_SIZE] = 1;
		*in_buf += TLS_HEADER_SIZE + 1;
	}
	/* The ChangeCipherSpec message is the first one at this step. */
	else {
		TlsIOCtx *io = &tls->io_out;

		io->msglen = io->hslen = 1;
		io->msgtype = TTLS_MSG_CHANGE_CIPHER_SPEC;
		io->hstype = TTLS_HS_INVALID;
		io->hs_hdr[0] = 1;

		return __ttls_add_record(tls, NULL, 0, NULL);
	}

	return 0;
}

/**
 * Process the ChangeCipherSpec message.
 * This function actually doesn't change the cipher specification as defined in
 * the RFC since changing cipher spec may lead to the CCS injection attack.
 * See description of the attack and the testing script at
 * https://nmap.org/nsedoc/scripts/ssl-ccs-injection.html
 */
int
ttls_parse_change_cipher_spec(TlsCtx *tls, unsigned char *buf, size_t len,
			      unsigned int *read)
{
	TlsIOCtx *io = &tls->io_in;

	if (io->msgtype != TTLS_MSG_CHANGE_CIPHER_SPEC) {
		TTLS_WARN(tls, "bad change cipher spec message type: %s,"
			  " Change Cipher Spec expected\n",
			  msgtype_to_str(io->msgtype));
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_UNEXPECTED_MESSAGE,
				TTLS_F_ST_CLOSE);
		return TTLS_ERR_UNEXPECTED_MESSAGE;
	}
	if (io->msglen != 1 || io->hstype != 1) {
		TTLS_WARN(tls, "bad change cipher spec message, len=%u"
			  " type=%s\n", io->msglen, hstype_to_str(io->hstype));
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR,
				TTLS_F_ST_CLOSE);
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
	r = tls->hs->calc_finished(tls, msg + TTLS_HS_HDR_LEN,
				   tls->conf->endpoint);
	if (unlikely(r))
		return r;
	/*
	 * On abbreviated handshake order of Finished messages are reversed:
	 * first server sends his Finished message, then client. The last
	 * recipient adds Finished message from other side into its checksum
	 * to validate handshake integrity. See ttls_parse_finished() for the
	 * same effect in full handshake path.
	 */
	if (tls->hs->resume) {
		r = ttls_update_checksum(tls, msg,
					 TTLS_HS_HDR_LEN + TLS_HASH_LEN);
		if (unlikely(r))
			return r;
	}

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
	int r;
	unsigned int n, ct_len;
	TlsIOCtx *io = &tls->io_in;
	TlsXfrm *xfrm = &tls->xfrm;
	TlsHandshake *hs = tls->hs;
	unsigned char hash[TLS_HASH_LEN];

	T_DBG("%s: msglen=%u(rlen=%u len=%lu)\n", __func__,
	      io->msglen, io->rlen, len);
	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);

	if (unlikely(!ttls_xfrm_ready(tls))) {
		TTLS_WARN(tls, "TLS context isn't ready on Finished\n");
		return TTLS_ERR_BAD_HS_FINISHED;
	}
	if (unlikely(io->msglen != TTLS_HS_FINISHED_BODY_LEN)) {
		TTLS_WARN(tls, "wrong ClientFinished message length: %u\n",
			  io->msglen);
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

	if ((r = ttls_decrypt(tls, hs->finished)))
		return r;
	/* Verify the handshake header. */
	if (unlikely(hs->finished[0] != TTLS_HS_FINISHED
		     || hs->finished[1] || hs->finished[2]
		     || hs->finished[3] != TLS_HASH_LEN))
	{
		TTLS_WARN(tls, "TLS bad finished message\n");
		T_DBG3_BUF("finished message: ",
			   hs->finished, TTLS_HS_HDR_LEN);
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR,
				TTLS_F_ST_CLOSE);
		return TTLS_ERR_BAD_HS_FINISHED;
	}

	r = tls->hs->calc_finished(tls, hash, tls->conf->endpoint ^ 1);
	if (unlikely(r))
		return r;

	if (crypto_memneq(&hs->finished[TTLS_HS_HDR_LEN], hash, TLS_HASH_LEN)) {
		TTLS_WARN(tls, "bad hash in finished message\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR,
				TTLS_F_ST_CLOSE);
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
	return ttls_update_checksum(tls, hs->finished,
				    TTLS_HS_HDR_LEN + TLS_HASH_LEN);
}

int
ttls_ctx_init(TlsCtx *tls, const TlsCfg *conf)
{
	bzero_fast(tls, sizeof(*tls));
	spin_lock_init(&tls->lock);

	tls->conf = conf;

	tls->hs = kmem_cache_alloc(ttls_hs_cache, GFP_ATOMIC);
	if (!tls->hs)
		return -ENOMEM;
	bzero_fast(tls->hs, sizeof(*tls->hs));

	tls->hs->sni_authmode = TTLS_VERIFY_UNSET;

	return 0;
}
EXPORT_SYMBOL(ttls_ctx_init);

/**
 * Set the certificate verification mode.
 * Default: NONE on server, REQUIRED on client.
 */
void
ttls_conf_authmode(TlsCfg *conf, int authmode)
{
	conf->authmode = authmode;
}

/**
 * Request resumption of session (client-side only).
 * Session data is copied from presented session structure.
 */
int
ttls_set_session(TlsCtx *tls, const TlsSess *sess)
{
	int r;

	BUG_ON(!tls || !sess);
	WARN_ON_ONCE(tls->conf->endpoint != TTLS_IS_CLIENT);

	if ((r = ttls_session_copy(&tls->sess, sess)))
		return r;

	tls->hs->resume = 1;

	return 0;
}

/**
 * Set own certificate chain and private key.
 *
 * @own_cert should contain in order from the bottom up your certificate chain.
 * The top certificate (self-signed) can be omitted.
 *
 * On server, this function can be called multiple times to provision more than
 * one cert/key pair (eg one ECDSA, one RSA with SHA-256, one RSA with SHA-1).
 * An adequate certificate will be selected according to the client's advertised
 * capabilities. In case multiple certificates are adequate, preference is given
 * to the one set by the first call to this function, then second, etc.
 *
 * On client, only the first call has any effect. That is, only one client
 * certificate can be provisioned. The server's preferences in its
 * CertficateRequest message will be ignored and our only cert will be sent
 * regardless of whether it matches those preferences - the server can then
 * decide what it wants to do with it.
 *
 * Called in process context on the startup.
 */
int
ttls_conf_own_cert(TlsPeerCfg *conf, TlsX509Crt *own_cert, TlsPkCtx *pk_key,
		   TlsX509Crt *ca_chain, ttls_x509_crl *ca_crl)
{
	TlsKeyCert *new;

	if (!(new = tfw_kmalloc(sizeof(TlsKeyCert), GFP_KERNEL)))
		return -ENOMEM;

	new->cert = own_cert;
	new->key = pk_key;
	new->ca_chain = ca_chain;
	new->ca_crl = ca_crl;
	new->next = NULL;

	/* Update conf->key_cert if the list was NULL, else add to the end. */
	if (!conf->key_cert) {
		conf->key_cert = new;
	} else {
		TlsKeyCert *cur = conf->key_cert;
		while (cur->next)
			cur = cur->next;
		cur->next = new;
	}

	return 0;
}
EXPORT_SYMBOL(ttls_conf_own_cert);

/**
 * Configure Session tickets. Only for server side. Called in process context
 * on the startup/reconfiguration.
 */
int
ttls_conf_tickets(TlsPeerCfg *conf, bool enable, unsigned long lifetime,
		  const char *secret_str, size_t len,
		  const char *vhost_name, size_t vn_len)
{
	if (!conf->endpoint)
		return -EINVAL;

	conf->sess_tickets = enable;

	if (!enable)
		return 0;

	return ttls_tickets_configure(conf, lifetime, secret_str, len,
				      vhost_name, vn_len);
}
EXPORT_SYMBOL(ttls_conf_tickets);

/**
 * Required if we need to verify client certificate.
 */
void
ttls_set_hs_authmode(TlsCtx *tls, int authmode)
{
	tls->hs->sni_authmode = authmode;
}

/**
 * Set or reset the hostname to check against the received server certificate.
 * It sets the ServerName TLS extension, too, if that extension is enabled.
 * (client-side only).
 *
 * TODO #830: we don't need the function before #830, so correspondingly we
 * don't use TlsCtx->hostname. Probably TlsVhost->name can be used. Anyway
 * there is no reason to call the dynamic memory allocator just for the
 * string name. Consider to use char hostname[TTLS_MAX_HOST_NAME_LEN] in
 * TlsCtx.
 */
int
ttls_set_hostname(TlsCtx *tls, const char *hostname)
{
	/* Initialize to suppress unnecessary compiler warning */
	size_t hostname_len = 0;

	BUG();

	/*
	 * Check if new hostname is valid before making
	 * any change to current one.
	 */
	if (hostname) {
		hostname_len = strlen(hostname);
		if (hostname_len > TTLS_MAX_HOST_NAME_LEN)
			return -EINVAL;
	}

	/*
	 * Now it's clear that we will overwrite the old hostname,
	 * so we can free it safely.
	 */
	if (tls->hostname) {
		bzero_fast(tls->hostname, strlen(tls->hostname));
		kfree(tls->hostname);
	}

	/* Passing NULL as hostname shall clear the old one. */
	if (!hostname) {
		tls->hostname = NULL;
	} else {
		tls->hostname = tfw_kmalloc(hostname_len + 1, GFP_ATOMIC);
		if (!tls->hostname)
			return -ENOMEM;

		memcpy(tls->hostname, hostname, hostname_len);
		tls->hostname[hostname_len] = '\0';
	}

	return 0;
}

/**
 * Get the name of the negotiated Application Layer Protocol.
 * This function should be called after the handshake is completed.
 */
const char *
ttls_get_alpn_protocol(const TlsCtx *tls)
{
	return tls->alpn_chosen->name;
}

/**
 * TODO #1031 replace conf->{min,max}_minor_ver by the flag whether to
 * use TLS 1.2 and/or 1.3.
 */
void
ttls_conf_version(TlsCfg *conf, int min_minor, int max_minor)
{
	conf->min_minor_ver = min_minor;
	conf->max_minor_ver = max_minor;
}

/**
 * Save session in order to resume it later (client-side only).
 * Session data is copied to presented session structure.
 *
 * WARNING Currently, peer certificate is lost in the operation.
 */
int
ttls_get_session(const TlsCtx *tls, TlsSess *dst)
{
	if (!tls || !dst || tls->conf->endpoint != TTLS_IS_CLIENT)
		return -EINVAL;

	return ttls_session_copy(dst, &tls->sess);
}

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
 * The step callers must return T_POSTPONE if more input data is required to
 * completely read current ingress record and 0 (T_OK) if current FSM state
 * finished successfully. All other return codes are treated as errors.
 *
 * @hh_len is pure optimization argument: it defines a backward offset in
 * @buf of size of handshake header if the header is in the @buf, so this way
 * we can compute the whole message checksum in one shot. Only handshake steps
 * reading ingress data use the argument.
 */
static int
ttls_handshake_step(TlsCtx *tls, unsigned char *buf, size_t len, size_t hh_len,
		    unsigned int *read)
{
	T_DBG3("handshake message %u on state %x\n",
	       tls->io_in.msgtype, tls->state);

/* TODO #769 Full TLS proxying */
#if 0
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
ttls_recv(void *tls_data, unsigned char *buf, unsigned int len, unsigned int *read)
{
	int r;
	unsigned int hh_len = 0, parsed = *read;
	TlsCtx *tls = (TlsCtx *)tls_data;
	TlsIOCtx *io = &tls->io_in;

	BUG_ON(!tls || !tls->conf);
	T_DBG3("%s: tls=%pK len=%u read=%u\n", __func__, tls, len, *read);

	if (!(io->st_flags & TTLS_F_ST_HDRIV)) {
		unsigned int delta;

		if ((r = ttls_parse_record_hdr(tls, buf, len, read))) {
			if (unlikely(r != T_POSTPONE))
				TTLS_WARN(tls, "Bad TLS record (err -0x%X)\n", r);
			return r;
		}
		delta = *read - parsed;
		len -= delta;
		buf += delta;
		parsed = *read;

		if (io->msgtype == TTLS_MSG_HANDSHAKE
		    && ttls_hs_checksumable(tls))
		{
			if (likely(delta >= TTLS_HS_HDR_LEN && len > 0)) {
				/*
				 * Compute handshake checksum for the message
				 * body and handshake header in one shot.
				 */
				hh_len = TTLS_HS_HDR_LEN;
			} else {
				r = ttls_update_checksum(tls, io->hs_hdr,
							 TTLS_HS_HDR_LEN);
				if (unlikely(r))
					return r;
			}
		}
	}
	WARN_ON_ONCE(!io->msglen);

	/*
	 * Current record is fully read and decrypted if necessary.
	 * Skip alerts and empty records and read a next one.
	 */
	switch (io->msgtype) {
	case TTLS_MSG_ALERT:
		if (unlikely(!ttls_xfrm_ready(tls))) {
			if (!(r = ttls_handle_alert(tls)))
				return T_OK;
			return r;
		}
		break;

	case TTLS_MSG_CHANGE_CIPHER_SPEC:
		/* Parsed as part of handshake FSM. */
	case TTLS_MSG_HANDSHAKE:
		if (len == 0)
			return T_POSTPONE;
		if (unlikely(tls->state == TTLS_HANDSHAKE_OVER)) {
			TTLS_WARN(tls, "refusing renegotiation, sending alert\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_NO_RENEGOTIATION,
					TTLS_F_ST_CLOSE);
			return T_BAD;
		}

		/*
		 * We add ingress messages to the handshake session checksum
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

		/* Cleanup security sensitive temporary data. */
		ttls_mpi_pool_cleanup_ctx(0, true);

		if (!r)
			return T_OK;
		if (r == T_POSTPONE) {
			/* Add the handshake message chunk to the checksum. */
			BUG_ON(!tls->hs && tls->state != TTLS_HANDSHAKE_OVER);
			if (ttls_hs_checksumable(tls)) {
				size_t n = *read - (int)parsed + hh_len;
				r = ttls_update_checksum(tls, buf - hh_len, n);
				if (unlikely(r))
					return r;
				r = T_POSTPONE;
			}
		}
		return r;

	case TTLS_MSG_APPLICATION_DATA:
		/*
		 * Don't allow application data before secured connection is
		 * established.
		 */
		if (unlikely(tls->state != TTLS_HANDSHAKE_OVER)) {
			TTLS_WARN(tls, "TLS context isn't ready after handshake\n");
			return -EPERM;
		}
		break;
	}

	if (len == 0)
		return T_POSTPONE;

	/* Encrypted data, crypto context is guaranteed to be ready here. */
	if (io->msglen > io->rlen + len) {
		*read += len;
		io->rlen += len;
		return T_POSTPONE;
	}

	if (ttls_tft_limit_rec_cb(tls->sess.tft))
		return T_BLOCK_WITH_RST;

	*read += io->msglen - io->rlen;
	if ((r = ttls_decrypt(tls, NULL))) {
		TTLS_WARN(tls, "TLS cannot decrypt msg on state %s, ret=%d%s\n",
			  tls_state_to_str(tls->state), r,
			  r == -EBADMSG ? "(bad ciphertext)" : "");
		return r;
	}

	if (io->msgtype == TTLS_MSG_ALERT) {
		if (!(r = ttls_handle_alert(tls)))
			return T_OK;
		return r;
	}

	return T_OK;
}
EXPORT_SYMBOL(ttls_recv);

/**
 * Notify the peer that the connection is being closed.
 */
int
ttls_close_notify(TlsCtx *tls, int close_type)
{
	BUG_ON(!tls || !tls->conf);
	T_DBG("write close notify\n");

	if (tls->state != TTLS_HANDSHAKE_OVER)
		return -EPROTO;

	return ttls_send_alert(tls, TTLS_ALERT_LEVEL_WARNING,
			       TTLS_ALERT_MSG_CLOSE_NOTIFY,
			       close_type);
}
EXPORT_SYMBOL(ttls_close_notify);

void
ttls_key_cert_free(TlsKeyCert *key_cert)
{
	TlsKeyCert *cur = key_cert, *next;

	while (cur) {
		next = cur->next;
		kfree(cur);
		cur = next;
	}
}
EXPORT_SYMBOL(ttls_key_cert_free);

void
ttls_ctx_clear(TlsCtx *tls)
{
	ttls_handshake_free(tls->hs);

	ttls_cipher_free(&tls->xfrm.cipher_ctx_enc);
	ttls_cipher_free(&tls->xfrm.cipher_ctx_dec);

	/* #830 check that all the data is freed correctly. */
	ttls_x509_crt_destroy(&tls->sess.peer_cert);

	bzero_fast(tls, sizeof(TlsCtx));
}
EXPORT_SYMBOL(ttls_ctx_clear);

void
ttls_config_init(TlsCfg *conf)
{
	ttls_bzero_safe(conf, sizeof(TlsCfg));
}
EXPORT_SYMBOL(ttls_config_init);

static int ttls_default_ciphersuites[] = {
	/* All AES-128 ephemeral suites */
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TTLS_TLS_DHE_RSA_WITH_AES_128_CCM,

	/* All AES-256 ephemeral suites */
	TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TTLS_TLS_DHE_RSA_WITH_AES_256_CCM,

	0
};

int ttls_preset_hashes[] = {
	TTLS_MD_SHA256,
	TTLS_MD_SHA384,
	TTLS_MD_NONE
};

/**
 * Load reasonable default TLS configuration values.
 * Use NSA Suite B as a preset-specific defaults.
 */
int
ttls_config_defaults(TlsCfg *conf, int endpoint)
{
	conf->endpoint = endpoint;

	/* Things that are common to all presets. */
	if (endpoint == TTLS_IS_CLIENT)
		conf->authmode = TTLS_VERIFY_REQUIRED;

	conf->cert_req_ca_list = 0;
	conf->min_minor_ver = TTLS_MINOR_VERSION_3; /* TLS 1.2 */
	conf->max_minor_ver = TTLS_MAX_MINOR_VERSION;

	return 0;
}
EXPORT_SYMBOL(ttls_config_defaults);

int
ttls_config_peer_defaults(TlsPeerCfg *conf, int endpoint)
{
	conf->endpoint = endpoint;
	conf->cert_req_ca_list = 0;
	conf->sess_tickets = 0;

	conf->min_minor_ver = TTLS_MINOR_VERSION_3; /* TLS 1.2 */
	conf->max_minor_ver = TTLS_MAX_MINOR_VERSION;

	conf->ciphersuite_list[TTLS_MINOR_VERSION_3]
		= ttls_default_ciphersuites;

	return 0;
}
EXPORT_SYMBOL(ttls_config_peer_defaults);

void
ttls_config_free(TlsCfg *conf)
{
	/* Called in process context for relatively small memory area. */
	memset(conf, 0, sizeof(TlsCfg));
}
EXPORT_SYMBOL(ttls_config_free);

void
ttls_config_peer_free(TlsPeerCfg *conf)
{
	if (conf->sess_tickets)
		ttls_tickets_clean(conf);
	/* Called in process context for relatively small memory area. */
	memset(conf, 0, sizeof(TlsPeerCfg));
}
EXPORT_SYMBOL(ttls_config_peer_free);

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

/*
 * Find an entry in a signature-hash set matching a given hash algorithm.
 * Most secure are preferred.
 */
ttls_md_type_t
ttls_sig_hash_set_find(TlsSigHashSet *set, ttls_pk_type_t sig_alg)
{
	/* fls(0x1) == fls(0x0) = TTLS_MD_NONE. */
	switch (sig_alg) {
	case TTLS_PK_RSA:
		return fls(set->rsa);
	case TTLS_PK_ECDSA:
		return fls(set->ecdsa);
	default:
		return TTLS_MD_NONE;
	}
}

/**
 * Add a signature-hash-pair to a signature-hash set/
 */
void
ttls_sig_hash_set_add(TlsSigHashSet *set, ttls_pk_type_t sig_alg,
		      ttls_md_type_t md_alg)
{
	switch (sig_alg) {
	case TTLS_PK_RSA:
		set->rsa |= 1 << md_alg;
		break;
	case TTLS_PK_ECDSA:
		set->ecdsa |= 1 << md_alg;
		break;
	default:
		return;
	}
}

static bool
ttls_sig_hash_set_has(TlsSigHashSet *set, ttls_pk_type_t sig_alg,
		      ttls_md_type_t md_alg)
{
	switch (sig_alg) {
	case TTLS_PK_RSA:
		return set->rsa & (1 << md_alg);
	case TTLS_PK_ECDSA:
		return set->ecdsa & (1 << md_alg);
	default:
		return false;
	}
}

static void
ttls_sig_hash_set_const(TlsSigHashSet *set, ttls_pk_type_t sig_alg,
			ttls_md_type_t md_alg)
{
	switch (sig_alg) {
	case TTLS_PK_RSA:
		set->rsa = 1 << md_alg;
		break;
	case TTLS_PK_ECDSA:
		set->ecdsa = 1 << md_alg;
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
ttls_check_curve(const TlsCtx *tls, ttls_ecp_group_id grp_id)
{
	const ttls_ecp_group_id *gid;

	for (gid = ttls_preset_curves; *gid != TTLS_ECP_DP_NONE; gid++)
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

	for (cur = ttls_preset_hashes; *cur != TTLS_MD_NONE; cur++)
		if (*cur == (int)md)
			return 0;

	return -1;
}

int
ttls_match_sig_hashes(const TlsCtx *tls)
{
	TlsSigHashSet *set = &tls->hs->hash_algs;
	bool dflt_available = false, has_rsa = false, has_ecdsa = false;
	const int *cur;

	if (WARN_ON_ONCE(!tls->peer_conf))
		goto err;

	/*
	 * Normally peers advertise supported functions, hashes supported by
	 * us is stored in order of preference in @tls->peer_conf.
	 * Grab the first matched and avoid spinning in the list.
	 */
	for (cur = ttls_preset_hashes; *cur != TTLS_MD_NONE; cur++) {
		if (!has_rsa
		    && ttls_sig_hash_set_has(set, TTLS_PK_RSA, *cur))
		{
			has_rsa = true;
			ttls_sig_hash_set_const(set, TTLS_PK_RSA, *cur);
			T_DBG("ClientHello: signature_algorithm ext:"
			      " choose hash %d for sig RSA",
			      *cur);
		}
		if (!has_ecdsa
		    && ttls_sig_hash_set_has(set, TTLS_PK_ECDSA, *cur))
		{
			has_ecdsa = true;
			ttls_sig_hash_set_const(set, TTLS_PK_ECDSA, *cur);
			T_DBG("ClientHello: signature_algorithm ext:"
			      " choose hash %d for sig ECDSA",
			      *cur);
		}

		if (likely(has_rsa && has_ecdsa))
			return 0;

		/*
		 * SHA256 is fallback default function, used if none was
		 * advertised by remote peer.
		 */
		if (*cur == TTLS_MD_SHA256)
			dflt_available = true;
	}

	/*
	 * No match between our list and remote peer list. If remote peer didn't
	 * advertised anything, peek default values.
	 */
	if (!dflt_available)
		goto err;
	if (!has_rsa) {
		if (ttls_sig_hash_set_find(set, TTLS_PK_RSA) != TTLS_MD_NONE)
			goto err;
		T_DBG("ClientHello: signature_algorithm ext:"
		      "No hash for RSA signature algorithm advertised by "
		      "client, fallback to SHA256\n");
		ttls_sig_hash_set_const(set, TTLS_PK_RSA, TTLS_MD_SHA256);
	}
	if (!has_ecdsa) {
		if (ttls_sig_hash_set_find(set, TTLS_PK_ECDSA) != TTLS_MD_NONE)
			goto err;
		T_DBG("ClientHello: signature_algorithm ext:"
		      "No hash for ECDSA signature algorithm advertised by "
		      "client, by peer, fallback to SHA256\n");
		ttls_sig_hash_set_const(set, TTLS_PK_ECDSA, TTLS_MD_SHA256);
	}

	return 0;
err:
	TTLS_WARN(tls, "ClientHello: signature_algorithm ext: client and"
		  " server hash function capabilities has no match");
	return -1;
}

/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK or error code otherwise
 */
int
ttls_check_cert_usage(const TlsX509Crt *cert, const TlsCiphersuite *ciphersuite,
		      int cert_endpoint)
{
	int r = 0, usage = 0;
	const char *ext_oid;
	size_t ext_len;

	if (cert_endpoint == TTLS_IS_SERVER) {
		/* Server part of the key exchange */
		switch (ciphersuite->key_exchange) {
		case TTLS_KEY_EXCHANGE_DHE_RSA:
		case TTLS_KEY_EXCHANGE_ECDHE_RSA:
		case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
			usage = TTLS_X509_KU_DIGITAL_SIGNATURE;
			break;
		/* Don't use default: we want warnings when adding new values */
		case TTLS_KEY_EXCHANGE_NONE:
			usage = 0;
		}
		ext_oid = TTLS_OID_SERVER_AUTH;
		ext_len = TTLS_OID_SIZE(TTLS_OID_SERVER_AUTH);
	} else {
		/* Client auth: we only implement RSA and ECDSA sign for now. */
		usage = TTLS_X509_KU_DIGITAL_SIGNATURE;
		ext_oid = TTLS_OID_CLIENT_AUTH;
		ext_len = TTLS_OID_SIZE(TTLS_OID_CLIENT_AUTH);
	}

	if (ttls_x509_crt_check_key_usage(cert, usage))
		r |= TTLS_X509_BADCERT_KEY_USAGE;
	if (ttls_x509_crt_check_extended_key_usage(cert, ext_oid, ext_len))
		r |= TTLS_X509_BADCERT_EXT_KEY_USAGE;

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
	r = ttls_md_finish(&ctx, output);

exit:
	ttls_md_free(&ctx);
	return r;
}

bool
ttls_alpn_ext_eq(const ttls_alpn_proto *proto, const unsigned char *buf,
		 size_t len)
{
	T_DBG("match client ALPN %.*s (len=%lu) against our %.*s\n",
	      (int)len, buf, len, (int)proto->len, proto->name);

	if (proto->len != len)
		return false;
	if (len == 8) /* http/1.1 */
		return *(unsigned long *)proto->name == *(unsigned long *)buf;
	if (len == 2) /* h2 */
		return *(unsigned short *)proto->name == *(unsigned short *)buf;

	return !memcmp_fast(proto->name, buf, len);
}


static void
ttls_exit(void)
{
	int cpu;

	kmem_cache_destroy(ttls_hs_cache);

	for_each_online_cpu(cpu) {
		struct aead_request **req = per_cpu_ptr(&g_req, cpu);
		kfree(*req);
	}

	ttls_mpool_exit();
	ttls_tickets_exit();
	ttls_x509_exit();
}

static int __init
ttls_init(void)
{
	int cpu, r;

	/* Bad configuration - protected record payload too large. */
	BUILD_BUG_ON(TTLS_PAYLOAD_LEN > 16384 + 2048);

	if ((r = ttls_mpool_init()))
		return r;

	if ((r = ttls_crypto_modinit()))
		goto err_free;
	if ((r = ttls_x509_init()))
		goto err_free;
	if ((r = ttls_tickets_init()))
		goto err_free;

	for_each_online_cpu(cpu) {
		struct aead_request **req = per_cpu_ptr(&g_req, cpu);
		*req = tfw_kmalloc(ttls_aead_reqsize(), GFP_KERNEL);
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
