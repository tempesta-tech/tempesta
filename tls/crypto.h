/*
 *		Tempesta TLS
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
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
#ifndef __TTLS_CRYPTO_H__
#define __TTLS_CRYPTO_H__

#include <crypto/hash.h>
#include <crypto/sha.h>

/* An enumeration of supported ciphers. */
typedef enum {
	TTLS_CIPHER_ID_NONE = 0,
	TTLS_CIPHER_ID_AES,
} ttls_cipher_id_t;

/* Supported (cipher, mode) pairs. */
typedef enum {
	TTLS_CIPHER_NONE = 0,
	TTLS_CIPHER_AES_128_GCM,
	TTLS_CIPHER_AES_192_GCM,
	TTLS_CIPHER_AES_256_GCM,
	TTLS_CIPHER_AES_128_CCM,
	TTLS_CIPHER_AES_192_CCM,
	TTLS_CIPHER_AES_256_CCM,
} ttls_cipher_type_t;

/* Supported cipher modes. */
typedef enum {
	TTLS_MODE_NONE = 0,
	TTLS_MODE_GCM,
	TTLS_MODE_STREAM, /* TLS 1.3: ChaCha20-Poly1305 */
	TTLS_MODE_CCM,
} ttls_cipher_mode_t;

/*
 * Supported message digests.
 *
 * TODO #1031: At the moment only SHA256 and SHA384 are supported in the
 * ciphersuites, but SHA512 is ready.
 */
typedef enum {
	TTLS_MD_NONE = 0,
	TTLS_MD_SHA256,
	TTLS_MD_SHA384,
	TTLS_MD_SHA512,
	__TTLS_MD_N = TTLS_MD_SHA512
} ttls_md_type_t;

/** Maximum length of any IV, in Bytes. */
#define TTLS_MAX_IV_LENGTH		16
#define TTLS_MD_MAX_SIZE		64  /* longest known is SHA512 */
#define __MD_MAX_CTX_SZ			(sizeof(struct sha512_state) + \
					 sizeof(struct shash_desc))

/**
 * Cipher information. Allows calling cipher functions in a generic way.
 *
 * @type	- Full cipher identifier, e.g. TTLS_CIPHER_AES_256_CBC;
 * @mode	- The cipher mode. For example, TTLS_MODE_CBC;
 * @key_len	- The cipher key length, in bytes. This is the default length
 *		  for variable sized ciphers. Includes parity bits for ciphers
 *		  like DES;
 * @name	- Name of the cipher;
 * @drv_name	- Name of appropriate Linux crypto driver;
 * @iv_size	- IV or nonce size, in Bytes. For ciphers that accept variable
 *		  IV sizes, this is the recommended size;
 * @alg		- Crypto algorithm descriptor;
 */
typedef struct {
	ttls_cipher_type_t		type;
	ttls_cipher_mode_t		mode;
	unsigned int			key_len;
	const char			*name;
	const char			*drv_name;
	unsigned int			iv_size;
	struct crypto_alg		*alg;
} TlsCipherInfo;

/**
 * Generic cipher context.
 *
 * @cipher_info		- Information about the associated cipher;
 * @cipher_ctx		- The cipher-specific context;
 * @iv_size		- IV size in Bytes, for ciphers with variable-length
 *			  IVs;
 * @iv			- Current IV;
 */
typedef struct {
	const TlsCipherInfo		*cipher_info;
	struct crypto_aead		*cipher_ctx;
	unsigned char			iv_size;
	unsigned char			iv[TTLS_MAX_IV_LENGTH];
} TlsCipherCtx;

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 *
 * @type		- Digest identifier;
 * @name		- Name of the message digest;
 * @alg_name		- hash Linux crypto driver;
 * @hmac_name		- HMAC Linux crypto driver;
 * @alg_hash		- Hash algorithm descriptor;
 * @alg_hmac		- HMAC algorithm descriptor;
 */
typedef struct TlsMdInfo {
	ttls_md_type_t		type;
	const char		*name;
	const char		*alg_name;
	const char		*hmac_name;
	struct crypto_alg	*alg_hash;
	struct crypto_alg	*alg_hmac;
} TlsMdInfo;

/**
 * The generic message-digest context.
 *
 * @md_info		- Information about the associated message digest;
 * @md_ctx		- The digest-specific context;
 */
typedef struct {
	const TlsMdInfo		*md_info;
	struct shash_desc	md_ctx;
	char			__ctx[__MD_MAX_CTX_SZ];
} TlsMdCtx;

typedef struct {
	struct shash_desc	desc;
	struct sha256_state	state;
} CRYPTO_MINALIGN_ATTR ttls_sha256_context;

typedef struct {
	struct shash_desc	desc;
	struct sha512_state	state;
} CRYPTO_MINALIGN_ATTR ttls_sha512_context;

const TlsCipherInfo *
ttls_cipher_info_from_type(const ttls_cipher_type_t cipher_type);

void ttls_cipher_free(TlsCipherCtx *ctx);
int ttls_cipher_setup(TlsCipherCtx *ctx, const TlsCipherInfo *ci,
		      unsigned int tag_size);

const TlsMdInfo *ttls_md_info_from_type(ttls_md_type_t md_type);
void ttls_md_init(TlsMdCtx *ctx);
void ttls_md_free(TlsMdCtx *ctx);

/*
 * This function selects the message digest algorithm to use, and allocates
 * internal structures. It should be called after ttls_md_init() or
 * ttls_md_free(). Makes it necessary to call ttls_md_free() later.
 */
int ttls_md_setup(TlsMdCtx *ctx, const TlsMdInfo *md_info, int hmac);

int ttls_md_starts(TlsMdCtx *ctx);
int ttls_md_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen);
int ttls_md_finish(TlsMdCtx *ctx, unsigned char *output);

/*
 * This function calculates the message-digest of a buffer, with respect to a
 * configurable message-digest algorithm in a single call.
 */
int ttls_md(const TlsMdInfo *md_info, const unsigned char *input,
	    size_t ilen, unsigned char *output);

int ttls_sha256_init_start(ttls_sha256_context *ctx);
int ttls_sha384_init_start(ttls_sha512_context *ctx);

int ttls_md_hmac_starts(TlsMdCtx *ctx, const unsigned char *key, size_t keylen);
int ttls_md_hmac_reset(TlsMdCtx *ctx);

unsigned int ttls_aead_reqsize(void);
int ttls_crypto_modinit(void);

static inline int
ttls_md_hmac_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen)
{
	return ttls_md_update(ctx, input, ilen);
}

static inline int
ttls_md_hmac_finish(TlsMdCtx *ctx, unsigned char *output)
{
	return ttls_md_finish(ctx, output);
}

static inline unsigned char
ttls_md_get_size(const TlsMdInfo *md_info)
{
	struct crypto_alg *alg;

	BUG_ON(!md_info);

	alg = md_info->alg_hash ? : md_info->alg_hmac;
	BUG_ON(!alg);

	return __crypto_shash_alg(alg)->digestsize;
}

static inline const char *
ttls_md_get_name(const TlsMdInfo *md_info)
{
	BUG_ON(!md_info);

	return md_info->name;
}

#endif /* __TTLS_CRYPTO_H__ */
