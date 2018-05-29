/*
 *  Privacy Enhanced Mail (PEM) decoding
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include "config.h"

#if defined(TTLS_PEM_PARSE_C) || defined(TTLS_PEM_WRITE_C)

#include "pem.h"
#include "base64.h"
#include "des.h"
#include "aes.h"
#include "md5.h"
#include "cipher.h"

#if defined(TTLS_PEM_PARSE_C)
/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

void ttls_pem_init(ttls_pem_context *ctx)
{
	memset(ctx, 0, sizeof(ttls_pem_context));
}

#if defined(TTLS_MD5_C) && defined(TTLS_CIPHER_MODE_CBC) &&		 \
	(defined(TTLS_DES_C) || defined(TTLS_AES_C))
/*
 * Read a 16-byte hex string and convert it to binary
 */
static int pem_get_iv(const unsigned char *s, unsigned char *iv,
					   size_t iv_len)
{
	size_t i, j, k;

	memset(iv, 0, iv_len);

	for (i = 0; i < iv_len * 2; i++, s++)
	{
		if (*s >= '0' && *s <= '9') j = *s - '0'; else
		if (*s >= 'A' && *s <= 'F') j = *s - '7'; else
		if (*s >= 'a' && *s <= 'f') j = *s - 'W'; else
			return(TTLS_ERR_PEM_INVALID_ENC_IV);

		k = ((i & 1) != 0) ? j : j << 4;

		iv[i >> 1] = (unsigned char)(iv[i >> 1] | k);
	}

	return 0;
}

static int pem_pbkdf1(unsigned char *key, size_t keylen,
					   unsigned char *iv,
					   const unsigned char *pwd, size_t pwdlen)
{
	ttls_md5_context md5_ctx;
	unsigned char md5sum[16];
	size_t use_len;
	int ret;

	ttls_md5_init(&md5_ctx);

	/*
	 * key[ 0..15] = MD5(pwd || IV)
	 */
	if ((ret = ttls_md5_starts_ret(&md5_ctx)) != 0)
		goto exit;
	if ((ret = ttls_md5_update_ret(&md5_ctx, pwd, pwdlen)) != 0)
		goto exit;
	if ((ret = ttls_md5_update_ret(&md5_ctx, iv,  8)) != 0)
		goto exit;
	if ((ret = ttls_md5_finish_ret(&md5_ctx, md5sum)) != 0)
		goto exit;

	if (keylen <= 16)
	{
		memcpy(key, md5sum, keylen);
		goto exit;
	}

	memcpy(key, md5sum, 16);

	/*
	 * key[16..23] = MD5(key[ 0..15] || pwd || IV])
	 */
	if ((ret = ttls_md5_starts_ret(&md5_ctx)) != 0)
		goto exit;
	if ((ret = ttls_md5_update_ret(&md5_ctx, md5sum, 16)) != 0)
		goto exit;
	if ((ret = ttls_md5_update_ret(&md5_ctx, pwd, pwdlen)) != 0)
		goto exit;
	if ((ret = ttls_md5_update_ret(&md5_ctx, iv, 8)) != 0)
		goto exit;
	if ((ret = ttls_md5_finish_ret(&md5_ctx, md5sum)) != 0)
		goto exit;

	use_len = 16;
	if (keylen < 32)
		use_len = keylen - 16;

	memcpy(key + 16, md5sum, use_len);

exit:
	ttls_md5_free(&md5_ctx);
	ttls_zeroize(md5sum, 16);

	return ret;
}

#if defined(TTLS_DES_C)
/*
 * Decrypt with DES-CBC, using PBKDF1 for key derivation
 */
static int pem_des_decrypt(unsigned char des_iv[8],
							unsigned char *buf, size_t buflen,
							const unsigned char *pwd, size_t pwdlen)
{
	ttls_des_context des_ctx;
	unsigned char des_key[8];
	int ret;

	ttls_des_init(&des_ctx);

	if ((ret = pem_pbkdf1(des_key, 8, des_iv, pwd, pwdlen)) != 0)
		goto exit;

	if ((ret = ttls_des_setkey_dec(&des_ctx, des_key)) != 0)
		goto exit;
	ret = ttls_des_crypt_cbc(&des_ctx, TTLS_DES_DECRYPT, buflen,
					 des_iv, buf, buf);

exit:
	ttls_des_free(&des_ctx);
	ttls_zeroize(des_key, 8);

	return ret;
}

/*
 * Decrypt with 3DES-CBC, using PBKDF1 for key derivation
 */
static int pem_des3_decrypt(unsigned char des3_iv[8],
							 unsigned char *buf, size_t buflen,
							 const unsigned char *pwd, size_t pwdlen)
{
	ttls_des3_context des3_ctx;
	unsigned char des3_key[24];
	int ret;

	ttls_des3_init(&des3_ctx);

	if ((ret = pem_pbkdf1(des3_key, 24, des3_iv, pwd, pwdlen)) != 0)
		goto exit;

	if ((ret = ttls_des3_set3key_dec(&des3_ctx, des3_key)) != 0)
		goto exit;
	ret = ttls_des3_crypt_cbc(&des3_ctx, TTLS_DES_DECRYPT, buflen,
					 des3_iv, buf, buf);

exit:
	ttls_des3_free(&des3_ctx);
	ttls_zeroize(des3_key, 24);

	return ret;
}
#endif /* TTLS_DES_C */

#if defined(TTLS_AES_C)
/*
 * Decrypt with AES-XXX-CBC, using PBKDF1 for key derivation
 */
static int pem_aes_decrypt(unsigned char aes_iv[16], unsigned int keylen,
							unsigned char *buf, size_t buflen,
							const unsigned char *pwd, size_t pwdlen)
{
	ttls_aes_context aes_ctx;
	unsigned char aes_key[32];
	int ret;

	ttls_aes_init(&aes_ctx);

	if ((ret = pem_pbkdf1(aes_key, keylen, aes_iv, pwd, pwdlen)) != 0)
		goto exit;

	if ((ret = ttls_aes_setkey_dec(&aes_ctx, aes_key, keylen * 8)) != 0)
		goto exit;
	ret = ttls_aes_crypt_cbc(&aes_ctx, TTLS_AES_DECRYPT, buflen,
					 aes_iv, buf, buf);

exit:
	ttls_aes_free(&aes_ctx);
	ttls_zeroize(aes_key, keylen);

	return ret;
}
#endif /* TTLS_AES_C */

#endif /* TTLS_MD5_C && TTLS_CIPHER_MODE_CBC &&
		  (TTLS_AES_C || TTLS_DES_C) */

int ttls_pem_read_buffer(ttls_pem_context *ctx, const char *header, const char *footer,
					 const unsigned char *data, const unsigned char *pwd,
					 size_t pwdlen, size_t *use_len)
{
	int ret, enc;
	size_t len;
	unsigned char *buf;
	const unsigned char *s1, *s2, *end;
#if defined(TTLS_MD5_C) && defined(TTLS_CIPHER_MODE_CBC) &&		 \
	(defined(TTLS_DES_C) || defined(TTLS_AES_C))
	unsigned char pem_iv[16];
	ttls_cipher_type_t enc_alg = TTLS_CIPHER_NONE;
#else
	((void) pwd);
	((void) pwdlen);
#endif /* TTLS_MD5_C && TTLS_CIPHER_MODE_CBC &&
		  (TTLS_AES_C || TTLS_DES_C) */

	if (ctx == NULL)
		return(TTLS_ERR_PEM_BAD_INPUT_DATA);

	s1 = (unsigned char *) strstr((const char *) data, header);

	if (s1 == NULL)
		return(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT);

	s2 = (unsigned char *) strstr((const char *) data, footer);

	if (s2 == NULL || s2 <= s1)
		return(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT);

	s1 += strlen(header);
	if (*s1 == ' ' ) s1++;
	if (*s1 == '\r') s1++;
	if (*s1 == '\n') s1++;
	else return(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT);

	end = s2;
	end += strlen(footer);
	if (*end == ' ' ) end++;
	if (*end == '\r') end++;
	if (*end == '\n') end++;
	*use_len = end - data;

	enc = 0;

	if (s2 - s1 >= 22 && memcmp(s1, "Proc-Type: 4,ENCRYPTED", 22) == 0)
	{
#if defined(TTLS_MD5_C) && defined(TTLS_CIPHER_MODE_CBC) &&		 \
	(defined(TTLS_DES_C) || defined(TTLS_AES_C))
		enc++;

		s1 += 22;
		if (*s1 == '\r') s1++;
		if (*s1 == '\n') s1++;
		else return(TTLS_ERR_PEM_INVALID_DATA);


#if defined(TTLS_DES_C)
		if (s2 - s1 >= 23 && memcmp(s1, "DEK-Info: DES-EDE3-CBC,", 23) == 0)
		{
			enc_alg = TTLS_CIPHER_DES_EDE3_CBC;

			s1 += 23;
			if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0)
				return(TTLS_ERR_PEM_INVALID_ENC_IV);

			s1 += 16;
		}
		else if (s2 - s1 >= 18 && memcmp(s1, "DEK-Info: DES-CBC,", 18) == 0)
		{
			enc_alg = TTLS_CIPHER_DES_CBC;

			s1 += 18;
			if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0)
				return(TTLS_ERR_PEM_INVALID_ENC_IV);

			s1 += 16;
		}
#endif /* TTLS_DES_C */

#if defined(TTLS_AES_C)
		if (s2 - s1 >= 14 && memcmp(s1, "DEK-Info: AES-", 14) == 0)
		{
			if (s2 - s1 < 22)
				return(TTLS_ERR_PEM_UNKNOWN_ENC_ALG);
			else if (memcmp(s1, "DEK-Info: AES-128-CBC,", 22) == 0)
				enc_alg = TTLS_CIPHER_AES_128_CBC;
			else if (memcmp(s1, "DEK-Info: AES-192-CBC,", 22) == 0)
				enc_alg = TTLS_CIPHER_AES_192_CBC;
			else if (memcmp(s1, "DEK-Info: AES-256-CBC,", 22) == 0)
				enc_alg = TTLS_CIPHER_AES_256_CBC;
			else
				return(TTLS_ERR_PEM_UNKNOWN_ENC_ALG);

			s1 += 22;
			if (s2 - s1 < 32 || pem_get_iv(s1, pem_iv, 16) != 0)
				return(TTLS_ERR_PEM_INVALID_ENC_IV);

			s1 += 32;
		}
#endif /* TTLS_AES_C */

		if (enc_alg == TTLS_CIPHER_NONE)
			return(TTLS_ERR_PEM_UNKNOWN_ENC_ALG);

		if (*s1 == '\r') s1++;
		if (*s1 == '\n') s1++;
		else return(TTLS_ERR_PEM_INVALID_DATA);
#else
		return(TTLS_ERR_PEM_FEATURE_UNAVAILABLE);
#endif /* TTLS_MD5_C && TTLS_CIPHER_MODE_CBC &&
		  (TTLS_AES_C || TTLS_DES_C) */
	}

	if (s1 >= s2)
		return(TTLS_ERR_PEM_INVALID_DATA);

	ret = ttls_base64_decode(NULL, 0, &len, s1, s2 - s1);

	if (ret == TTLS_ERR_BASE64_INVALID_CHARACTER)
		return(TTLS_ERR_PEM_INVALID_DATA + ret);

	if ((buf = ttls_calloc(1, len)) == NULL)
		return(TTLS_ERR_PEM_ALLOC_FAILED);

	if ((ret = ttls_base64_decode(buf, len, &len, s1, s2 - s1)) != 0)
	{
		ttls_zeroize(buf, len);
		ttls_free(buf);
		return(TTLS_ERR_PEM_INVALID_DATA + ret);
	}

	if (enc != 0)
	{
#if defined(TTLS_MD5_C) && defined(TTLS_CIPHER_MODE_CBC) &&		 \
	(defined(TTLS_DES_C) || defined(TTLS_AES_C))
		if (pwd == NULL)
		{
			ttls_zeroize(buf, len);
			ttls_free(buf);
			return(TTLS_ERR_PEM_PASSWORD_REQUIRED);
		}

		ret = 0;

#if defined(TTLS_DES_C)
		if (enc_alg == TTLS_CIPHER_DES_EDE3_CBC)
			ret = pem_des3_decrypt(pem_iv, buf, len, pwd, pwdlen);
		else if (enc_alg == TTLS_CIPHER_DES_CBC)
			ret = pem_des_decrypt(pem_iv, buf, len, pwd, pwdlen);
#endif /* TTLS_DES_C */

#if defined(TTLS_AES_C)
		if (enc_alg == TTLS_CIPHER_AES_128_CBC)
			ret = pem_aes_decrypt(pem_iv, 16, buf, len, pwd, pwdlen);
		else if (enc_alg == TTLS_CIPHER_AES_192_CBC)
			ret = pem_aes_decrypt(pem_iv, 24, buf, len, pwd, pwdlen);
		else if (enc_alg == TTLS_CIPHER_AES_256_CBC)
			ret = pem_aes_decrypt(pem_iv, 32, buf, len, pwd, pwdlen);
#endif /* TTLS_AES_C */

		if (ret != 0)
		{
			ttls_free(buf);
			return ret;
		}

		/*
		 * The result will be ASN.1 starting with a SEQUENCE tag, with 1 to 3
		 * length bytes (allow 4 to be sure) in all known use cases.
		 *
		 * Use that as heurisitic to try detecting password mismatchs.
		 */
		if (len <= 2 || buf[0] != 0x30 || buf[1] > 0x83)
		{
			ttls_zeroize(buf, len);
			ttls_free(buf);
			return(TTLS_ERR_PEM_PASSWORD_MISMATCH);
		}
#else
		ttls_zeroize(buf, len);
		ttls_free(buf);
		return(TTLS_ERR_PEM_FEATURE_UNAVAILABLE);
#endif /* TTLS_MD5_C && TTLS_CIPHER_MODE_CBC &&
		  (TTLS_AES_C || TTLS_DES_C) */
	}

	ctx->buf = buf;
	ctx->buflen = len;

	return 0;
}

void ttls_pem_free(ttls_pem_context *ctx)
{
	if (ctx->buf != NULL)
		ttls_zeroize(ctx->buf, ctx->buflen);
	ttls_free(ctx->buf);
	ttls_free(ctx->info);

	ttls_zeroize(ctx, sizeof(ttls_pem_context));
}
#endif /* TTLS_PEM_PARSE_C */

#if defined(TTLS_PEM_WRITE_C)
int ttls_pem_write_buffer(const char *header, const char *footer,
					  const unsigned char *der_data, size_t der_len,
					  unsigned char *buf, size_t buf_len, size_t *olen)
{
	int ret;
	unsigned char *encode_buf = NULL, *c, *p = buf;
	size_t len = 0, use_len, add_len = 0;

	ttls_base64_encode(NULL, 0, &use_len, der_data, der_len);
	add_len = strlen(header) + strlen(footer) + (use_len / 64) + 1;

	if (use_len + add_len > buf_len)
	{
		*olen = use_len + add_len;
		return(TTLS_ERR_BASE64_BUFFER_TOO_SMALL);
	}

	if (use_len != 0 &&
		((encode_buf = ttls_calloc(1, use_len)) == NULL))
		return(TTLS_ERR_PEM_ALLOC_FAILED);

	if ((ret = ttls_base64_encode(encode_buf, use_len, &use_len, der_data,
							   der_len)) != 0)
	{
		ttls_free(encode_buf);
		return ret;
	}

	memcpy(p, header, strlen(header));
	p += strlen(header);
	c = encode_buf;

	while (use_len)
	{
		len = (use_len > 64) ? 64 : use_len;
		memcpy(p, c, len);
		use_len -= len;
		p += len;
		c += len;
		*p++ = '\n';
	}

	memcpy(p, footer, strlen(footer));
	p += strlen(footer);

	*p++ = '\0';
	*olen = p - buf;

	ttls_free(encode_buf);
	return 0;
}
#endif /* TTLS_PEM_WRITE_C */
#endif /* TTLS_PEM_PARSE_C || TTLS_PEM_WRITE_C */
