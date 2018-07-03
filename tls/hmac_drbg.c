/*
 *  HMAC_DRBG implementation (NIST SP 800-90)
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

/*
 *  The NIST SP 800-90A DRBGs are described in the following publication.
 *  http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
 *  References below are based on rev. 1 (January 2012).
 */
#include "config.h"

#if defined(TTLS_HMAC_DRBG_C)

#include "hmac_drbg.h"

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

/*
 * HMAC_DRBG context initialization
 */
void ttls_hmac_drbg_init(ttls_hmac_drbg_context *ctx)
{
	memset(ctx, 0, sizeof(ttls_hmac_drbg_context));
	spin_lock_init(&ctx->mutex);
}

/*
 * HMAC_DRBG update, using optional additional data (10.1.2.2)
 */
void ttls_hmac_drbg_update(ttls_hmac_drbg_context *ctx,
		   const unsigned char *additional, size_t add_len)
{
	size_t md_len = ttls_md_get_size(ctx->md_ctx.md_info);
	unsigned char rounds = (additional != NULL && add_len != 0) ? 2 : 1;
	unsigned char sep[1];
	unsigned char K[TTLS_MD_MAX_SIZE];

	for (sep[0] = 0; sep[0] < rounds; sep[0]++)
	{
		/* Step 1 or 4 */
		ttls_md_hmac_reset(&ctx->md_ctx);
		ttls_md_hmac_update(&ctx->md_ctx, ctx->V, md_len);
		ttls_md_hmac_update(&ctx->md_ctx, sep, 1);
		if (rounds == 2)
			ttls_md_hmac_update(&ctx->md_ctx, additional, add_len);
		ttls_md_hmac_finish(&ctx->md_ctx, K);

		/* Step 2 or 5 */
		ttls_md_hmac_starts(&ctx->md_ctx, K, md_len);
		ttls_md_hmac_update(&ctx->md_ctx, ctx->V, md_len);
		ttls_md_hmac_finish(&ctx->md_ctx, ctx->V);
	}
}

/*
 * Simplified HMAC_DRBG initialisation (for use with deterministic ECDSA)
 */
int ttls_hmac_drbg_seed_buf(ttls_hmac_drbg_context *ctx,
			const ttls_md_info_t * md_info,
			const unsigned char *data, size_t data_len)
{
	int ret;

	if ((ret = ttls_md_setup(&ctx->md_ctx, md_info, 1)) != 0)
		return ret;

	/*
	 * Set initial working state.
	 * Use the V memory location, which is currently all 0, to initialize the
	 * MD context with an all-zero key. Then set V to its initial value.
	 */
	ttls_md_hmac_starts(&ctx->md_ctx, ctx->V, ttls_md_get_size(md_info));
	memset(ctx->V, 0x01, ttls_md_get_size(md_info));

	ttls_hmac_drbg_update(ctx, data, data_len);

	return 0;
}

/*
 * HMAC_DRBG reseeding: 10.1.2.4 (arabic) + 9.2 (Roman)
 */
int ttls_hmac_drbg_reseed(ttls_hmac_drbg_context *ctx,
		  const unsigned char *additional, size_t len)
{
	unsigned char seed[TTLS_HMAC_DRBG_MAX_SEED_INPUT];
	size_t seedlen;

	/* III. Check input length */
	if (len > TTLS_HMAC_DRBG_MAX_INPUT ||
		ctx->entropy_len + len > TTLS_HMAC_DRBG_MAX_SEED_INPUT)
	{
		return(TTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG);
	}

	memset(seed, 0, TTLS_HMAC_DRBG_MAX_SEED_INPUT);

	/* IV. Gather entropy_len bytes of entropy for the seed */
	if (ctx->f_entropy(ctx->p_entropy, seed, ctx->entropy_len) != 0)
		return(TTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED);

	seedlen = ctx->entropy_len;

	/* 1. Concatenate entropy and additional data if any */
	if (additional != NULL && len != 0)
	{
		memcpy(seed + seedlen, additional, len);
		seedlen += len;
	}

	/* 2. Update state */
	ttls_hmac_drbg_update(ctx, seed, seedlen);

	/* 3. Reset reseed_counter */
	ctx->reseed_counter = 1;

	/* 4. Done */
	return 0;
}

/*
 * HMAC_DRBG initialisation (10.1.2.3 + 9.1)
 */
int ttls_hmac_drbg_seed(ttls_hmac_drbg_context *ctx,
		const ttls_md_info_t * md_info,
		int (*f_entropy)(void *, unsigned char *, size_t),
		void *p_entropy,
		const unsigned char *custom,
		size_t len)
{
	int ret;
	size_t entropy_len, md_size;

	if ((ret = ttls_md_setup(&ctx->md_ctx, md_info, 1)) != 0)
		return ret;

	md_size = ttls_md_get_size(md_info);

	/*
	 * Set initial working state.
	 * Use the V memory location, which is currently all 0, to initialize the
	 * MD context with an all-zero key. Then set V to its initial value.
	 */
	ttls_md_hmac_starts(&ctx->md_ctx, ctx->V, md_size);
	memset(ctx->V, 0x01, md_size);

	ctx->f_entropy = f_entropy;
	ctx->p_entropy = p_entropy;

	ctx->reseed_interval = TTLS_HMAC_DRBG_RESEED_INTERVAL;

	/*
	 * See SP800-57 5.6.1 (p. 65-66) for the security strength provided by
	 * each hash function, then according to SP800-90A rev1 10.1 table 2,
	 * min_entropy_len (in bits) is security_strength.
	 *
	 * (This also matches the sizes used in the NIST test vectors.)
	 */
	entropy_len = md_size <= 20 ? 16 : /* 160-bits hash -> 128 bits */
				  md_size <= 28 ? 24 : /* 224-bits hash -> 192 bits */
		  32;  /* better (256+) -> 256 bits */

	/*
	 * For initialisation, use more entropy to emulate a nonce
	 * (Again, matches test vectors.)
	 */
	ctx->entropy_len = entropy_len * 3 / 2;

	if ((ret = ttls_hmac_drbg_reseed(ctx, custom, len)) != 0)
		return ret;

	ctx->entropy_len = entropy_len;

	return 0;
}

/*
 * Set prediction resistance
 */
void ttls_hmac_drbg_set_prediction_resistance(ttls_hmac_drbg_context *ctx,
				  int resistance)
{
	ctx->prediction_resistance = resistance;
}

/*
 * Set entropy length grabbed for reseeds
 */
void ttls_hmac_drbg_set_entropy_len(ttls_hmac_drbg_context *ctx, size_t len)
{
	ctx->entropy_len = len;
}

/*
 * Set reseed interval
 */
void ttls_hmac_drbg_set_reseed_interval(ttls_hmac_drbg_context *ctx, int interval)
{
	ctx->reseed_interval = interval;
}

/*
 * HMAC_DRBG random function with optional additional data:
 * 10.1.2.5 (arabic) + 9.3 (Roman)
 */
int ttls_hmac_drbg_random_with_add(void *p_rng,
				   unsigned char *output, size_t out_len,
				   const unsigned char *additional, size_t add_len)
{
	int ret;
	ttls_hmac_drbg_context *ctx = (ttls_hmac_drbg_context *) p_rng;
	size_t md_len = ttls_md_get_size(ctx->md_ctx.md_info);
	size_t left = out_len;
	unsigned char *out = output;

	/* II. Check request length */
	if (out_len > TTLS_HMAC_DRBG_MAX_REQUEST)
		return(TTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG);

	/* III. Check input length */
	if (add_len > TTLS_HMAC_DRBG_MAX_INPUT)
		return(TTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG);

	/* 1. (aka VII and IX) Check reseed counter and PR */
	if (ctx->f_entropy != NULL && /* For no-reseeding instances */
		(ctx->prediction_resistance == TTLS_HMAC_DRBG_PR_ON ||
		  ctx->reseed_counter > ctx->reseed_interval))
	{
		if ((ret = ttls_hmac_drbg_reseed(ctx, additional, add_len)) != 0)
			return ret;

		add_len = 0; /* VII.4 */
	}

	/* 2. Use additional data if any */
	if (additional != NULL && add_len != 0)
		ttls_hmac_drbg_update(ctx, additional, add_len);

	/* 3, 4, 5. Generate bytes */
	while (left != 0)
	{
		size_t use_len = left > md_len ? md_len : left;

		ttls_md_hmac_reset(&ctx->md_ctx);
		ttls_md_hmac_update(&ctx->md_ctx, ctx->V, md_len);
		ttls_md_hmac_finish(&ctx->md_ctx, ctx->V);

		memcpy(out, ctx->V, use_len);
		out += use_len;
		left -= use_len;
	}

	/* 6. Update */
	ttls_hmac_drbg_update(ctx, additional, add_len);

	/* 7. Update reseed counter */
	ctx->reseed_counter++;

	/* 8. Done */
	return 0;
}

/*
 * HMAC_DRBG random function
 */
int ttls_hmac_drbg_random(void *p_rng, unsigned char *output, size_t out_len)
{
	int ret;
	ttls_hmac_drbg_context *ctx = (ttls_hmac_drbg_context *) p_rng;

	spin_lock(&ctx->mutex);

	ret = ttls_hmac_drbg_random_with_add(ctx, output, out_len, NULL, 0);

	spin_unlock(&ctx->mutex);

	return ret;
}

/*
 * Free an HMAC_DRBG context
 */
void ttls_hmac_drbg_free(ttls_hmac_drbg_context *ctx)
{
	if (ctx == NULL)
		return;

	ttls_md_free(&ctx->md_ctx);
	ttls_zeroize(ctx, sizeof(ttls_hmac_drbg_context));
}

/* Dummy checkup routine */
int ttls_hmac_drbg_self_test(int verbose)
{
	(void) verbose;
	return 0;
}

#endif /* TTLS_HMAC_DRBG_C */
