/**
 *		Tempesta TLS
 *
 * Diffie-Hellman-Merkle key exchange.
 *
 * RFC-3526: More Modular Exponential (MODP) Diffie-Hellman groups for Internet
 * Key Exchange (IKE) defines a number of standardized Diffie-Hellman groups
 * for IKE.
 *
 * RFC-5114: Additional Diffie-Hellman Groups for Use with IETF Standards
 * defines a number of standardized Diffie-Hellman groups that can be used.
 *
 * The security of the DHM key exchange relies on the proper choice of prime
 * modulus - optimally, it should be a safe prime. The usage of non-safe primes
 * both decreases the difficulty of the underlying discrete logarithm problem
 * and can lead to small subgroup attacks leaking private exponent bits when
 * invalid public keys are used and not detected. This is especially relevant
 * if the same DHM parameters are reused for multiple key exchanges as in static
 * DHM, while the criticality of small-subgroup attacks is lower for ephemeral
 * DHM.
 *
 * For performance reasons, the code does neither perform primality nor safe
 * primality tests, nor the expensive checks for invalid subgroups. Moreover,
 * even if these were performed, non-standardized primes cannot be trusted
 * because of the possibility of backdoors that can't be effectively checked
 * for.
 *
 * Diffie-Hellman-Merkle is therefore a security risk when not using
 * standardized primes generated using a trustworthy ("nothing up my sleeve")
 * method, such as the RFC 3526 / 7919 primes. In the TLS protocol, DH
 * parameters need to be negotiated, so using the default primes systematically
 * is not always an option. If possible, use Elliptic Curve Diffie-Hellman
 * (ECDH), which has better performance, and for which the TLS protocol mandates
 * the use of standard parameters.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
#ifndef TTLS_DHM_H
#define TTLS_DHM_H

#include "bignum.h"

/*
 * DHM Error codes
 */
#define TTLS_ERR_DHM_BAD_INPUT_DATA		-0x3080  /**< Bad input parameters. */
#define TTLS_ERR_DHM_READ_PARAMS_FAILED				-0x3100  /**< Reading of the DHM parameters failed. */
#define TTLS_ERR_DHM_READ_PUBLIC_FAILED				-0x3200  /**< Reading of the public values failed. */
#define TTLS_ERR_DHM_MAKE_PUBLIC_FAILED				-0x3280  /**< Making of the public value failed. */
#define TTLS_ERR_DHM_CALC_SECRET_FAILED				-0x3300  /**< Calculation of the DHM secret failed. */

/**
 * The DHM context structure.
 *
 * @len		- The size of P in bytes;
 * @P		- The prime modulus;
 * @G		- The generator;
 * @X		- Our secret value;
 * @GX		- Our public key = G^X mod P;
 * @GY		- The public key of the peer = G^Y mod P;
 * @K		- The shared secret = G^(XY) mod P;
 * @RP		- The cached value = R^2 mod P;
 * @Vi		- The blinding value;
 * @Vf		- The unblinding value;
 * @pX		- The previous X.
 */
typedef struct {
	size_t	len;
	TlsMpi	P;
	TlsMpi	G;
	TlsMpi	X;
	TlsMpi	GX;
	TlsMpi	GY;
	TlsMpi	K;
	TlsMpi	RP;
	TlsMpi	Vi;
	TlsMpi	Vf;
	TlsMpi	pX;
} TlsDHMCtx;

/**
 * \brief		  This function parses the ServerKeyExchange parameters.
 *
 * \param ctx	  The DHM context.
 * \param p		On input, *p must be the start of the input buffer.
 *				 On output, *p is updated to point to the end of the data
 *				 that has been read. On success, this is the first byte
 *				 past the end of the ServerKeyExchange parameters.
 *				 On error, this is the point at which an error has been
 *				 detected, which is usually not useful except to debug
 *				 failures.
 * \param end	  The end of the input buffer.
 *
 * \return		 \c 0 on success, or an \c TTLS_ERR_DHM_XXX error code
 *				 on failure.
 */
int ttls_dhm_read_params(TlsDHMCtx *ctx,
		 unsigned char **p,
		 const unsigned char *end);

int ttls_dhm_make_params(TlsDHMCtx *ctx, int x_size, unsigned char *output,
			 size_t *olen);

/**
 * \brief		  This function imports the public value G^Y of the peer.
 *
 * \param ctx	  The DHM context.
 * \param input	The input buffer.
 * \param ilen	 The size of the input buffer.
 *
 * \return		 \c 0 on success, or an \c TTLS_ERR_DHM_XXX error code
 *				 on failure.
 */
int ttls_dhm_read_public(TlsDHMCtx *ctx,
		 const unsigned char *input, size_t ilen);

/**
 * \brief		  This function creates its own private value \c X and
 *				 exports \c G^X.
 *
 * \param ctx	  The DHM context.
 * \param x_size   The private value size in Bytes.
 * \param output   The destination buffer.
 * \param olen	 The length of the destination buffer. Must be at least
				   equal to ctx->len (the size of \c P).
 *
 * \note		   The destination buffer will always be fully written
 *				 so as to contain a big-endian presentation of G^X mod P.
 *				 If it is larger than ctx->len, it will accordingly be
 *				 padded with zero-bytes in the beginning.
 *
 * \return		 \c 0 on success, or an \c TTLS_ERR_DHM_XXX error code
 *				 on failure.
 */
int ttls_dhm_make_public(TlsDHMCtx *ctx, int x_size,
		 unsigned char *output, size_t olen);

int ttls_dhm_calc_secret(TlsDHMCtx *ctx,
		 unsigned char *output, size_t output_size, size_t *olen);

void ttls_dhm_load(TlsDHMCtx *ctx);

#endif /* dhm.h */
