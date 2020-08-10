/**
 *		Tempesta TLS
 *
 * The Elliptic Curve Diffie-Hellman (ECDH) protocol APIs.
 *
 * ECDH is an anonymous key agreement protocol allowing two parties to
 * establish a shared secret over an insecure channel. Each party must have an
 * elliptic-curve public–private key pair.
 *
 * For more information, see NIST SP 800-56A Rev. 2: Recommendation for
 * Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography.
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
#ifndef TTLS_ECDH_H
#define TTLS_ECDH_H

#include "bignum.h"
#include "ecp.h"

/**
 * Defines the source of the imported EC key: our key or the key of the peer.
 */
typedef enum {
	TTLS_ECDH_OURS,
	TTLS_ECDH_THEIRS,
} ttls_ecdh_side;

/**
 * The ECDH context structure.
 *
 * @rgp			- elliptic curve used;
 * @d			- private key;
 * @Q			- public key;
 * @Qp			- the peer X and Y coordinates of the public key point;
 */
typedef struct {
	const TlsEcpGrp	*grp;
	TlsMpi		d;
	TlsEcpPoint	Q;
	unsigned long	Qp[0];
} TlsECDHCtx;

int ttls_ecdh_make_params(TlsECDHCtx *ctx, size_t *olen,
			  unsigned char *buf, size_t blen);
int ttls_ecdh_get_params(TlsECDHCtx *ctx, const TlsEcpKeypair *key);

int ttls_ecdh_make_public(TlsECDHCtx *ctx, size_t *olen, unsigned char *buf,
			  size_t blen);
int ttls_ecdh_read_public(TlsECDHCtx *ctx, const unsigned char *buf,
			  size_t blen);

int ttls_ecdh_calc_secret(TlsECDHCtx *ctx, size_t *olen, unsigned char *buf,
			  size_t blen);

#endif /* ecdh.h */
