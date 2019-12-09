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
 * @Q			- public key;
 * @Qp			- value of the public key of the peer;
 * @z			- shared secret which is _P.X
 *			  (see ttls_ecdh_compute_shared());
 * @Vi			- blinding value;
 * @Vf			- unblinding value;
 * @d			- private key;
 * @_d			- previous private key;
 */
typedef struct {
	TlsEcpGrp	grp;
	TlsEcpPoint	Q;
	TlsEcpPoint	Qp;
	union {
		TlsMpi		z;
		TlsEcpPoint	_P;
	};
	TlsEcpPoint	Vi;
	TlsEcpPoint	Vf;
	TlsMpi		d;
	TlsMpi		_d;
} TlsECDHCtx;

int ttls_ecdh_make_params(TlsECDHCtx *ctx, size_t *olen,
			  unsigned char *buf, size_t blen);

/**
 * \brief		   This function sets up an ECDH context from an EC key.
 *
 *				  It is used by clients and servers in place of the
 *				  ServerKeyExchange for static ECDH, and imports ECDH
 *				  parameters from the EC key information of a certificate.
 *
 * \param ctx	   The ECDH context to set up.
 * \param key	   The EC key to use.
 * \param side	  Defines the source of the key:
 *				  <ul><li>1: Our key.</li>
		<li>0: The key of the peer.</li></ul>
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX error code
 *				  on failure.
 *
 * \see			 ecp.h
 */
int ttls_ecdh_get_params(TlsECDHCtx *ctx, const TlsEcpKeypair *key,
		 ttls_ecdh_side side);

int ttls_ecdh_make_public(TlsECDHCtx *ctx, size_t *olen,
			  unsigned char *buf, size_t blen);

/**
 * \brief	   This function parses and processes a TLS ClientKeyExchange
 *			  payload.
 *
 *			  This is the second function used by a TLS server for ECDH(E)
 *			  ciphersuites.
 *
 * \param ctx   The ECDH context.
 * \param buf   The start of the input buffer.
 * \param blen  The length of the input buffer.
 *
 * \return	  \c 0 on success, or an \c TTLS_ERR_ECP_XXX error code
 *			  on failure.
 *
 * \see		 ecp.h
 */
int ttls_ecdh_read_public(TlsECDHCtx *ctx,
		  const unsigned char *buf, size_t blen);

/**
 * \brief		   This function derives and exports the shared secret.
 *
 *				  This is the last function used by both TLS client
 *				  and servers.
 *
 * \param ctx	   The ECDH context.
 * \param olen	  The number of Bytes written.
 * \param buf	   The destination buffer.
 * \param blen	  The length of the destination buffer.
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX error code
 *				  on failure.
 *
 * \see			 ecp.h
 *
 * \note			If \p f_rng is not NULL, it is used to implement
 *				  countermeasures against potential elaborate timing
 *				  attacks. For more information, see ttls_ecp_mul().
 */
int ttls_ecdh_calc_secret(TlsECDHCtx *ctx, size_t *olen,
		  unsigned char *buf, size_t blen);

#endif /* ecdh.h */
