/**
 *		Tempesta TLS
 *
 * The Elliptic Curve Digital Signature Algorithm (ECDSA).
 *
 * ECDSA is defined in Standards for Efficient Cryptography Group (SECG):
 * SEC1 Elliptic Curve Cryptography.
 * The use of ECDSA for TLS is defined in RFC 8422.
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
#ifndef TTLS_ECDSA_H
#define TTLS_ECDSA_H

#include "ecp.h"
#include "crypto.h"

/*
 * RFC 8422 page 18:
 *
 *	Ecdsa-Sig-Value ::= SEQUENCE {
 *		r	INTEGER,
 *		s	INTEGER
 *	 }
 *
 * Size is at most 1 (tag) + 1 (len) + 1 (initial 0) + ECP_MAX_BYTES for each
 * of r and s, twice that + 1 (tag) + 2 (len) for the sequence (assuming
 * ECP_MAX_BYTES is less than 126 for r and s, and less than 124
 * (total len <= 255) for the sequence).
 */
#if TTLS_ECP_MAX_BYTES > 124
#error "TTLS_ECP_MAX_BYTES bigger than expected, please fix TTLS_ECDSA_MAX_LEN"
#endif

/* The maximal size of an ECDSA signature in bytes. */
#define TTLS_ECDSA_MAX_LEN	(3 + 2 * (3 + TTLS_ECP_MAX_BYTES))

/**
 * \brief		   This function computes the ECDSA signature of a
 *				  previously-hashed message.
 *
 * \note			The deterministic version is usually preferred.
 *
 * \param grp	   The ECP group.
 * \param r		 The first output integer.
 * \param s		 The second output integer.
 * \param d		 The private signing key.
 * \param buf	   The message hash.
 * \param blen	  The length of \p buf.
 *
 * \note			If the bitlength of the message hash is larger than the
 *				  bitlength of the group order, then the hash is truncated
 *				  as defined in <em>Standards for Efficient Cryptography Group
 *				  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *				  4.1.3, step 5.
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX
 *				  or \c TTLS_MPI_XXX error code on failure.
 *
 * \see			 ecp.h
 */
int ttls_ecdsa_sign(TlsEcpGrp *grp, TlsMpi *r, TlsMpi *s,
				const TlsMpi *d, const unsigned char *buf, size_t blen);

int ttls_ecdsa_write_signature(TlsEcpKeypair *ctx,
			       const unsigned char *hash, size_t hlen,
			       unsigned char *sig, size_t *slen);
int ttls_ecdsa_read_signature(TlsEcpKeypair *ctx,
			      const unsigned char *hash, size_t hlen,
			      const unsigned char *sig, size_t slen);

#endif /* ecdsa.h */
