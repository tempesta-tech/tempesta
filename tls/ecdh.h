/**
 * \file ecdh.h
 *
 * \brief The Elliptic Curve Diffie-Hellman (ECDH) protocol APIs.
 *
 * ECDH is an anonymous key agreement protocol allowing two parties to
 * establish a shared secret over an insecure channel. Each party must have an
 * elliptic-curve public–private key pair.
 *
 * For more information, see <em>NIST SP 800-56A Rev. 2: Recommendation for
 * Pair-Wise Key Establishment Schemes Using Discrete Logarithm
 * Cryptography</em>.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef TTLS_ECDH_H
#define TTLS_ECDH_H

#include "ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines the source of the imported EC key:
 * <ul><li>Our key.</li>
 * <li>The key of the peer.</li></ul>
 */
typedef enum
{
	TTLS_ECDH_OURS,
	TTLS_ECDH_THEIRS,
} ttls_ecdh_side;

/**
 * \brief		   The ECDH context structure.
 */
typedef struct
{
	ttls_ecp_group grp;   /*!< The elliptic curve used. */
	ttls_mpi d;		   /*!< The private key. */
	ttls_ecp_point Q;	 /*!< The public key. */
	ttls_ecp_point Qp;	/*!< The value of the public key of the peer. */
	ttls_mpi z;		   /*!< The shared secret. */
	int point_format;		/*!< The format of point export in TLS messages. */
	ttls_ecp_point Vi;	/*!< The blinding value. */
	ttls_ecp_point Vf;	/*!< The unblinding value. */
	ttls_mpi _d;		  /*!< The previous \p d. */
}
ttls_ecdh_context;

/**
 * \brief		   This function generates an ECDH keypair on an elliptic
 *				  curve.
 *
 *				  This function performs the first of two core computations
 *				  implemented during the ECDH key exchange. The second core
 *				  computation is performed by ttls_ecdh_compute_shared().
 *
 * \param grp	   The ECP group.
 * \param d		 The destination MPI (private key).
 * \param Q		 The destination point (public key).
 * \param f_rng	 The RNG function.
 * \param p_rng	 The RNG parameter.
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX or
 *				  \c TTLS_MPI_XXX error code on failure.
 *
 * \see			 ecp.h
 */
int ttls_ecdh_gen_public(ttls_ecp_group *grp, ttls_mpi *d, ttls_ecp_point *Q,
					 int (*f_rng)(void *, unsigned char *, size_t),
					 void *p_rng);

/**
 * \brief		   This function computes the shared secret.
 *
 *				  This function performs the second of two core computations
 *				  implemented during the ECDH key exchange. The first core
 *				  computation is performed by ttls_ecdh_gen_public().
 *
 * \param grp	   The ECP group.
 * \param z		 The destination MPI (shared secret).
 * \param Q		 The public key from another party.
 * \param d		 Our secret exponent (private key).
 * \param f_rng	 The RNG function.
 * \param p_rng	 The RNG parameter.
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX or
 *				  \c TTLS_MPI_XXX error code on failure.
 *
 * \see			 ecp.h
 *
 * \note			If \p f_rng is not NULL, it is used to implement
 *				  countermeasures against potential elaborate timing
 *				  attacks. For more information, see ttls_ecp_mul().
 */
int ttls_ecdh_compute_shared(ttls_ecp_group *grp, ttls_mpi *z,
						 const ttls_ecp_point *Q, const ttls_mpi *d,
						 int (*f_rng)(void *, unsigned char *, size_t),
						 void *p_rng);

/**
 * \brief		   This function initializes an ECDH context.
 *
 * \param ctx	   The ECDH context to initialize.
 */
void ttls_ecdh_init(ttls_ecdh_context *ctx);

/**
 * \brief		   This function frees a context.
 *
 * \param ctx	   The context to free.
 */
void ttls_ecdh_free(ttls_ecdh_context *ctx);

/**
 * \brief		   This function generates a public key and a TLS
 *				  ServerKeyExchange payload.
 *
 *				  This is the first function used by a TLS server for ECDHE
 *				  ciphersuites.
 *
 * \param ctx	   The ECDH context.
 * \param olen	  The number of characters written.
 * \param buf	   The destination buffer.
 * \param blen	  The length of the destination buffer.
 * \param f_rng	 The RNG function.
 * \param p_rng	 The RNG parameter.
 *
 * \note			This function assumes that the ECP group (grp) of the
 *				  \p ctx context has already been properly set,
 *				  for example, using ttls_ecp_group_load().
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX error code
 *				  on failure.
 *
 * \see			 ecp.h
 */
int ttls_ecdh_make_params(ttls_ecdh_context *ctx, size_t *olen,
					  unsigned char *buf, size_t blen,
					  int (*f_rng)(void *, unsigned char *, size_t),
					  void *p_rng);

/**
 * \brief		   This function parses and processes a TLS ServerKeyExhange
 *				  payload.
 *
 *				  This is the first function used by a TLS client for ECDHE
 *				  ciphersuites.
 *
 * \param ctx	   The ECDH context.
 * \param buf	   The pointer to the start of the input buffer.
 * \param end	   The address for one Byte past the end of the buffer.
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX error code
 *				  on failure.
 *
 * \see			 ecp.h
 */
int ttls_ecdh_read_params(ttls_ecdh_context *ctx,
					  const unsigned char **buf, const unsigned char *end);

/**
 * \brief		   This function sets up an ECDH context from an EC key.
 *
 *				  It is used by clients and servers in place of the
 *				  ServerKeyEchange for static ECDH, and imports ECDH
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
int ttls_ecdh_get_params(ttls_ecdh_context *ctx, const ttls_ecp_keypair *key,
					 ttls_ecdh_side side);

/**
 * \brief		   This function generates a public key and a TLS
 *				  ClientKeyExchange payload.
 *
 *				  This is the second function used by a TLS client for ECDH(E)
 *				  ciphersuites.
 *
 * \param ctx	   The ECDH context.
 * \param olen	  The number of Bytes written.
 * \param buf	   The destination buffer.
 * \param blen	  The size of the destination buffer.
 * \param f_rng	 The RNG function.
 * \param p_rng	 The RNG parameter.
 *
 * \return		  \c 0 on success, or an \c TTLS_ERR_ECP_XXX error code
 *				  on failure.
 *
 * \see			 ecp.h
 */
int ttls_ecdh_make_public(ttls_ecdh_context *ctx, size_t *olen,
					  unsigned char *buf, size_t blen,
					  int (*f_rng)(void *, unsigned char *, size_t),
					  void *p_rng);

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
int ttls_ecdh_read_public(ttls_ecdh_context *ctx,
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
 * \param f_rng	 The RNG function.
 * \param p_rng	 The RNG parameter.
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
int ttls_ecdh_calc_secret(ttls_ecdh_context *ctx, size_t *olen,
					  unsigned char *buf, size_t blen,
					  int (*f_rng)(void *, unsigned char *, size_t),
					  void *p_rng);

#ifdef __cplusplus
}
#endif

#endif /* ecdh.h */
