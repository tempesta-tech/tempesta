/**
 *		Tempesta TLS
 *
 * Context-independent RSA helper functions.
 *
 * This file declares some RSA-related helper functions useful when
 * implementing the RSA interface. They are public and provided in a
 * separate compilation unit in order to make it easy for designers of
 * alternative RSA implementations to use them in their code, as it is
 * conceived that the functionality they provide will be necessary
 * for most complete implementations.
 *
 * There are two classes of helper functions:
 * (1) Parameter-generating helpers. These are:
 *  - ttls_rsa_deduce_primes
 *  - ttls_rsa_deduce_private_exponent
 *  - ttls_rsa_deduce_crt
 *   Each of these functions takes a set of core RSA parameters
 *   and generates some other, or CRT related parameters.
 * (2) Parameter-checking helpers. These are:
 *  - ttls_rsa_validate_params
 *  - ttls_rsa_validate_crt
 *  They take a set of core or CRT related RSA parameters
 *  and check their validity.
 *
 * Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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
#ifndef TTLS_RSA_INTERNAL_H
#define TTLS_RSA_INTERNAL_H

#include "config.h"
#include "bignum.h"

/**
 * \brief		  Compute RSA prime moduli P, Q from public modulus N=PQ
 *				 and a pair of private and public key.
 *
 * \note		   This is a 'static' helper function not operating on
 *				 an RSA context. Alternative implementations need not
 *				 overwrite it.
 *
 * \param N		RSA modulus N = PQ, with P, Q to be found
 * \param E		RSA public exponent
 * \param D		RSA private exponent
 * \param P		Pointer to MPI holding first prime factor of N on success
 * \param Q		Pointer to MPI holding second prime factor of N on success
 *
 * \return
 *				 - 0 if successful. In this case, P and Q constitute a
 *				   factorization of N.
 *				 - A non-zero error code otherwise.
 *
 * \note		   It is neither checked that P, Q are prime nor that
 *				 D, E are modular inverses wrt. P-1 and Q-1. For that,
 *				 use the helper function \c ttls_rsa_validate_params.
 *
 */
int ttls_rsa_deduce_primes(ttls_mpi const *N, ttls_mpi const *E,
				   ttls_mpi const *D,
				   ttls_mpi *P, ttls_mpi *Q);

/**
 * \brief		  Compute RSA private exponent from
 *				 prime moduli and public key.
 *
 * \note		   This is a 'static' helper function not operating on
 *				 an RSA context. Alternative implementations need not
 *				 overwrite it.
 *
 * \param P		First prime factor of RSA modulus
 * \param Q		Second prime factor of RSA modulus
 * \param E		RSA public exponent
 * \param D		Pointer to MPI holding the private exponent on success.
 *
 * \return
 *				 - 0 if successful. In this case, D is set to a simultaneous
 *				   modular inverse of E modulo both P-1 and Q-1.
 *				 - A non-zero error code otherwise.
 *
 * \note		   This function does not check whether P and Q are primes.
 *
 */
int ttls_rsa_deduce_private_exponent(ttls_mpi const *P,
				 ttls_mpi const *Q,
				 ttls_mpi const *E,
				 ttls_mpi *D);


/**
 * \brief		  Generate RSA-CRT parameters
 *
 * \note		   This is a 'static' helper function not operating on
 *				 an RSA context. Alternative implementations need not
 *				 overwrite it.
 *
 * \param P		First prime factor of N
 * \param Q		Second prime factor of N
 * \param D		RSA private exponent
 * \param DP	   Output variable for D modulo P-1
 * \param DQ	   Output variable for D modulo Q-1
 * \param QP	   Output variable for the modular inverse of Q modulo P.
 *
 * \return		 0 on success, non-zero error code otherwise.
 *
 * \note		   This function does not check whether P, Q are
 *				 prime and whether D is a valid private exponent.
 *
 */
int ttls_rsa_deduce_crt(const ttls_mpi *P, const ttls_mpi *Q,
				const ttls_mpi *D, ttls_mpi *DP,
				ttls_mpi *DQ, ttls_mpi *QP);


/**
 * \brief		  Check validity of core RSA parameters
 *
 * \note		   This is a 'static' helper function not operating on
 *				 an RSA context. Alternative implementations need not
 *				 overwrite it.
 *
 * \param N		RSA modulus N = PQ
 * \param P		First prime factor of N
 * \param Q		Second prime factor of N
 * \param D		RSA private exponent
 * \param E		RSA public exponent
 *
 * \return
 *				 - 0 if the following conditions are satisfied
 *				   if all relevant parameters are provided:
 *		- 1 < N = P * Q
 *		- 1 < D, E < N
 *		- D and E are modular inverses modulo P-1 and Q-1
 *				   (%) This is only done if TTLS_GENPRIME is defined.
 *				 - A non-zero error code otherwise.
 *
 * \note		   The function can be used with a restricted set of arguments
 *				 to perform specific checks only. E.g., calling it with
 *				 (-,P,-,-,-) and a PRNG amounts to a primality check for P.
 */
int ttls_rsa_validate_params(const ttls_mpi *N, const ttls_mpi *P,
		 const ttls_mpi *Q, const ttls_mpi *D,
		 const ttls_mpi *E, bool rnd);

/**
 * \brief		  Check validity of RSA CRT parameters
 *
 * \note		   This is a 'static' helper function not operating on
 *				 an RSA context. Alternative implementations need not
 *				 overwrite it.
 *
 * \param P		First prime factor of RSA modulus
 * \param Q		Second prime factor of RSA modulus
 * \param D		RSA private exponent
 * \param DP	   MPI to check for D modulo P-1
 * \param DQ	   MPI to check for D modulo P-1
 * \param QP	   MPI to check for the modular inverse of Q modulo P.
 *
 * \return
 *				 - 0 if the following conditions are satisfied:
 *		- D = DP mod P-1 if P, D, DP != NULL
 *		- Q = DQ mod P-1 if P, D, DQ != NULL
 *		- QP = Q^-1 mod P if P, Q, QP != NULL
 *				 - \c TTLS_ERR_RSA_KEY_CHECK_FAILED if check failed,
 *				   potentially including \c TTLS_ERR_MPI_XXX if some
 *				   MPI calculations failed.
 *				 - \c TTLS_ERR_RSA_BAD_INPUT_DATA if insufficient
 *				   data was provided to check DP, DQ or QP.
 *
 * \note		   The function can be used with a restricted set of arguments
 *				 to perform specific checks only. E.g., calling it with the
 *				 parameters (P, -, D, DP, -, -) will check DP = D mod P-1.
 */
int ttls_rsa_validate_crt(const ttls_mpi *P,  const ttls_mpi *Q,
				  const ttls_mpi *D,  const ttls_mpi *DP,
				  const ttls_mpi *DQ, const ttls_mpi *QP);

#endif /* rsa_internal.h */
