/**
 * \file bignum.h
 *
 * \brief Multi-precision integer library
 */
/*
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
#ifndef TTLS_BIGNUM_H
#define TTLS_BIGNUM_H

/**< An error occurred while reading from or writing to a file. */
#define TTLS_ERR_MPI_FILE_IO_ERROR					 -0x0002
/**< Bad input parameters to function. */
#define TTLS_ERR_MPI_BAD_INPUT_DATA					-0x0004
/**< There is an invalid character in the digit string. */
#define TTLS_ERR_MPI_INVALID_CHARACTER				 -0x0006
/**< The buffer is too small to write to. */
#define TTLS_ERR_MPI_BUFFER_TOO_SMALL				  -0x0008
/**< The input arguments are negative or result in illegal output. */
#define TTLS_ERR_MPI_NEGATIVE_VALUE					-0x000A
/**< The input argument for division is zero, which is not allowed. */
#define TTLS_ERR_MPI_DIVISION_BY_ZERO				  -0x000C
/**< The input arguments are not acceptable. */
#define TTLS_ERR_MPI_NOT_ACCEPTABLE					-0x000E
/**< Memory allocation failed. */
#define TTLS_ERR_MPI_ALLOC_FAILED					  -0x0010

#define TTLS_MPI_CHK(f) do { if ((ret = f) != 0) goto cleanup; } while (0)

/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 */
#define TTLS_MPI_MAX_LIMBS							 10000

/*
 * Maximum window size used for modular exponentiation. Default: 6
 * Minimum value: 1. Maximum value: 6.
 *
 * Result is an array of (2 << TTLS_MPI_WINDOW_SIZE) MPIs used
 * for the sliding window calculation. (So 64 by default)
 *
 * Reduction in size, reduces speed.
 */
#define TTLS_MPI_WINDOW_SIZE						   6

/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * (Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits)
 *
 * Note: Calculations can temporarily result in larger MPIs. So the number
 * of limbs required (TTLS_MPI_MAX_LIMBS) is higher.
 */
#define TTLS_MPI_MAX_SIZE							  1024

/**< Maximum number of bits for usable MPIs. */
#define TTLS_MPI_MAX_BITS							  (8 * TTLS_MPI_MAX_SIZE)

/*
 * When reading from files with ttls_mpi_read_file() and writing to files with
 * ttls_mpi_write_file() the buffer should have space
 * for a (short) label, the MPI (in the provided radix), the newline
 * characters and the '\0'.
 *
 * By default we assume at least a 10 char label, a minimum radix of 10
 * (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
 * Autosized at compile time for at least a 10 char label, a minimum radix
 * of 10 (decimal) for a number of TTLS_MPI_MAX_BITS size.
 *
 * This used to be statically sized to 1250 for a maximum of 4096 bit
 * numbers (1234 decimal chars).
 *
 * Calculate using the formula:
 *  TTLS_MPI_RW_BUFFER_SIZE = ceil(TTLS_MPI_MAX_BITS / ln(10) * ln(2)) +
 *								LabelSize + 6
 */
#define TTLS_MPI_MAX_BITS_SCALE100		  (100 * TTLS_MPI_MAX_BITS)
#define TTLS_LN_2_DIV_LN_10_SCALE100				 332
#define TTLS_MPI_RW_BUFFER_SIZE			 (((TTLS_MPI_MAX_BITS_SCALE100 + TTLS_LN_2_DIV_LN_10_SCALE100 - 1) / TTLS_LN_2_DIV_LN_10_SCALE100) + 10 + 6)

typedef  int64_t ttls_mpi_sint;
typedef uint64_t ttls_mpi_uint;

/**
 * \brief		  MPI structure
 */
typedef struct
{
	int s;			  /*!<  integer sign	  */
	size_t n;		   /*!<  total # of limbs  */
	ttls_mpi_uint *p;		  /*!<  pointer to limbs  */
} __attribute__((packed))
ttls_mpi;

/**
 * \brief		   Initialize one MPI (make internal references valid)
 *				  This just makes it ready to be set or freed,
 *				  but does not define a value for the MPI.
 *
 * \param X		 One MPI to initialize.
 */
void ttls_mpi_init(ttls_mpi *X);

/**
 * \brief		  Unallocate one MPI
 *
 * \param X		One MPI to unallocate.
 */
void ttls_mpi_free(ttls_mpi *X);

/**
 * \brief		  Enlarge to the specified number of limbs
 *
 * \param X		MPI to grow
 * \param nblimbs  The target number of limbs
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_grow(ttls_mpi *X, size_t nblimbs);

/**
 * \brief		  Resize down, keeping at least the specified number of limbs
 *
 * \param X		MPI to shrink
 * \param nblimbs  The minimum number of limbs to keep
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_shrink(ttls_mpi *X, size_t nblimbs);

/**
 * \brief		  Copy the contents of Y into X
 *
 * \param X		Destination MPI
 * \param Y		Source MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_copy(ttls_mpi *X, const ttls_mpi *Y);

/**
 * \brief		  Swap the contents of X and Y
 *
 * \param X		First MPI value
 * \param Y		Second MPI value
 */
void ttls_mpi_swap(ttls_mpi *X, ttls_mpi *Y);

/**
 * \brief		  Safe conditional assignement X = Y if assign is 1
 *
 * \param X		MPI to conditionally assign to
 * \param Y		Value to be assigned
 * \param assign   1: perform the assignment, 0: keep X's original value
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *
 * \note		   This function is equivalent to
 *					  if (assign) ttls_mpi_copy(X, Y);
 *				 except that it avoids leaking any information about whether
 *				 the assignment was done or not (the above code may leak
 *				 information through branch prediction and/or memory access
 *				 patterns analysis).
 */
int ttls_mpi_safe_cond_assign(ttls_mpi *X, const ttls_mpi *Y, unsigned char assign);

/**
 * \brief		  Safe conditional swap X <-> Y if swap is 1
 *
 * \param X		First ttls_mpi value
 * \param Y		Second ttls_mpi value
 * \param assign   1: perform the swap, 0: keep X and Y's original values
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *
 * \note		   This function is equivalent to
 *					  if (assign) ttls_mpi_swap(X, Y);
 *				 except that it avoids leaking any information about whether
 *				 the assignment was done or not (the above code may leak
 *				 information through branch prediction and/or memory access
 *				 patterns analysis).
 */
int ttls_mpi_safe_cond_swap(ttls_mpi *X, ttls_mpi *Y, unsigned char assign);

/**
 * \brief		  Set value from integer
 *
 * \param X		MPI to set
 * \param z		Value to use
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_lset(ttls_mpi *X, ttls_mpi_sint z);

/**
 * \brief		  Get a specific bit from X
 *
 * \param X		MPI to use
 * \param pos	  Zero-based index of the bit in X
 *
 * \return		 Either a 0 or a 1
 */
int ttls_mpi_get_bit(const ttls_mpi *X, size_t pos);

/**
 * \brief		  Set a bit of X to a specific value of 0 or 1
 *
 * \note		   Will grow X if necessary to set a bit to 1 in a not yet
 *				 existing limb. Will not grow if bit should be set to 0
 *
 * \param X		MPI to use
 * \param pos	  Zero-based index of the bit in X
 * \param val	  The value to set the bit to (0 or 1)
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_BAD_INPUT_DATA if val is not 0 or 1
 */
int ttls_mpi_set_bit(ttls_mpi *X, size_t pos, unsigned char val);

/**
 * \brief		  Return the number of zero-bits before the least significant
 *				 '1' bit
 *
 * Note: Thus also the zero-based index of the least significant '1' bit
 *
 * \param X		MPI to use
 */
size_t ttls_mpi_lsb(const ttls_mpi *X);

/**
 * \brief		  Return the number of bits up to and including the most
 *				 significant '1' bit'
 *
 * Note: Thus also the one-based index of the most significant '1' bit
 *
 * \param X		MPI to use
 */
size_t ttls_mpi_bitlen(const ttls_mpi *X);

/**
 * \brief		  Return the total size in bytes
 *
 * \param X		MPI to use
 */
size_t ttls_mpi_size(const ttls_mpi *X);

/**
 * \brief		  Import from an ASCII string
 *
 * \param X		Destination MPI
 * \param radix	Input numeric base
 * \param s		Null-terminated string buffer
 *
 * \return		 0 if successful, or a TTLS_ERR_MPI_XXX error code
 */
int ttls_mpi_read_string(ttls_mpi *X, int radix, const char *s);

/**
 * \brief		  Export into an ASCII string
 *
 * \param X		Source MPI
 * \param radix	Output numeric base
 * \param buf	  Buffer to write the string to
 * \param buflen   Length of buf
 * \param olen	 Length of the string written, including final NUL byte
 *
 * \return		 0 if successful, or a TTLS_ERR_MPI_XXX error code.
 *				 *olen is always updated to reflect the amount
 *				 of data that has (or would have) been written.
 *
 * \note		   Call this function with buflen = 0 to obtain the
 *				 minimum required buffer size in *olen.
 */
int ttls_mpi_write_string(const ttls_mpi *X, int radix,
							  char *buf, size_t buflen, size_t *olen);

/**
 * \brief		  Import X from unsigned binary data, big endian
 *
 * \param X		Destination MPI
 * \param buf	  Input buffer
 * \param buflen   Input buffer size
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_read_binary(ttls_mpi *X, const unsigned char *buf, size_t buflen);

/**
 * \brief		  Export X into unsigned binary data, big endian.
 *				 Always fills the whole buffer, which will start with zeros
 *				 if the number is smaller.
 *
 * \param X		Source MPI
 * \param buf	  Output buffer
 * \param buflen   Output buffer size
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
 */
int ttls_mpi_write_binary(const ttls_mpi *X, unsigned char *buf, size_t buflen);

/**
 * \brief		  Left-shift: X <<= count
 *
 * \param X		MPI to shift
 * \param count	Amount to shift
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_shift_l(ttls_mpi *X, size_t count);

/**
 * \brief		  Right-shift: X >>= count
 *
 * \param X		MPI to shift
 * \param count	Amount to shift
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_shift_r(ttls_mpi *X, size_t count);

/**
 * \brief		  Compare unsigned values
 *
 * \param X		Left-hand MPI
 * \param Y		Right-hand MPI
 *
 * \return		 1 if |X| is greater than |Y|,
 *				-1 if |X| is lesser  than |Y| or
 *				 0 if |X| is equal to |Y|
 */
int ttls_mpi_cmp_abs(const ttls_mpi *X, const ttls_mpi *Y);

/**
 * \brief		  Compare signed values
 *
 * \param X		Left-hand MPI
 * \param Y		Right-hand MPI
 *
 * \return		 1 if X is greater than Y,
 *				-1 if X is lesser  than Y or
 *				 0 if X is equal to Y
 */
int ttls_mpi_cmp_mpi(const ttls_mpi *X, const ttls_mpi *Y);

/**
 * \brief		  Compare signed values
 *
 * \param X		Left-hand MPI
 * \param z		The integer value to compare to
 *
 * \return		 1 if X is greater than z,
 *				-1 if X is lesser  than z or
 *				 0 if X is equal to z
 */
int ttls_mpi_cmp_int(const ttls_mpi *X, ttls_mpi_sint z);

/**
 * \brief		  Unsigned addition: X = |A| + |B|
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_add_abs(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Unsigned subtraction: X = |A| - |B|
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
int ttls_mpi_sub_abs(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Signed addition: X = A + B
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_add_mpi(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Signed subtraction: X = A - B
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_sub_mpi(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Signed addition: X = A + b
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param b		The integer value to add
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_add_int(ttls_mpi *X, const ttls_mpi *A, ttls_mpi_sint b);

/**
 * \brief		  Signed subtraction: X = A - b
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param b		The integer value to subtract
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_sub_int(ttls_mpi *X, const ttls_mpi *A, ttls_mpi_sint b);

/**
 * \brief		  Baseline multiplication: X = A * B
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_mul_mpi(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Baseline multiplication: X = A * b
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param b		The unsigned integer value to multiply with
 *
 * \note		   b is unsigned
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_mul_int(ttls_mpi *X, const ttls_mpi *A, ttls_mpi_uint b);

/**
 * \brief		  Division by ttls_mpi: A = Q * B + R
 *
 * \param Q		Destination MPI for the quotient
 * \param R		Destination MPI for the rest value
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note		   Either Q or R can be NULL.
 */
int ttls_mpi_div_mpi(ttls_mpi *Q, ttls_mpi *R, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Division by int: A = Q * b + R
 *
 * \param Q		Destination MPI for the quotient
 * \param R		Destination MPI for the rest value
 * \param A		Left-hand MPI
 * \param b		Integer to divide by
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note		   Either Q or R can be NULL.
 */
int ttls_mpi_div_int(ttls_mpi *Q, ttls_mpi *R, const ttls_mpi *A, ttls_mpi_sint b);

/**
 * \brief		  Modulo: R = A mod B
 *
 * \param R		Destination MPI for the rest value
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_DIVISION_BY_ZERO if B == 0,
 *				 TTLS_ERR_MPI_NEGATIVE_VALUE if B < 0
 */
int ttls_mpi_mod_mpi(ttls_mpi *R, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Modulo: r = A mod b
 *
 * \param r		Destination ttls_mpi_uint
 * \param A		Left-hand MPI
 * \param b		Integer to divide by
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_DIVISION_BY_ZERO if b == 0,
 *				 TTLS_ERR_MPI_NEGATIVE_VALUE if b < 0
 */
int ttls_mpi_mod_int(ttls_mpi_uint *r, const ttls_mpi *A, ttls_mpi_sint b);

/**
 * \brief		  Sliding-window exponentiation: X = A^E mod N
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param E		Exponent MPI
 * \param N		Modular MPI
 * \param _RR	  Speed-up MPI used for recalculations
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_BAD_INPUT_DATA if N is negative or even or
 *				 if E is negative
 *
 * \note		   _RR is used to avoid re-computing R*R mod N across
 *				 multiple calls, which speeds up things a bit. It can
 *				 be set to NULL if the extra performance is unneeded.
 */
int ttls_mpi_exp_mod(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *E, const ttls_mpi *N, ttls_mpi *_RR);

/**
 * \brief		  Fill an MPI X with size bytes of random
 *
 * \param X		Destination MPI
 * \param size	 Size in bytes
 * \param f_rng	RNG function
 * \param p_rng	RNG parameter
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 *
 * \note		   The bytes obtained from the PRNG are interpreted
 *				 as a big-endian representation of an MPI; this can
 *				 be relevant in applications like deterministic ECDSA.
 */
int ttls_mpi_fill_random(ttls_mpi *X, size_t size,
					 int (*f_rng)(void *, unsigned char *, size_t),
					 void *p_rng);

/**
 * \brief		  Greatest common divisor: G = gcd(A, B)
 *
 * \param G		Destination MPI
 * \param A		Left-hand MPI
 * \param B		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 */
int ttls_mpi_gcd(ttls_mpi *G, const ttls_mpi *A, const ttls_mpi *B);

/**
 * \brief		  Modular inverse: X = A^-1 mod N
 *
 * \param X		Destination MPI
 * \param A		Left-hand MPI
 * \param N		Right-hand MPI
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_BAD_INPUT_DATA if N is <= 1,
				   TTLS_ERR_MPI_NOT_ACCEPTABLE if A has no inverse mod N.
 */
int ttls_mpi_inv_mod(ttls_mpi *X, const ttls_mpi *A, const ttls_mpi *N);

/**
 * \brief		  Miller-Rabin primality test
 *
 * \param X		MPI to check
 * \param f_rng	RNG function
 * \param p_rng	RNG parameter
 *
 * \return		 0 if successful (probably prime),
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_NOT_ACCEPTABLE if X is not prime
 */
int ttls_mpi_is_prime(const ttls_mpi *X,
				  int (*f_rng)(void *, unsigned char *, size_t),
				  void *p_rng);

/**
 * \brief		  Prime number generation
 *
 * \param X		Destination MPI
 * \param nbits	Required size of X in bits
 *				 (3 <= nbits <= TTLS_MPI_MAX_BITS)
 * \param dh_flag  If 1, then (X-1)/2 will be prime too
 * \param f_rng	RNG function
 * \param p_rng	RNG parameter
 *
 * \return		 0 if successful (probably prime),
 *				 TTLS_ERR_MPI_ALLOC_FAILED if memory allocation failed,
 *				 TTLS_ERR_MPI_BAD_INPUT_DATA if nbits is < 3
 */
int ttls_mpi_gen_prime(ttls_mpi *X, size_t nbits, int dh_flag,
				   int (*f_rng)(void *, unsigned char *, size_t),
				   void *p_rng);

int ttls_mpi_init(void);
void ttls_mpi_exit(void);

#endif /* bignum.h */
