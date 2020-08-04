/*
 *		Tempesta TLS
 *
 * Declarations for big integer assembly routines.
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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
#ifndef __BIGNUM_ASM_H__
#define __BIGNUM_ASM_H__

int mpi_add_x86_64(unsigned long *x, size_t x_len,
		   const unsigned long *b, size_t b_len,
		   const unsigned long *a, size_t a_len);

void mpi_sub_x86_64_5_4(unsigned long *x, const unsigned long *b,
			const unsigned long *a);
void mpi_sub_x86_64_4_4(unsigned long *x, const unsigned long *b,
			const unsigned long *a);
void mpi_sub_x86_64_3_3(unsigned long *x, const unsigned long *b,
			const unsigned long *a);
void mpi_sub_x86_64_2_2(unsigned long *x, const unsigned long *b,
			const unsigned long *a);
void mpi_sub_x86_64(unsigned long *x, const unsigned long *b,
		    const unsigned long *a, size_t b_len, size_t a_len);
void mpi_sub_mod_p256_x86_64_4(unsigned long *x, const unsigned long *a,
			       const unsigned long *b);

void mpi_shift_l_x86_64_4(unsigned long *x, const unsigned long *a,
			  unsigned long bits);
void mpi_shift_l_x86_64(unsigned long *x, const unsigned long *a, size_t x_len,
			unsigned long bits);

void mpi_shift_r_x86_64_4(unsigned long *x, unsigned long bits);
void mpi_shift_r_x86_64(unsigned long *x, size_t x_len, unsigned long bits);

void mpi_div2_x86_64_4(unsigned long *x, const unsigned long *a);

void mpi_tpl_x86_64_4(unsigned long *x, const unsigned long *a);

void mpi_mul_x86_64_4(unsigned long *x, const unsigned long *a,
		      const unsigned long *b);
void mpi_sqr_x86_64_4(unsigned long *x, const unsigned long *a);

void mpi_mul_mod_p256_x86_64_4(unsigned long *x, const unsigned long *a,
			       const unsigned long *b);
void mpi_sqr_mod_p256_x86_64_4(unsigned long *x, const unsigned long *a);

void ecp_mod_p256_x86_64(unsigned long *x);

#endif /* __BIGNUM_ASM_H__ */

