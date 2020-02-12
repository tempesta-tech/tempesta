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
		   unsigned long *b, size_t b_len,
		   unsigned long *a, size_t a_len);

void mpi_sub_x86_64(unsigned long *x, unsigned long *b, unsigned long *a,
		    size_t b_len, size_t a_len);

#endif /* __BIGNUM_ASM_H__ */

