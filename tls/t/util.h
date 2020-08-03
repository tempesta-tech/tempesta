/**
 *		Tempesta TLS common utils for the tests
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TTLS_UTILS_H__
#define __TTLS_UTILS_H__

#define ERROR_ON(file, line, expr)					\
do {									\
	if (expr) {							\
		fprintf(stderr, "Assertion on %s:%d %s\n", file, line, #expr); \
		BUG();							\
	}								\
} while (0)

/**
 * Test assertion that MPI @m uses @n limbs and the limbs are equal to
 * unsigned long values passed as the variadic list or arguments.
 */
static inline void
__expect_mpi(const char *file, int line, const TlsMpi *m, unsigned short n, ...)
{
	int i;
	va_list args;

	ERROR_ON(file, line, n > m->limbs);

	va_start(args, n);
	for (i = 0; i < n; i++) {
		unsigned long l = va_arg(args, unsigned long);
		ERROR_ON(file, line, MPI_P(m)[i] != l);
	}
	va_end(args);
}

#define EXPECT_MPI(m, n, ...)						\
	__expect_mpi(__FILE__, __LINE__, m, n, __VA_ARGS__)

#endif /* __TTLS_UTILS_H__ */
