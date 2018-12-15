/*
 *		Tempesta TLS
 *
 * Debugging routines.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#if defined(DEBUG) && (DEBUG == 3)

#include "debug.h"

#define DEBUG_BUF_SIZE	  1024
/* Maximum number of item send for PK debugging, plus 1 */
#define TTLS_PK_DEBUG_MAX_ITEMS		3

void
ttls_debug_print_mpi(const ttls_context *ssl, const char *file, int line,
		     const char *text, const ttls_mpi *X)
{
	char str[DEBUG_BUF_SIZE];
	int j, k, zeros = 1;
	size_t i, n, idx = 0;
	unsigned int x;

	BUG_ON(!ssl->conf || !X);

	for (n = X->n - 1; n > 0; n--)
		if (X->p[n])
			break;

	for (j = (sizeof(ttls_mpi_uint) << 3) - 1; j >= 0; j--)
		if ((X->p[n] >> j) & 1)
			break;

	snprintf(str + idx, sizeof(str) - idx, "value of '%s' (%d bits) is:\n",
		 text, (int)((n * (sizeof(ttls_mpi_uint) << 3)) + j + 1));
	T_DBG3("%s", str);

	idx = 0;
	for (i = n + 1, j = 0; i > 0; i--) {
		if (zeros && !X->p[i - 1])
			continue;

		for (k = sizeof(ttls_mpi_uint) - 1; k >= 0; k--) {
			if (zeros && !((X->p[i - 1] >> (k << 3)) & 0xFF))
				continue;
			zeros = 0;

			if (!(j % 16) && j > 0) {
				snprintf(str + idx, sizeof(str) - idx, "\n");
				T_DBG3("%s", str);
				idx = 0;
			}

			x = (unsigned int)(X->p[i - 1] >> (k << 3)) & 0xFF;
			idx += snprintf(str + idx, sizeof(str) - idx, " %02x",
					x);
			j++;
		}

	}

	if (zeros == 1)
		idx += snprintf(str + idx, sizeof(str) - idx, " 00");
	snprintf(str + idx, sizeof(str) - idx, "\n");
	T_DBG3("%s", str);
}

void
ttls_debug_print_ecp(const ttls_context *ssl, const char *file, int line,
		     const char *text, const ttls_ecp_point *X)
{
	char str[DEBUG_BUF_SIZE];

	BUG_ON(!ssl->conf);

	snprintf(str, sizeof(str), "%s(X)", text);
	ttls_debug_print_mpi(ssl, file, line, str, &X->X);

	snprintf(str, sizeof(str), "%s(Y)", text);
	ttls_debug_print_mpi(ssl, file, line, str, &X->Y);
}

static void
debug_print_pk(const ttls_context *ssl, const char *file, int line,
	       const char *text, const ttls_pk_context *pk)
{
	size_t i;
	ttls_pk_debug_item items[TTLS_PK_DEBUG_MAX_ITEMS];
	char name[16];

	memset(items, 0, sizeof(items));

	if (ttls_pk_debug(pk, items)) {
		T_DBG3("%s", "invalid PK context\n");
		return;
	}

	for (i = 0; i < TTLS_PK_DEBUG_MAX_ITEMS; i++) {
		if (items[i].type == TTLS_PK_DEBUG_NONE)
			return;

		snprintf(name, sizeof(name), "%s%s", text, items[i].name);
		name[sizeof(name) - 1] = '\0';

		if (items[i].type == TTLS_PK_DEBUG_MPI) {
			ttls_debug_print_mpi(ssl, file, line, name,
					     items[i].value);
		}
		else if (items[i].type == TTLS_PK_DEBUG_ECP) {
			ttls_debug_print_ecp(ssl, file, line, name,
					     items[i].value);
		}
		else {
			T_WARN("should not happen\n");
		}
	}
}

static void
debug_print_line_by_line(const ttls_context *ssl, const char *file, int line,
			 const char *text)
{
	char str[DEBUG_BUF_SIZE];
	const char *start, *cur;

	start = text;
	for (cur = text; *cur != '\0'; cur++) {
		if (*cur == '\n') {
			size_t len = cur - start + 1;
			if (len > DEBUG_BUF_SIZE - 1)
				len = DEBUG_BUF_SIZE - 1;

			memcpy(str, start, len);
			str[len] = '\0';
			T_DBG3("%s", str);
			start = cur + 1;
		}
	}
}

void
ttls_debug_print_crt(const ttls_context *ssl, const char *file, int line,
		     const char *text, const ttls_x509_crt *crt)
{
	char buf[DEBUG_BUF_SIZE];
	int i = 0;

	BUG_ON(!ssl->conf || !crt);

	while (crt) {
		snprintf(buf, sizeof(buf), "%s #%d:\n", text, ++i);
		T_DBG3("%s", buf);

		ttls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
		debug_print_line_by_line(ssl, file, line, buf);

		debug_print_pk(ssl, file, line, "crt->", &crt->pk);

		crt = crt->next;
	}
}

#endif
