/*
 *		Tempesta TLS
 *
 * Debugging routines.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
 *
 * Based on mbed TLS, https://tls.mbed.org.
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
#include "debug.h"
#include "pk_internal.h"

#ifdef DEBUG

/**
 * Prints @msg for all debug layers.
 * Print argeuments on 3rd debug layer as list of @n pairs
 * <const char *name, const TlsMpi *X>.
 */
void
__log_mpis(size_t n, const char *msg, ...)
{
	T_DBG("%s\n", msg);
#if DEBUG == 3
	{
		va_list args;

		va_start(args, msg);
		while (n--)
			/* Put the args on the stack in reverse order. */
			ttls_mpi_dump(va_arg(args, const TlsMpi *),
				      va_arg(args, const char *));
		va_end(args);
	}
#endif
}

#if DEBUG == 3

#define DEBUG_BUF_SIZE	  1024
/* Maximum number of item send for PK debugging, plus 1 */
#define TTLS_PK_DEBUG_MAX_ITEMS		3

static void
__debug_print_pk(const char *file, int line, const char *msg,
		 const TlsPkCtx *pk)
{
	size_t i;
	ttls_pk_debug_item items[TTLS_PK_DEBUG_MAX_ITEMS];
	char name[16];

	BUG_ON(!pk || !pk->pk_info);
	BUG_ON(!pk->pk_info->debug_func);

	memset(items, 0, sizeof(items));

	pk->pk_info->debug_func(pk->pk_ctx, items);

	for (i = 0; i < TTLS_PK_DEBUG_MAX_ITEMS; i++) {
		if (items[i].type == TTLS_PK_DEBUG_NONE)
			return;

		snprintf(name, sizeof(name), "%s%s", msg, items[i].name);
		name[sizeof(name) - 1] = '\0';

		if (items[i].type == TTLS_PK_DEBUG_MPI) {
			ttls_mpi_dump(items[i].value, name);
		}
		else if (items[i].type == TTLS_PK_DEBUG_ECP) {
			T_DBG_ECP(name, (TlsEcpPoint *)items[i].value);
		}
		else {
			T_WARN("should not happen\n");
		}
	}
}

static void
__debug_print_line_by_line(const char *file, int line, const char *msg)
{
	char str[DEBUG_BUF_SIZE];
	const char *start, *cur;

	start = msg;
	for (cur = msg; *cur != '\0'; cur++) {
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
ttls_debug_print_crt(const char *file, int line, const char *msg,
		     const ttls_x509_crt *crt)
{
	char buf[DEBUG_BUF_SIZE];
	int i = 0;

	while (crt) {
		snprintf(buf, sizeof(buf), "%s #%d:\n", msg, ++i);
		T_DBG3("%s", buf);

		ttls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
		__debug_print_line_by_line(file, line, buf);

		__debug_print_pk(file, line, "crt->", &crt->pk);

		crt = crt->next;
	}
}

#endif
#endif
