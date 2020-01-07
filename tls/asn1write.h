/**
 *		Tempesta TLS
 *
 * ASN.1 buffer writing functionality.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#ifndef TTLS_ASN1_WRITE_H
#define TTLS_ASN1_WRITE_H

#include "asn1.h"

#define TTLS_ASN1_CHK_ADD(g, f)						\
do {									\
	if ((ret = f) < 0)						\
		return ret;						\
	else								\
		g += ret;						\
} while (0)

int ttls_asn1_write_len(unsigned char **p, unsigned char *start, size_t len);
int ttls_asn1_write_tag(unsigned char **p, unsigned char *start,
			unsigned char tag);
int ttls_asn1_write_mpi(unsigned char **p, unsigned char *start, const TlsMpi *X);

#endif /* TTLS_ASN1_WRITE_H */
