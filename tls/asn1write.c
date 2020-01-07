/**
 *		Tempesta TLS
 *
 * ASN.1 buffer writing functionality
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
#include <linux/slab.h>

#include "asn1write.h"

/**
 * Write a length field in ASN.1 format.
 * Note: function works backwards in data buffer.
 *
 * @p		- reference to current position pointer;
 * @start	- start of the buffer (for bounds-checking);
 * @len		- the length to write.
 *
 * @return the length written or a negative error code.
 */
int
ttls_asn1_write_len(unsigned char **p, unsigned char *start, size_t len)
{
	if (len < 0x80) {
		if (*p - start < 1)
			return -ENOSPC;
		*--(*p) = (unsigned char) len;
		return 1;
	}

	if (len <= 0xFF) {
		if (*p - start < 2)
			return -ENOSPC;

		*--(*p) = (unsigned char) len;
		*--(*p) = 0x81;
		return 2;
	}

	if (len <= 0xFFFF) {
		if (*p - start < 3)
			return -ENOSPC;

		*--(*p) = len & 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = 0x82;
		return 3;
	}

	if (len <= 0xFFFFFF) {
		if (*p - start < 4)
			return -ENOSPC;

		*--(*p) = len & 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = (len >> 16) & 0xFF;
		*--(*p) = 0x83;
		return 4;
	}

	if (len <= 0xFFFFFFFF) {
		if (*p - start < 5)
			return -ENOSPC;

		*--(*p) = len & 0xFF;
		*--(*p) = (len >>  8) & 0xFF;
		*--(*p) = (len >> 16) & 0xFF;
		*--(*p) = (len >> 24) & 0xFF;
		*--(*p) = 0x84;
		return 5;
	}

	return -EINVAL;
}

/**
 * Write a ASN.1 tag in ASN.1 format.
 * Note: function works backwards in data buffer
 *
 * @p		- reference to current position pointer;
 * @start	- start of the buffer (for bounds-checking);
 * @tag		- the tag to write.
 *
 * @return the length written or a negative error code.
 */
int
ttls_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
	if (*p - start < 1)
		return -ENOSPC;

	*--(*p) = tag;

	return 1;
}

/**
 * Write a big number (TTLS_ASN1_INTEGER) in ASN.1 format.
 * Note: function works backwards in data buffer
 *
 * @p		- reference to current position pointer;
 * @start	- start of the buffer (for bounds-checking);
 * @X		- the MPI to write.
 *
 * @return the length written or a negative error code.
 */
int
ttls_asn1_write_mpi(unsigned char **p, unsigned char *start, const TlsMpi *X)
{
	int ret;
	size_t len = ttls_mpi_size(X);

	if (*p < start || (size_t)(*p - start) < len)
		return -ENOSPC;

	(*p) -= len;
	TTLS_MPI_CHK(ttls_mpi_write_binary(X, *p, len));

	/*
	 * DER format assumes 2s complement for numbers, so the leftmost bit
	 * should be 0 for positive numbers and 1 for negative numbers.
	 */
	if (X->s ==1 && **p & 0x80) {
		if (*p - start < 1)
			return -ENOSPC;

		*--(*p) = 0x00;
		len += 1;
	}

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(p, start, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(p, start, TTLS_ASN1_INTEGER));

	ret = (int)len;

cleanup:
	return ret;
}
