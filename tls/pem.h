/*
 *		Tempesta TLS
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
#include <linux/types.h>

#ifndef TTLS_PEM_H
#define TTLS_PEM_H

/**
 * PEM Error codes
 * These error codes are returned in case of errors reading the PEM data.
 */
/* No PEM header or footer found. */
#define TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT		-0x1080
/* PEM string is not as expected. */
#define TTLS_ERR_PEM_INVALID_DATA			-0x1100
/* Failed to allocate memory. */
#define TTLS_ERR_PEM_ALLOC_FAILED			-0x1180
/* RSA IV is not in hex-format. */
#define TTLS_ERR_PEM_INVALID_ENC_IV			-0x1200
/* Unsupported key encryption algorithm. */
#define TTLS_ERR_PEM_UNKNOWN_ENC_ALG			-0x1280
/* Private key password can't be empty. */
#define TTLS_ERR_PEM_PASSWORD_REQUIRED			-0x1300
/* Given private key password does not allow for correct decryption. */
#define TTLS_ERR_PEM_PASSWORD_MISMATCH			-0x1380
/* Unavailable feature, e.g. hashing/encryption combination. */
#define TTLS_ERR_PEM_FEATURE_UNAVAILABLE		-0x1400
/* Output buffer too small. */
#define TTLS_ERR_BASE64_BUFFER_TOO_SMALL		-0x002A
/* Invalid character in input. */
#define TTLS_ERR_BASE64_INVALID_CHARACTER		-0x002C

int ttls_pem_read_buffer(const char *header, const char *footer,
			 unsigned char *data, size_t *use_len);

#endif /* pem.h */
