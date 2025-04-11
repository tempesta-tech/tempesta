/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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
#ifndef __CRYPTO_SHA_H__
#define __CRYPTO_SHA_H__

#include "linux/compiler.h"

#define SHA512_DIGEST_SIZE	64
#define SHA512_BLOCK_SIZE	128

#define SHA256_DIGEST_SIZE	32
#define SHA256_BLOCK_SIZE	64

struct sha512_state {
	u64 state[SHA512_DIGEST_SIZE / 8];
	u64 count[2];
	u8 buf[SHA512_BLOCK_SIZE];
};

struct sha256_state {
	u32 state[SHA256_DIGEST_SIZE / 4];
	u64 count[2];
	u8 buf[SHA256_BLOCK_SIZE];
};

#endif /* __CRYPTO_SHA_H__ */
