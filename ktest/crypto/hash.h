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
#ifndef __CRYPTO_HASH_H__
#define __CRYPTO_HASH_H__

#include "linux/kernel.h"
#include "linux/atomic.h"

#define CRYPTO_MAX_ALG_NAME	128

struct crypto_shash { /* dummy strut */ };
struct shash_desc { /* dummy strut */ };
struct crypto_tfm { /* dummy strut */ };
struct crypto_type { /* dummy strut */ };
struct ablkcipher_alg { /* dummy strut */ };
struct blkcipher_alg { /* dummy strut */ };
struct cipher_alg { /* dummy strut */ };
struct compress_alg { /* dummy strut */ };

struct crypto_alg {
	struct list_head cra_list;
	struct list_head cra_users;

	u32 cra_flags;
	unsigned int cra_blocksize;
	unsigned int cra_ctxsize;
	unsigned int cra_alignmask;

	int cra_priority;
	atomic_t cra_refcnt;

	char cra_name[CRYPTO_MAX_ALG_NAME];
	char cra_driver_name[CRYPTO_MAX_ALG_NAME];

	const struct crypto_type *cra_type;

	union {
		struct ablkcipher_alg ablkcipher;
		struct blkcipher_alg blkcipher;
		struct cipher_alg cipher;
		struct compress_alg compress;
	} cra_u;

	int (*cra_init)(struct crypto_tfm *tfm);
	void (*cra_exit)(struct crypto_tfm *tfm);
	void (*cra_destroy)(struct crypto_alg *alg);
	
	struct module *cra_module;
} CRYPTO_MINALIGN_ATTR;

struct shash_alg {
	int (*init)(struct shash_desc *desc);
	int (*update)(struct shash_desc *desc, const u8 *data,
		      unsigned int len);
	int (*final)(struct shash_desc *desc, u8 *out);
	int (*finup)(struct shash_desc *desc, const u8 *data,
		     unsigned int len, u8 *out);
	int (*digest)(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out);
	int (*export)(struct shash_desc *desc, void *out);
	int (*import)(struct shash_desc *desc, const void *in);
	int (*setkey)(struct crypto_shash *tfm, const u8 *key,
		      unsigned int keylen);

	unsigned int descsize;

	/* These fields must match hash_alg_common. */
	unsigned int digestsize CRYPTO_MINALIGN_ATTR;
	unsigned int statesize;

	struct crypto_alg base;
};

static inline struct shash_alg *__crypto_shash_alg(struct crypto_alg *alg)
{
	return container_of(alg, struct shash_alg, base);
}

#endif /* __CRYPTO_HASH_H__ */
