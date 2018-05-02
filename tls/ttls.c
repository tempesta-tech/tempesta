/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <asm/fpu/api.h>
#include <linux/module.h>

#include "ttls.h"

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta TLS");
MODULE_VERSION("2.8.0");
MODULE_LICENSE("GPL");

/**
 * TODO: analyze all the calls to @calloc and @free over the whole code and
 * carefully change all of them to appropriate kernel routines (probably SLAB
 * allocations can be used) or exclude at all (if the optimization is possible.
 */
void *calloc(size_t n, size_t size)
{
	return kzalloc(n * size, GFP_ATOMIC);
}

void free(void *ptr)
{
	kfree(ptr);
}

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
int rand(void)
{
	return get_random_int();
}
#endif

// TODO move the stuff to unit tests.
#define DO_SELF_TEST(f)							\
do {									\
	if ((r = f(1 /* use 1 for verbose */))) {			\
		pr_err("TTLS: '" __stringify(f) "' failed (%x)\n", -r);	\
		goto err;						\
	}								\
} while (0)

static int
ttls_self_test(void)
{
	int r = -EINVAL;

	kernel_fpu_begin();

	// TODO call all the *_self_test()'s
	DO_SELF_TEST(mbedtls_mpi_self_test);
	DO_SELF_TEST(mbedtls_ecp_self_test);
	DO_SELF_TEST(mbedtls_md5_self_test);
	DO_SELF_TEST(mbedtls_aes_self_test);
	DO_SELF_TEST(mbedtls_rsa_self_test);
	DO_SELF_TEST(mbedtls_sha1_self_test);
	DO_SELF_TEST(mbedtls_sha256_self_test);
	DO_SELF_TEST(mbedtls_x509_self_test);

	r = 0;
err:
	kernel_fpu_end();

	return r;
}

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

static int __init
ttls_init(void)
{
	if (ttls_self_test())
		return -EINVAL;

	return 0;
}

static void
ttls_exit(void)
{
}

module_init(ttls_init);
module_exit(ttls_exit);

/*
 * ------------------------------------------------------------------------
 *	pulic API interface (feel free to add more symbols here)
 * ------------------------------------------------------------------------
 */
EXPORT_SYMBOL(mbedtls_pk_init);
EXPORT_SYMBOL(mbedtls_pk_free);
EXPORT_SYMBOL(mbedtls_pk_parse_key);

EXPORT_SYMBOL(mbedtls_ssl_init);
EXPORT_SYMBOL(mbedtls_ssl_free);
EXPORT_SYMBOL(mbedtls_ssl_setup);
EXPORT_SYMBOL(mbedtls_ssl_set_bio);
EXPORT_SYMBOL(mbedtls_ssl_read);
EXPORT_SYMBOL(mbedtls_ssl_write);
EXPORT_SYMBOL(mbedtls_ssl_handshake);
EXPORT_SYMBOL(mbedtls_ssl_close_notify);

EXPORT_SYMBOL(mbedtls_ssl_config_init);
EXPORT_SYMBOL(mbedtls_ssl_config_free);
EXPORT_SYMBOL(mbedtls_ssl_config_defaults);
EXPORT_SYMBOL(mbedtls_ssl_conf_rng);
EXPORT_SYMBOL(mbedtls_ssl_conf_dbg);
EXPORT_SYMBOL(mbedtls_ssl_conf_own_cert);
EXPORT_SYMBOL(mbedtls_ssl_conf_ca_chain);

EXPORT_SYMBOL(mbedtls_x509_crt_init);
EXPORT_SYMBOL(mbedtls_x509_crt_free);
EXPORT_SYMBOL(mbedtls_x509_crt_parse);

EXPORT_SYMBOL(mbedtls_debug_set_threshold);
