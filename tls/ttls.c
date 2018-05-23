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

static int __init
ttls_init(void)
{
	return ttls_mpi_init();
}

static void
ttls_exit(void)
{
	ttls_mpi_exit();
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
