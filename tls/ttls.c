/**
 *		Tempesta TLS
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
#include "ssl_internal.h"

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta TLS");
MODULE_VERSION("0.2.0");
MODULE_LICENSE("GPL");

static int __init
ttls_init(void)
{
	/* Bad configuration - protected record payload too large. */
	BUILD_BUG_ON(TTLS_PAYLOAD_LEN > 16384 + 2048);

	return ttls_mpi_modinit();
}

static void
ttls_exit(void)
{
	ttls_mpi_modexit();
}

module_init(ttls_init);
module_exit(ttls_exit);

/*
 * ------------------------------------------------------------------------
 *	pulic API interface (feel free to add more symbols here)
 * ------------------------------------------------------------------------
 */
EXPORT_SYMBOL(ttls_pk_init);
EXPORT_SYMBOL(ttls_pk_free);
EXPORT_SYMBOL(ttls_pk_parse_key);

EXPORT_SYMBOL(ttls_ssl_init);
EXPORT_SYMBOL(ttls_ssl_free);
EXPORT_SYMBOL(ttls_ssl_setup);
EXPORT_SYMBOL(ttls_ssl_set_bio);

EXPORT_SYMBOL(ttls_ssl_config_init);
EXPORT_SYMBOL(ttls_ssl_config_free);
EXPORT_SYMBOL(ttls_ssl_config_defaults);
EXPORT_SYMBOL(ttls_ssl_conf_rng);
EXPORT_SYMBOL(ttls_ssl_conf_dbg);
EXPORT_SYMBOL(ttls_ssl_conf_own_cert);
EXPORT_SYMBOL(ttls_ssl_conf_ca_chain);

EXPORT_SYMBOL(ttls_x509_crt_init);
EXPORT_SYMBOL(ttls_x509_crt_free);
EXPORT_SYMBOL(ttls_x509_crt_parse);

EXPORT_SYMBOL(ttls_debug_set_threshold);
