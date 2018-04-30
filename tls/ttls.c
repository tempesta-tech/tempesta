/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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
#include <linux/module.h>

#include "ttls.h"

/**
 * TODO: analyze all the calls to @calloc and @free over the whole code and
 * carefully change all of them to appropriate kernel routines (probably SLAB
 * allocations can be used) or exclude at all (if the optimization is possible.
 */
void *ttls_calloc(size_t n, size_t size)
{
	return kzalloc(n * size, GFP_ATOMIC);
}
EXPORT_SYMBOL(ttls_calloc);

void ttls_free(void *ptr)
{
	kfree(ptr);
}
EXPORT_SYMBOL(ttls_free);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
int rand(void)
{
	return get_random_int();
}
#endif

/**
 * Threading support (locking)
 */

static void
ttls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	spin_lock_init(mutex);
}

static void
ttls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
}

static int
ttls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	spin_lock(mutex);
	return 0;
}

static int
ttls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	spin_unlock(mutex);
	return 0;
}

#define DO_SELF_TEST(f)							\
do {									\
	int r;								\
	if ((r = f(0 /* use 1 for verbose */))) {			\
		pr_err("TTLS: '" __stringify(f) "' failed (%x)\n", -r);	\
		return -EINVAL;						\
	}								\
} while (0)

static int
ttls_self_test(void)
{
	DO_SELF_TEST(mbedtls_mpi_self_test);
	DO_SELF_TEST(mbedtls_ecp_self_test);
	DO_SELF_TEST(mbedtls_md5_self_test);
	DO_SELF_TEST(mbedtls_aes_self_test);
	DO_SELF_TEST(mbedtls_rsa_self_test);
	DO_SELF_TEST(mbedtls_sha1_self_test);
	DO_SELF_TEST(mbedtls_sha256_self_test);
	DO_SELF_TEST(mbedtls_x509_self_test);

	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

static int __init
ttls_init(void)
{
	/* Should preceed @ttls_self_test call */
	mbedtls_threading_set_alt(ttls_mutex_init,
				  ttls_mutex_free,
				  ttls_mutex_lock,
				  ttls_mutex_unlock);

	if (ttls_self_test())
		return -EINVAL;

	return 0;
}

static void
ttls_exit(void)
{
	mbedtls_threading_free_alt();
}

module_init(ttls_init);
module_exit(ttls_exit);

MODULE_AUTHOR("Tempesta Technologies");
MODULE_VERSION("2.3.0");
MODULE_LICENSE("GPL v2");

/*
 * ------------------------------------------------------------------------
 *	pulic API interface (feel free to add more symbols here)
 * ------------------------------------------------------------------------
 */

/*
 * Bignum (multi-precision integers) support
 */

#if defined(MBEDTLS_BIGNUM_C)
EXPORT_SYMBOL(mbedtls_mpi_copy);
EXPORT_SYMBOL(mbedtls_mpi_free);
EXPORT_SYMBOL(mbedtls_mpi_read_string);
EXPORT_SYMBOL(mbedtls_mpi_size);
#endif

/*
 * Elliptic curves
 */

#if defined(MBEDTLS_ECP_C)
EXPORT_SYMBOL(mbedtls_ecp_curve_info_from_tls_id);
EXPORT_SYMBOL(mbedtls_ecp_group_load);
EXPORT_SYMBOL(mbedtls_ecp_grp_id_list);
#endif

/*
 * Hashing (message digest) algorithms
 */

#if defined(MBEDTLS_MD_C)
EXPORT_SYMBOL(mbedtls_md_init);
EXPORT_SYMBOL(mbedtls_md_get_size);
EXPORT_SYMBOL(mbedtls_md_info_from_type);
EXPORT_SYMBOL(mbedtls_md_clone);
EXPORT_SYMBOL(mbedtls_md_setup);
EXPORT_SYMBOL(mbedtls_md_process);
EXPORT_SYMBOL(mbedtls_md_update);
EXPORT_SYMBOL(mbedtls_md_starts);
EXPORT_SYMBOL(mbedtls_md_finish);
EXPORT_SYMBOL(mbedtls_md_hmac_update);
EXPORT_SYMBOL(mbedtls_md_hmac_starts);
EXPORT_SYMBOL(mbedtls_md_hmac_finish);
EXPORT_SYMBOL(mbedtls_md_hmac_reset);
EXPORT_SYMBOL(mbedtls_md_free);
#endif

#if defined(MBEDTLS_MD5_C)
EXPORT_SYMBOL(mbedtls_md5_init);
EXPORT_SYMBOL(mbedtls_md5_clone);
EXPORT_SYMBOL(mbedtls_md5_update);
EXPORT_SYMBOL(mbedtls_md5_starts);
EXPORT_SYMBOL(mbedtls_md5_finish);
EXPORT_SYMBOL(mbedtls_md5_free);
#endif

#if defined(MBEDTLS_SHA1_C)
EXPORT_SYMBOL(mbedtls_sha1_init);
EXPORT_SYMBOL(mbedtls_sha1_clone);
EXPORT_SYMBOL(mbedtls_sha1_update);
EXPORT_SYMBOL(mbedtls_sha1_starts);
EXPORT_SYMBOL(mbedtls_sha1_finish);
EXPORT_SYMBOL(mbedtls_sha1_free);
#endif

#if defined(MBEDTLS_SHA256_C)
EXPORT_SYMBOL(mbedtls_sha256_init);
EXPORT_SYMBOL(mbedtls_sha256_clone);
EXPORT_SYMBOL(mbedtls_sha256_update);
EXPORT_SYMBOL(mbedtls_sha256_starts);
EXPORT_SYMBOL(mbedtls_sha256_finish);
EXPORT_SYMBOL(mbedtls_sha256_free);
#endif

#if defined(MBEDTLS_SHA512_C)
EXPORT_SYMBOL(mbedtls_sha512_init);
EXPORT_SYMBOL(mbedtls_sha512_clone);
EXPORT_SYMBOL(mbedtls_sha512_update);
EXPORT_SYMBOL(mbedtls_sha512_starts);
EXPORT_SYMBOL(mbedtls_sha512_finish);
EXPORT_SYMBOL(mbedtls_sha512_free);
#endif

/*
 * Ciphers
 */

#if defined(MBEDTLS_CIPHER_C)
EXPORT_SYMBOL(mbedtls_cipher_auth_decrypt);
EXPORT_SYMBOL(mbedtls_cipher_auth_encrypt);
EXPORT_SYMBOL(mbedtls_cipher_crypt);
EXPORT_SYMBOL(mbedtls_cipher_free);
EXPORT_SYMBOL(mbedtls_cipher_info_from_type);
EXPORT_SYMBOL(mbedtls_cipher_init);
EXPORT_SYMBOL(mbedtls_cipher_setkey);
EXPORT_SYMBOL(mbedtls_cipher_set_padding_mode);
EXPORT_SYMBOL(mbedtls_cipher_setup);
#endif

/*
 * Public key abstraction layer
 */

#if defined(MBEDTLS_PK_C)
EXPORT_SYMBOL(mbedtls_pk_init);
EXPORT_SYMBOL(mbedtls_pk_can_do);
EXPORT_SYMBOL(mbedtls_pk_decrypt);
EXPORT_SYMBOL(mbedtls_pk_get_bitlen);
EXPORT_SYMBOL(mbedtls_pk_parse_key);
EXPORT_SYMBOL(mbedtls_pk_sign);
EXPORT_SYMBOL(mbedtls_pk_verify);
EXPORT_SYMBOL(mbedtls_pk_free);
#endif

/*
 * Diffie-Hellman
 */

#if defined(MBEDTLS_DHM_C)
EXPORT_SYMBOL(mbedtls_dhm_calc_secret);
EXPORT_SYMBOL(mbedtls_dhm_free);
EXPORT_SYMBOL(mbedtls_dhm_init);
EXPORT_SYMBOL(mbedtls_dhm_make_params);
EXPORT_SYMBOL(mbedtls_dhm_read_public);
#endif

#if defined(MBEDTLS_ECDH_C)
EXPORT_SYMBOL(mbedtls_ecdh_calc_secret);
EXPORT_SYMBOL(mbedtls_ecdh_free);
EXPORT_SYMBOL(mbedtls_ecdh_get_params);
EXPORT_SYMBOL(mbedtls_ecdh_init);
EXPORT_SYMBOL(mbedtls_ecdh_make_params);
EXPORT_SYMBOL(mbedtls_ecdh_read_public);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
EXPORT_SYMBOL(mbedtls_x509_crt_init);
EXPORT_SYMBOL(mbedtls_x509_crt_free);
EXPORT_SYMBOL(mbedtls_x509_crt_parse);
EXPORT_SYMBOL(mbedtls_x509_crt_parse_der);
EXPORT_SYMBOL(mbedtls_x509_crt_profile_suiteb);
EXPORT_SYMBOL(mbedtls_x509_crt_profile_default);
EXPORT_SYMBOL(mbedtls_x509_crt_verify_with_profile);
#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
EXPORT_SYMBOL(mbedtls_x509_crt_check_key_usage);
#endif
#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
EXPORT_SYMBOL(mbedtls_x509_crt_check_extended_key_usage);
#endif
#endif

/*
 * Debugging
 */

#if defined(MBEDTLS_DEBUG_C)
EXPORT_SYMBOL(mbedtls_debug_print_buf);
EXPORT_SYMBOL(mbedtls_debug_print_crt);
EXPORT_SYMBOL(mbedtls_debug_print_ecp);
EXPORT_SYMBOL(mbedtls_debug_print_mpi);
EXPORT_SYMBOL(mbedtls_debug_print_msg);
EXPORT_SYMBOL(mbedtls_debug_print_ret);
EXPORT_SYMBOL(mbedtls_debug_set_threshold);
#endif

/*
 * Uncategorized
 */

EXPORT_SYMBOL(mbedtls_ssl_list_ciphersuites);
EXPORT_SYMBOL(mbedtls_ssl_ciphersuite_uses_ec);
EXPORT_SYMBOL(mbedtls_ssl_ciphersuite_uses_psk);
EXPORT_SYMBOL(mbedtls_ssl_get_ciphersuite_name);
EXPORT_SYMBOL(mbedtls_ssl_get_ciphersuite_sig_pk_alg);
EXPORT_SYMBOL(mbedtls_ssl_ciphersuite_from_id);
