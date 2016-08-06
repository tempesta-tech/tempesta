#include <linux/module.h>

#include "ttls.h"

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

MODULE_LICENSE("GPLv2");

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
