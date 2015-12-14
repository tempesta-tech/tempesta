/*
 *  SSL server demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "../../ttls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "../../ttls/platform.h"
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||    \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||     \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||    \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_PEM_PARSE_C)
static int __init
tfw_ssl_srv_init(void)
{
    pr_info("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
           "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
           "MBEDTLS_PEM_PARSE_C not defined.\n");
    return 0;
}
#else

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "../../ttls/entropy.h"
#include "../../ttls/ctr_drbg.h"
#include "../../ttls/certs.h"
#include "../../ttls/x509.h"
#include "../../ttls/ssl.h"
#include "../../ttls/net.h"
#include "../../ttls/error.h"
#include "../../ttls/debug.h"
#include "../../ttls/certs.c"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "../../ttls/ssl_cache.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

static int __init
tfw_ssl_srv_init(void)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /*
     * 1. Load the certificates and private RSA key
     */
    pr_info("\n  . Loading the server cert. and key...");

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse(&srvcert,
                                 (const unsigned char *)mbedtls_test_srv_crt,
                                 mbedtls_test_srv_crt_len);
    if (ret != 0) {
        pr_info(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&srvcert,
                                 (const unsigned char *)mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret != 0) {
        pr_info(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret =  mbedtls_pk_parse_key(&pkey,
                                (const unsigned char *)mbedtls_test_srv_key,
                                mbedtls_test_srv_key_len, NULL, 0);
    if (ret != 0) {
        pr_info(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    pr_info(" ok\n");

    /*
     * 2. Setup the listening TCP socket
     */
    pr_info("  . Bind on https://localhost:4433/ ...");

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433",
                                MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        pr_info(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    pr_info(" ok\n");

    /*
     * 3. Seed the RNG
     */
    pr_info("  . Seeding the random number generator...");

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        pr_info(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    pr_info(" ok\n");

    /*
     * 4. Setup stuff
     */
    pr_info("  . Setting up the SSL data....");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        pr_info(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        pr_info(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        pr_info(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    pr_info(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        pr_info("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    pr_info("  . Waiting for a remote connection ...");

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0) {
        pr_info(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    pr_info(" ok\n");

    /*
     * 5. Handshake
     */
    pr_info("  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            pr_info(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    pr_info(" ok\n");

    /*
     * 6. Read the HTTP Request
     */
    pr_info("  < Read from client:");

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0) {
            switch(ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    pr_info(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    pr_info(" connection was reset by peer\n");
                    break;

                default:
                    pr_info(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        pr_info(" %d bytes read\n\n%s", len, (char *) buf);

        if (ret > 0)
            break;
    }
    while (1);

    /*
     * 7. Write the 200 Response
     */
    pr_info("  > Write to client:");

    len = sprintf((char *) buf, HTTP_RESPONSE,
                   mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            pr_info(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            pr_info(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    pr_info(" %d bytes written\n\n%s\n", len, (char *) buf);

    pr_info("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            pr_info(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    pr_info(" ok\n");

    ret = 0;
    goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        pr_info("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_PEM_PARSE_C */

static void
tfw_ssl_srv_exit(void)
{
}

module_init(tfw_ssl_srv_init);
module_exit(tfw_ssl_srv_exit);
