/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) implementation.
 *
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
#include <mbedtls/certs.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#include "connection.h"
#include "tls.h"
#include "http_msg.h"

static mbedtls_ssl_config tfw_tls_conf;
static mbedtls_x509_crt tfw_tls_srvcert;
static mbedtls_pk_context tfw_tls_pkey;

/**
 * TODO do all crypto and handle TLS FSM here.
 *
 * Decrypted response messages should be directly placed in TDB area
 * to avoid copying.
 */
static int
tfw_tls_msg_process(void *conn, struct sk_buff *skb, unsigned int off)
{
	int r;
	TfwConnection *c = (TfwConnection *)conn;
	TfwTlsContext *tls = c->tls;

	ss_skb_queue_tail(&tls->rx_queue, skb);

	r = mbedtls_ssl_handshake(&c->tls->ctx);
	if (r == MBEDTLS_ERR_SSL_CONN_EOF) {
		return TFW_PASS;
	} else if (r == 0) {
		struct sk_buff *nskb = alloc_skb(MAX_TCP_HEADER + 1024, GFP_ATOMIC);

		if (unlikely(!nskb))
			return TFW_BLOCK;

		skb_reserve(nskb, MAX_TCP_HEADER);
		skb_put(nskb, 1024);

		r = mbedtls_ssl_read(&tls->ctx, nskb->data, 1024);

		printk("mbedtls_ssl_read() r = %d\n", r);
		if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
			kfree_skb(nskb);
			return TFW_PASS;
		} else if (r <= 0) {
			kfree_skb(nskb);
			return r ? TFW_BLOCK : TFW_PASS;
		}
		printk("mbedtls_ssl_read() r = %d [%.*s]\n", r, r, nskb->data);

		skb_trim(nskb, r);

		r = tfw_gfsm_move(&c->msg->state, TFW_HTTPS_FSM_TODO_ISSUE_81, nskb, 0);
		if (r == TFW_BLOCK)
			return TFW_BLOCK;

		return TFW_PASS;
	}

	return TFW_BLOCK;
}

static TfwMsg *
tfw_tls_conn_msg_alloc(TfwConnection *conn)
{
	TfwHttpMsg *hm;

	BUG_ON(TFW_CONN_TYPE(conn) & Conn_Srv);

	hm = tfw_http_msg_alloc(TFW_CONN_TYPE(conn));
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_connection_get(conn);
	tfw_gfsm_state_init(&hm->msg.state, conn, TFW_HTTPS_FSM_INIT);

	printk("%s hm = %p\n", __func__, hm);

	return (TfwMsg *)hm;
}

////////////////////////////////////////////////////////////////////////////////
// TODO:
//  - use ss_skb_alloc instead of alloc_skb
//

static int
tfw_tls_send(void *conn, const unsigned char *buf, size_t len)
{
	TfwConnection *c = (TfwConnection *)conn;
	TfwTlsContext *tls = c->tls;
	struct sk_buff *skb = alloc_skb(MAX_TCP_HEADER + len, GFP_ATOMIC);

	if (unlikely(!skb))
		return MBEDTLS_ERR_NET_SEND_FAILED;

	skb_reserve(skb, MAX_TCP_HEADER);
	skb_put(skb, len);

	if (unlikely(skb_store_bits(skb, 0, buf, len)))
		BUG();

	ss_skb_queue_tail(&tls->tx_queue, skb);
	ss_send(c->sk, &tls->tx_queue, SS_F_SYNC);

	printk("%s len = %lu\n", __func__, len);

	return len;
}

static int
tfw_tls_recv(void *conn, unsigned char *buf, size_t len)
{
	TfwConnection *c = (TfwConnection *)conn;
	TfwTlsContext *tls = c->tls;
	struct sk_buff *skb = ss_skb_peek_tail(&tls->rx_queue);

	if (unlikely(!skb))
		return 0;

	len = min_t(size_t, skb->len, len);
	if (unlikely(skb_copy_bits(skb, 0, buf, len)))
		BUG();

	pskb_pull(skb, len);

	if (unlikely(!skb->len)) {
		ss_skb_unlink(&tls->rx_queue, skb);
		kfree_skb(skb);
	}

	printk("%s len = %lu\n", __func__, len);

	return len;
}

////////////////////////////////////////////////////////////////////////////////

static int
tfw_tls_conn_init(TfwConnection *conn)
{
	int r;
	TfwTlsContext *tls;

	tls = kmalloc(sizeof(TfwTlsContext), GFP_ATOMIC);
	if (unlikely(!tls))
		return -ENOMEM;

	mbedtls_ssl_init(&tls->ctx);

	ss_skb_queue_head_init(&tls->rx_queue);
	ss_skb_queue_head_init(&tls->tx_queue);

	r = mbedtls_ssl_setup(&tls->ctx, &tfw_tls_conf);
	mbedtls_ssl_set_bio(&tls->ctx, conn, tfw_tls_send, tfw_tls_recv, NULL);

	if (r) {
		printk("mbedtls_ssl_setup() failed r = %d\n", r);
		return -EINVAL;
	}

	conn->tls = tls;

	printk("%s tls = %p\n", __func__, tls);

	return 0;
}

static void
tfw_tls_conn_drop(TfwConnection *conn)
{
	TfwTlsContext *tls = conn->tls;

	BUG_ON(!tls);

	printk("%s\n", __func__);

	mbedtls_ssl_free(&tls->ctx);
	kfree(tls);
	conn->tls = NULL;

	conn->msg = NULL;
}

static TfwConnHooks tls_conn_hooks = {
	.conn_init	= tfw_tls_conn_init,
	.conn_drop	= tfw_tls_conn_drop,
	.conn_msg_alloc	= tfw_tls_conn_msg_alloc,
};

static void my_dbg(void *ctx, int level, const char *file, int line, const char *str)
{
	if (level < 2) printk("<mbedtls> %s:%d -- %s\n", file, line, str);
}

#include <linux/random.h>

static int my_rnd(void *rnd, unsigned char *out, size_t len)
{
	get_random_bytes(out, len);
	return 0;
}

static int
mbedtls_init(void)
{
	int r;

	/* testing */

	mbedtls_mpi_self_test(1);

	/* initialization */

	mbedtls_ssl_config_init(&tfw_tls_conf);
	mbedtls_x509_crt_init(&tfw_tls_srvcert);
	mbedtls_pk_init(&tfw_tls_pkey);

	mbedtls_debug_set_threshold(128);

	mbedtls_ssl_conf_rng(&tfw_tls_conf, my_rnd, NULL);
	mbedtls_ssl_conf_dbg(&tfw_tls_conf, my_dbg, NULL);

	r = mbedtls_x509_crt_parse(&tfw_tls_srvcert, (const unsigned char *)mbedtls_test_srv_crt, mbedtls_test_srv_crt_len);
	if (r) {
		printk("mbedtls_x509_crt_parse() failed r = %d\n", r);
		return -EINVAL;
	}

	r = mbedtls_x509_crt_parse(&tfw_tls_srvcert, (const unsigned char *)mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);
	if (r) {
		printk("mbedtls_x509_crt_parse() failed r = %d\n", r);
		return -EINVAL;
	}

	r = mbedtls_ssl_config_defaults(&tfw_tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (r) {
		printk("mbedtls_ssl_config_defaults() failed r = %d\n", r);
		return -EINVAL;
	}

	r = mbedtls_pk_parse_key(&tfw_tls_pkey, (const unsigned char *)mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0);
	if (r) {
		printk("mbedtls_pk_parse_key() failed r = %d\n", r);
		return -EINVAL;
	}

	mbedtls_ssl_conf_ca_chain(&tfw_tls_conf, tfw_tls_srvcert.next, NULL);
	r = mbedtls_ssl_conf_own_cert(&tfw_tls_conf, &tfw_tls_srvcert, &tfw_tls_pkey);
	if (r) {
		printk("mbedtls_ssl_conf_own_cert() failed r = %d\n", r);
		return -EINVAL;
	}

	printk("%s() OK\n", __func__);

	return 0;
}

int __init
tfw_tls_init(void)
{
	int r = tfw_gfsm_register_fsm(TFW_FSM_HTTPS, tfw_tls_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_HTTPS);

	r = mbedtls_init();
	if (r)
		return r;

	return 0;
}

void
tfw_tls_exit(void)
{
	tfw_connection_hooks_unregister(TFW_FSM_HTTPS);
	tfw_gfsm_unregister_fsm(TFW_FSM_HTTPS);
}
