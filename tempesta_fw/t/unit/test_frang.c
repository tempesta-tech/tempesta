/**
 *  		Tempesta FW
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
 *
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * his program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <linux/socket.h>

#include "../../classifier.h"
#include "../../client.h"
#include "../../connection.h"
#include "../../sync_socket.h"
#include "../../gfsm.h"
#include "../../http_msg.h"
#include "../../log.h"
#include "../../lib.h"
#include "../../tempesta_fw.h"

#include "addr.h"
#include "cfg.h"
#include "helpers.h"
#include "kallsyms_helper.h"
#include "sched_helper.h"
#include "test.h"

#define FRANG_HASH_BITS 17
#define FRANG_FREQ	8

typedef struct {
	unsigned long	ts;
	unsigned int	conn_new;
	unsigned int	req;
} FrangRates;

typedef struct frang_account_t {
	struct hlist_node hentry;
	struct in6_addr addr;		/* client address */
	unsigned long last_ts;	/* last access time */
	unsigned int conn_curr;	/* current connections number */
	FrangRates history[FRANG_FREQ];
} FrangAcc;

typedef struct {
	char *str;
	size_t len;			/* The pre-computed strlen(@str). */
} FrangCtVal;

typedef struct {
	/* Limits (zero means unlimited). */
	unsigned int req_rate;
	unsigned int req_burst;
	unsigned int conn_rate;
	unsigned int conn_burst;
	unsigned int conn_max;
	/*
	Limits on time it takes to receive
	 a full header or a body chunk.
	*/
	unsigned long clnt_hdr_timeout;
	unsigned long clnt_body_timeout;
	/* Limits for HTTP request contents: uri, headers, body, etc. */
	unsigned int http_uri_len;
	unsigned int http_field_len;
	unsigned int http_body_len;
	unsigned int http_hchunk_cnt;
	unsigned int http_bchunk_cnt;
	bool http_ct_required;
	bool http_host_required;
	/* The bitmask of allowed HTTP Method values. */
	unsigned long http_methods_mask;
	/* The list of allowed Content-Type values. */
	FrangCtVal *http_ct_vals;
} FrangCfg;

FrangCfg *frang_cfg;
const int (*frang_conn_new) (struct sock *);
int (*frang_http_req_handler)(void *obj,struct sk_buff *skb, 
			      unsigned int off);

struct inet_sock *isk;
struct sock mocksock;

const char *inet_addr = "192.168.245.128";

static TfwConnection *
test_conn_alloc(void)
{
	TfwConnection *conn;
	static struct kmem_cache *test_conn_cache = NULL;
	if(!test_conn_cache)
		test_conn_cache = kmem_cache_create("tfw_test_conn_cache",
				        sizeof(TfwConnection), 0, 0, NULL);
	BUG_ON(test_conn_cache == NULL);
	conn = kmem_cache_alloc(test_conn_cache, GFP_ATOMIC);
	BUG_ON(!conn);
	tfw_connection_init(conn);
	return conn;
}

static int
req_handler(TfwHttpReq  *req)
{
	TfwConnection *conn;

	conn = test_conn_alloc();
	conn->msg = &req->msg;
	conn->sk = &mocksock;
	isk = (struct inet_sock *) (&mocksock);
	isk->inet_saddr = htonl(in_aton(inet_addr));
	if (!conn->sk->sk_security) {
		frang_conn_new(conn->sk);
	}

	return frang_http_req_handler((void *) conn,
					       req->msg.skb_list.first, 25);
}

static TfwHttpReq *
get_test_req(unsigned char *req)
{
	TfwHttpReq *test_req;
	int len = strlen(req);
	BUG_ON(len == 0);
	test_req = test_req_alloc(len);
	tfw_http_parse_req(test_req, req, len);
	return test_req;
}

TEST(frang, max_conn)
{
	int res;
	int i;
	TfwHttpReq *mockreq;
	FrangAcc *ra;
	unsigned long ts;

	mockreq = get_test_req("GET / HTTP/1.1\r\n");
	frang_cfg->conn_max = 5;
	isk = (struct inet_sock *) (&mocksock);
	isk->inet_saddr = htonl(in_aton(inet_addr));
	res = frang_conn_new(&mocksock);
	ra = mocksock.sk_security;
	ra->conn_curr = 5;
	mocksock.sk_security = ra;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;
	frang_cfg->conn_max = 0;
	frang_cfg->conn_rate = 5;
	ra->history[i].conn_new = 5;
	mocksock.sk_security = ra;
	res = req_handler(mockreq);
	/*conn_rate */
	EXPECT_EQ(TFW_BLOCK, res);
	frang_cfg->conn_max = 0;
	frang_cfg->conn_rate = 0;
	frang_cfg->conn_burst = 5;
	ra->history[i].conn_new = 5;
	mocksock.sk_security = ra;

	res = req_handler (mockreq);
	/*conn_max */
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, uri)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET /home/index.html HTTP /1.1\r\n");
	frang_cfg->http_uri_len = 5;
	mockreq->frang_st = 3;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, ct_check)
{
	int res;
	TfwHttpReq *mockreq;
	FrangCtVal ctval[1];

	mockreq = get_test_req("POST /foo HTTP/1.1\r\nContent-Type:text/html;");;
	ctval[0].str = "application/html";
	ctval[0].len = strlen(ctval[0].str);
	frang_cfg->http_ct_vals = ctval;
	mockreq->frang_st = 0;

	res = req_handler(mockreq);
	/*ct_vals*/
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	frang_cfg->http_ct_required = true;
	mockreq->frang_st = 0;

	res = req_handler(mockreq);
	/*ct_required*/
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, req_method)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	frang_cfg->http_methods_mask = 2;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, field_len)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	frang_cfg->http_field_len = 3;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, host)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET /foo HTTP/1.1\r\n");
	frang_cfg->http_host_required = true;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, req_count)
{
	int res;
	int i;
	TfwConnection mockconn;
	unsigned long ts;
	TfwHttpReq *mockreq;
	FrangAcc *ra;

	mockreq = get_test_req("GET / HTTP/1.1\r\n");
	frang_cfg->conn_max = 0;
	frang_cfg->conn_burst = 0;
	frang_cfg->conn_rate = 0;
	frang_cfg->req_rate = 5;
	isk = (struct inet_sock *) (&mocksock);
	isk->inet_saddr = htonl(in_aton(inet_addr));
	mockconn.sk = &mocksock;

	res = frang_conn_new(&mocksock);
	ra = mockconn.sk->sk_security;
	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;
	ra->history[i].req = 5;
	mocksock.sk_security = ra;
	mockreq->frang_st = 0;
	res = req_handler (mockreq);
	EXPECT_EQ(TFW_BLOCK, res);

	frang_cfg->req_rate = 5;
	frang_cfg->req_burst = 5;
	ra->history[i].req = 5;
	mocksock.sk_security = ra;
	mockreq->frang_st = 0;
	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, body_len)
{
	int res;
	TfwHttpReq *mockreq;
	TfwStr body;
	TfwStr crlf;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	body.ptr = "GET http://natsys-lab.com/foo";
	body.len = strlen(body.ptr);
	crlf.len = 2;
	crlf.ptr = "\r\n";
	mockreq->crlf = crlf;
	mockreq->body.len = 29;
	frang_cfg->http_body_len = 3;
	mockreq->frang_st = 0;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, body_timeout)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	frang_cfg->clnt_body_timeout = 1;
	mockreq->frang_st = 12;
	mockreq->tm_bchunk = jiffies - 100;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, hdr_timeout)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	frang_cfg->clnt_body_timeout = 0;
	frang_cfg->clnt_hdr_timeout = 1;
	mockreq->frang_st = 0;
	mockreq->tm_header = jiffies - 100;

	res = req_handler (mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, chunk_cnt)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n");
	frang_cfg->http_hchunk_cnt = 1;
	mockreq->chunk_cnt = 3;
	mockreq->frang_st = 0;

	res = req_handler (mockreq);
	/*header chunk*/
	EXPECT_EQ(TFW_BLOCK, res);

	frang_cfg->http_hchunk_cnt = 0;
	frang_cfg->http_bchunk_cnt = 1;
	mockreq->chunk_cnt = 3;

	res = req_handler (mockreq);
	/*body chunks*/
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST_SUITE(frang)
{
	frang_cfg = (FrangCfg *) get_sym_ptr("frang_cfg");
	frang_conn_new = get_sym_ptr("frang_conn_new");
	frang_http_req_handler = get_sym_ptr("frang_http_req_handler");

	BUG_ON(frang_http_req_handler == NULL);
	BUG_ON(frang_conn_new == NULL);
	BUG_ON(frang_cfg == NULL);

	TEST_RUN(frang, req_count);
	TEST_RUN(frang, max_conn);
	TEST_RUN(frang, uri);
	TEST_RUN(frang, body_len);
	TEST_RUN(frang, ct_check);
	TEST_RUN(frang, field_len);
	TEST_RUN(frang, host);
	TEST_RUN(frang, req_method);
	TEST_RUN(frang, chunk_cnt);
	TEST_RUN(frang, body_timeout);
	TEST_RUN(frang, hdr_timeout);
}
