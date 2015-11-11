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

#include <linux/inet.h>
#include <linux/module.h>
#include "../../gfsm.h"
#ifdef module_init
#undef module_init
#undef module_exit
#define module_init(funk)
#define module_exit(funk)
#endif
#include <linux/export.h>
#include "../../classifier/frang.c"
#include "helpers.h"
#include "kallsyms_helper.h"
#include "test.h"

#define FRANG_HASH_BITS 17
#define FRANG_FREQ	8
#define HANDLER_OFF	0

struct inet_sock mocksock;
const char *inet_addr = "192.168.245.128";

static TfwConnection *
test_conn_alloc(void)
{
	TfwConnection *conn;
	static struct kmem_cache *test_conn_cache = NULL;

	if(test_conn_cache == NULL)
		test_conn_cache = kmem_cache_create(
					"tfw_test_conn_cache",
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
	conn->sk = (struct sock*)&mocksock;
	mocksock.inet_daddr = htonl(in_aton(inet_addr));

	if (!conn->sk->sk_security) 
		frang_conn_new(conn->sk);

	return frang_http_req_handler((void *) conn, 
				 	       conn->msg->skb_list.first, 
					       HANDLER_OFF);
}

static TfwHttpReq *
get_test_req(const char *req)
{
	TfwHttpReq *test_req;
	static char req_str_copy[PAGE_SIZE]; 
	int len = strlen(req);

	BUG_ON(len == 0);
	BUG_ON(len + 1 > sizeof(req_str_copy));
	strcpy(req_str_copy, req);
	test_req = test_req_alloc(len);
	tfw_http_parse_req(test_req, req_str_copy, len);
	return test_req;
}

TEST(frang, uri)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET /home/index.html HTTP /1.1\r\n\r\n");
	frang_cfg.http_uri_len = 5;
	mockreq->frang_st = 3;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, req_count)
{
	int res;
	int i;
	unsigned long ts;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET / HTTP/1.1\r\n\r\n");
	frang_cfg.conn_max = 0;
	frang_cfg.conn_burst = 0;
	frang_cfg.conn_rate = 0;
	frang_cfg.req_rate = 5;
	mocksock.inet_saddr = htonl(in_aton(inet_addr));

	res = frang_conn_new((struct sock*)&mocksock);
	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;
	((FrangAcc*)mocksock.sk.sk_security)->history[i].req = 5;
	mockreq->frang_st = 0;

	res = req_handler (mockreq);
	EXPECT_EQ(TFW_BLOCK, res);

	frang_cfg.req_rate = 5;
	frang_cfg.req_burst = 5;
	((FrangAcc*)mocksock.sk.sk_security)->history[i].req = 5;
	mockreq->frang_st = 0;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, max_conn)
{
	int res;
	int i;
	TfwHttpReq *mockreq;
	unsigned long ts;

	mockreq = get_test_req("GET / HTTP/1.1\r\n\r\n");
	frang_cfg.conn_max = 5;

	mocksock.inet_saddr = htonl(in_aton(inet_addr));
	if(!mocksock.sk.sk_security)
		frang_conn_new((struct sock *)&mocksock);
	((FrangAcc*)mocksock.sk.sk_security)->conn_curr = 5;

	res = req_handler(mockreq);
	/*conn_max*/
	EXPECT_EQ(TFW_BLOCK, res);

	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;
	frang_cfg.conn_max = 0;
	frang_cfg.conn_rate = 5;
	((FrangAcc*)mocksock.sk.sk_security)->history[i].conn_new = 5;

	res = req_handler(mockreq);
	/*conn_rate */
	EXPECT_EQ(TFW_BLOCK, res);

	frang_cfg.conn_max = 0;
	frang_cfg.conn_rate = 0;
	frang_cfg.conn_burst = 5;
((FrangAcc*)mocksock.sk.sk_security)->history[i].conn_new = 5;

	res = req_handler(mockreq);
	/*conn_burst*/
	EXPECT_EQ(TFW_BLOCK, res);

	test_req_free(mockreq);
}


TEST(frang, ct_check)
{
	int res;
	TfwHttpReq *mockreq;
	FrangCtVal ctval[1];

	mockreq = get_test_req("POST /foo HTTP/1.1\r\nContent-Type:text/html;\r\n\r\n");
	ctval[0].str = "application/html";
	ctval[0].len = strlen(ctval[0].str);
	frang_cfg.http_ct_vals = ctval;
	mockreq->frang_st = 0;

	res = req_handler(mockreq);
	/*ct_vals*/
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	frang_cfg.http_ct_required = true;
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

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	frang_cfg.http_methods_mask = 2;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, field_len)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	frang_cfg.http_field_len = 3;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, host)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET /foo HTTP/1.1\r\n\r\n");
	frang_cfg.http_host_required = true;

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

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	body.ptr = "<http><body></body></http>";
	body.len = strlen(body.ptr);
	crlf.len = 2;
	crlf.ptr = "\r\n";
	mockreq->crlf = crlf;
	mockreq->body = body;
	frang_cfg.http_body_len = 3;
	mockreq->frang_st = 0;

	res = req_handler(mockreq);
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST(frang, body_timeout)
{
	int res;
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	frang_cfg.clnt_body_timeout = 1;
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

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	frang_cfg.clnt_body_timeout = 0;
	frang_cfg.clnt_hdr_timeout = 1;
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

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	frang_cfg.http_hchunk_cnt = 1;
	mockreq->chunk_cnt = 3;
	mockreq->frang_st = 0;

	res = req_handler (mockreq);
	/*header chunk*/
	EXPECT_EQ(TFW_BLOCK, res);

	frang_cfg.http_hchunk_cnt = 0;
	frang_cfg.http_bchunk_cnt = 1;
	mockreq->chunk_cnt = 3;

	res = req_handler (mockreq);
	/*body chunks*/
	EXPECT_EQ(TFW_BLOCK, res);
	test_req_free(mockreq);
}

TEST_SUITE(frang)
{
	tfw_gfsm_register_fsm(TFW_FSM_HTTP,frang_http_req_handler);
	frang_init();

	TEST_RUN(frang, uri);
	TEST_RUN(frang, req_count);
	TEST_RUN(frang, max_conn);
	TEST_RUN(frang, ct_check);
	TEST_RUN(frang, req_method);
	TEST_RUN(frang, field_len);
	TEST_RUN(frang, host);
	TEST_RUN(frang, body_len);
	TEST_RUN(frang, body_timeout);
	TEST_RUN(frang, hdr_timeout);
	TEST_RUN(frang, chunk_cnt);

	frang_exit();
}
