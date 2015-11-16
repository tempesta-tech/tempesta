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

#include "../../gfsm.h"
#include "../../http.h"
#include "helpers.h"
#include "test.h"

#ifdef module_init
#undef module_init
#undef module_exit
#define module_init(funk)
#define module_exit(funk)
#endif

#include "../../classifier/frang.c"

#define FRANG_HASH_BITS 17
#define FRANG_FREQ	8
#define HANDLER_OFF	0

struct inet_sock mocksock;
const char *inet_addr = "192.168.245.128";

static int
mock_http_req_handler(void *obj, struct sk_buff *skb, unsigned int off)
{
	return TFW_PASS;
}

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
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET /home/index.html HTTP /1.1\r\n\r\n");
	mockreq->frang_st = 3;

	frang_cfg.http_uri_len = 5;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, req_count)
{
	int i;
	unsigned long ts;
	TfwHttpReq *mockreq;
	mockreq = get_test_req("GET / HTTP/1.1\r\n\r\n");
	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;

	((FrangAcc*)mocksock.sk.sk_security)->history[i].req = 5;
	mockreq->frang_st = 0;

	/*req_rate*/
	frang_cfg.conn_max = 0;
	frang_cfg.conn_burst = 0;
	frang_cfg.conn_rate = 0;
	frang_cfg.req_rate = 5;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	/*req_burst*/	
	mockreq->frang_st = 0;

	frang_cfg.req_rate = 0;
	frang_cfg.req_burst = 5;
	((FrangAcc*)mocksock.sk.sk_security)->history[i].req = 5;
	
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, conn_count)
{
	int i;
	TfwHttpReq *mockreq;
	unsigned long ts;

	/*conn_max*/
	((FrangAcc*)mocksock.sk.sk_security)->conn_curr = 5;
	mockreq = get_test_req("GET / HTTP/1.1\r\n\r\n");

	frang_cfg.conn_max = 5;
	
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	/*conn_rate*/
	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;
	frang_cfg.conn_max = 0;
	frang_cfg.conn_rate = 5;
	((FrangAcc*)mocksock.sk.sk_security)->history[i].conn_new = 5;
	
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

/*conn_burst*/
	frang_cfg.conn_max = 0;
	frang_cfg.conn_rate = 0;
	frang_cfg.conn_burst = 5;

	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));
	test_req_free(mockreq);
}

TEST(frang, ct_check)
{
	TfwHttpReq *mockreq;
	FrangCtVal ctval[1];

	mockreq = get_test_req("POST /foo HTTP/1.1\r\nContent-Type:text/html;\r\n\r\n");
	mockreq->frang_st = 0;
	/*ct_vals*/
	ctval[0].str = "application/html";
	ctval[0].len = strlen(ctval[0].str);
	frang_cfg.http_ct_vals = ctval;
	
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));
	test_req_free(mockreq);

	/*ct_required*/
	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	mockreq->frang_st = 0;

	frang_cfg.http_ct_required = true;
	
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));
	test_req_free(mockreq);
}

TEST(frang, req_method)
{
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");

	frang_cfg.http_methods_mask = 2;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, field_len)
{
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");

	frang_cfg.http_field_len = 3;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, host)
{
	TfwHttpReq *mockreq;

	mockreq = get_test_req("GET /foo HTTP/1.1\r\n\r\n");

	frang_cfg.http_host_required = true;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}


TEST(frang, body_len)
{
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
	mockreq->frang_st =0;

	frang_cfg.http_body_len = 3;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, body_timeout)
{
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	mockreq->frang_st = 12;
	mockreq->tm_bchunk = jiffies - 100;
	
	frang_cfg.clnt_body_timeout = 1;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, hdr_timeout)
{
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");
	mockreq->frang_st = 0;
	mockreq->tm_header = jiffies - 100;

	frang_cfg.clnt_body_timeout = 0;
	frang_cfg.clnt_hdr_timeout = 1;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST(frang, chunk_cnt)
{
	TfwHttpReq *mockreq;

	mockreq = get_test_req("POST /foo HTTP/1.1\r\n\r\n");

	/*header chunk*/
	frang_cfg.http_hchunk_cnt = 1;
	mockreq->chunk_cnt = 3;
	mockreq->frang_st = 0;

	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	/*body chunks*/
	frang_cfg.http_hchunk_cnt = 0;
	frang_cfg.http_bchunk_cnt = 1;
	mockreq->chunk_cnt = 3;
	EXPECT_EQ(TFW_BLOCK, req_handler(mockreq));

	test_req_free(mockreq);
}

TEST_SUITE(frang)
{	
	/* The initial FSM state isn't hookable. */
	tfw_gfsm_register_fsm(TFW_FSM_HTTP, mock_http_req_handler);
	frang_init();
	
	/* A new frang account for tests */ 
	mocksock.inet_saddr = htonl(in_aton(inet_addr));
	frang_conn_new((struct sock*)&mocksock);

	TEST_RUN(frang, uri);
	TEST_RUN(frang, req_count);
	TEST_RUN(frang, conn_count);
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
