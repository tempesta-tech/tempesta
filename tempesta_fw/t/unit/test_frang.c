/**
 *  		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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

#include "test.h"
#include "sched_helper.h"
#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include "../../tempesta_fw.h"
#include "../../lib.h"
#include "../../log.h"
#include "../../msg.h"
#include "../../http.h"
#include "cfg.h"
#include "../../gfsm.h"
#include "../../client.h"
#include "../../connection.h"
#include "test.h"
#include "kallsyms_helper.h"

#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/ipv6.h>

#include "../../addr.h"
#include "../../classifier.h"
#include "../../sync_socket.h"
#include "../../client.h"
#include "../../connection.h"
#include "../../gfsm.h"
#include "../../http_msg.h"
#include "../../log.h"
#include "../../lib.h"
#include "../../tempesta_fw.h"

#include "addr.h"
#include "helpers.h"

#define FRANG_HASH_BITS 17

#define FRANG_FREQ 8
typedef struct
{
  unsigned long ts;
  unsigned int conn_new;
  unsigned int req;
} FrangRates;

typedef struct frang_account_t
{
  struct hlist_node hentry;
  struct in6_addr addr;		/* client address */
  unsigned long last_ts;	/* last access time */
  unsigned int conn_curr;	/* current connections number */
  FrangRates history[FRANG_FREQ];
} FrangAcc;

const int (*frang_conn_new) (struct sock *);
struct sock mockSock;
struct inet_sock *isk;
int res;

const char *inet_addr = "192.168.168.245.128";
unsigned short i = 0;
typedef struct
{
  char *str;
  size_t len;			/* The pre-computed strlen(@str). */
} FrangCtVal;
typedef struct
{
  /* Limits (zero means unlimited). */
  unsigned int req_rate;
  unsigned int req_burst;
  unsigned int conn_rate;
  unsigned int conn_burst;
  unsigned int conn_max;

  /*
   * Limits on time it takes to receive
   * a full header or a body chunk.
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
struct inet_sock *isk;
static int (*frang_http_req_handler) (void *obj,
				      struct sk_buff * skb, unsigned int off);
static struct kmem_cache *tfw_test_conn_cache;

TfwConnection *
test_conn_alloc (void)
{
	TfwConnection *conn;

	if (!tfw_test_conn_cache)
	{
		tfw_test_conn_cache =	
		kmem_cache_create ("tfw_test_conn_cache", 
				   sizeof (TfwConnection), 0,0, NULL);
    	}
	conn = kmem_cache_alloc (tfw_test_conn_cache, GFP_ATOMIC);
  	if (!conn)
		return NULL;

	tfw_connection_init (conn);
	return conn;
}


int
req_handler (TfwHttpReq * req)
{
	TfwConnection *conn;

	conn = test_conn_alloc ();
	conn->msg = &req->msg;
	if (!conn)
	{
      		TFW_DBG ("req_handler: conn is null\n");
    	}
	conn->sk = &mockSock;
	isk = (struct inet_sock *) (&mockSock);
	isk->inet_saddr = htonl (in_aton (inet_addr));
	if (!conn->sk->sk_security)
    	{
      		frang_conn_new = get_sym_ptr ("frang_conn_new");
 		res = frang_conn_new (conn->sk);
    }



  	frang_http_req_handler = get_sym_ptr ("frang_http_req_handler");
	if (!frang_http_req_handler_ptr)
    	{
      		FW_DBG ("frang_req_handleris null str:%d\n", 392);
    	}
	return frang_http_req_handler ((void *) conn, 
					req->msg.skb_list.first, 25);
}

TEST(frang, max_conn)
{
  	TfwHttpReq *mockReq;
	FrangAcc *ra;
	unsigned long ts;
	mockReq = test_req_alloc (17);
	tfw_http_parse_req(mockReq, "GET / HTTP/1.1\r\n", 16);
  	if (!frang_cfg)
	{
		frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
	}
	frang_cfg->conn_max = 5;
  	isk = (struct inet_sock *) (&mockSock);
	isk->inet_saddr = htonl (in_aton (inet_addr));

	frang_conn_new = get_sym_ptr ("frang_conn_new");
	if (!frang_conn_new)
	{
		TFW_DBG ("max_conn:%s\n", "conn_new ptr is null");
	}
	res = frang_conn_new (&mockSock);
	ra = mockSock.sk_security;



  	isk = (struct inet_sock *) (&mockSock);
	isk->inet_saddr = in_aton (inet_addr);
	ra->conn_curr = 5;
	mockSock.sk_security = ra;
	res = req_handler (mockReq);
	EXPECT_EQ (TFW_BLOCK, res);
	ts = jiffies * FRANG_FREQ / HZ;
	i = ts % FRANG_FREQ;
	frang_cfg->conn_max = 0;
	frang_cfg->conn_rate = 5;
	ra->history[i].conn_new = 5;
	mockSock.sk_security = ra;
	res = req_handler (mockReq);
	/*conn_rate */
	EXPECT_EQ (TFW_BLOCK, res);
	frang_cfg->conn_max = 0;
	frang_cfg->conn_rate = 0;
frang_cfg->conn_burst = 5;
	ra->history[i].conn_new = 5;
	mockSock.sk_security = ra;
	res = req_handler (mockReq);
	/*conn_max */
	EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, uri)
{
	TfwHttpReq *mockReq;
	TfwStr uri;
	mockReq = test_req_alloc (26);
	tfw_http_parse_req(mockReq, "GET /index.html HTTP /1.1", 25);
	if (!frang_cfg)
	{
		frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
	}

	frang_cfg->http_uri_len = 5;

	uri.len = 17;
	uri.ptr = (void *) "/home/index.html";
	uri.flags = TFW_STR_COMPLETE;
	mockReq->uri_path = uri;
	mockReq->frang_st = 3;
	res = req_handler (mockReq);
	EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, ct_check)
{
  TfwHttpReq *mockReq;
  FrangCtVal ctval[1];

  mockReq = test_req_alloc (22);
  tfw_http_parse_req (mockReq, "POST /foo HTTP/1.1\r\n", 20);
  TFW_DBG ("ct_check:%s;%lu\n", "after parse req req:",
	   (unsigned long) mockReq);
  if (!frang_cfg)
    {
      rang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }
  ctval[0].len = 17;
  ctval[0].str = "application/html";
  frang_cfg->http_ct_required = true;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);

  mockReq->frang_st = 9;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, req_method)
{
  TfwHttpReq *mockReq;
  mockReq = test_req_alloc (17);
  tfw_http_parse_req (mockReq, "PUT /index.html", 16);
  if (!frang_cfg)
    {
      frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }

  frang_cfg->http_methods_mask = 2;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, field_len)
{
  TfwHttpReq *mockReq;
  mockReq = test_req_alloc (20);
  tfw_http_parse_req (mockReq, "GET /foo HTTP/1.1\r\n", 19);

  if (!frang_cfg)
    {
      frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }
  frang_cfg->http_field_len = 3;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, host)
{
  TfwHttpReq *mockReq;
  mockReq = test_req_alloc (7);
  tfw_http_parse_req (mockReq, "GET /foo HTTP/1.1\r\n", 19);

  if (!frang_cfg)
    {
      frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }
  frang_cfg->http_host_required = true;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

static int (*frang_req_limit_ptr) (FrangAcc * ra, struct sock * sk);
TEST (frang, req_count)
{
  TfwConnection mockConn;
  unsigned long ts;
  TfwHttpReq *mockReq;
  FrangAcc *ra;
  mockReq = test_req_alloc (17);
  tfw_http_parse_req (mockReq, "GET / HTTP/1.1\r\n", 16);
  if (!frang_cfg)
    {
      frang_cfg = get_sym_ptr ("frang_cfg");
    }
  frang_req_limit_ptr = get_sym_ptr ("frang_req_limit");
  if (!frang_req_limit_ptr)
    {
      TFW_DBG ("req_count:%s;\n", "req_limit ptr is null");
    }
  frang_cfg->conn_max = 0;
  frang_cfg->conn_burst = 0;
  frang_cfg->conn_rate = 0;
  frang_cfg->req_rate = 5;
  isk = (struct inet_sock *) (&mockSock);
  isk->inet_saddr = htonl (in_aton (inet_addr));

  mockConn.sk = &mockSock;

  frang_conn_new = get_sym_ptr ("frang_conn_new");
  res = frang_conn_new (&mockSock);
  ra = mockConn.sk->sk_security;

  ts = jiffies * FRANG_FREQ / HZ;
  i = ts % FRANG_FREQ;
  ra->history[i].req = 5;
  if (!frang_conn_new)
    {
      TFW_DBG ("frang_req_count507:%s\n", "conn_new ptr is null");
    }
  mockSock.sk_security = ra;
  mockReq->frang_st = 0;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
  frang_cfg->req_rate = 5;
  frang_cfg->req_burst = 5;
  ra->history[i].req = 5;
  TFW_DBG ("frang_req_count 517:%s\n", "conn_new ptr is null");

  mockSock.sk_security = ra;
  mockReq->frang_st = 0;

  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, body_len)
{
  TfwHttpReq *mockReq;
  TfwStr body;
  TfwStr crlf;
  mockReq = test_req_alloc (22);

  tfw_http_parse_req (mockReq, "POST /foo HTTP/1.1\r\n", 20);

  body.ptr = "GET http://natsys-lab.com/foo";
  body.len = 29;
  crlf.len = 2;
  crlf.ptr = "\r\n";

  mockReq->crlf = crlf;

  mockReq->body.len = 29;
  if (!frang_cfg)
    {
      frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }


  frang_cfg->http_body_len = 3;
  mockReq->frang_st = 0;

  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, body_timeout)
{
  TfwHttpReq *mockReq;
  mockReq = test_req_alloc (62);
  tfw_http_parse_req (mockReq, "POST http://natsys-lab.com/foo HTTP/1.1\r\n \
Content-Length:29\r\n", 61);
  if (!frang_cfg)
    {
      frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }

  frang_cfg->clnt_body_timeout = 1;
  mockReq->frang_st = 12;
  mockReq->tm_bchunk = jiffies - 100;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, hdr_timeout)
{
  TfwHttpReq *mockReq;
  mockReq = test_req_alloc (62);
  tfw_http_parse_req (mockReq, "POST http://natsys-lab.com/foo HTTP/1.1\r\n \
Content-Length:29\r\n", 61);
  if (!frang_cfg)
    {
      rang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }

  frang_cfg->clnt_body_timeout = 0;
  frang_cfg->clnt_hdr_timeout = 1;
  mockReq->frang_st = 0;
  mockReq->tm_header = jiffies - 100;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST (frang, chunk_cnt)
{
  TfwHttpReq *mockReq;
  mockReq = test_req_alloc (62);
  tfw_http_parse_req (mockReq, "POST http://natsys-lab.com/foo HTTP/1.1\r\n \
Content-Length:29\r\n", 61);
  if (!frang_cfg)
    {
      frang_cfg = (FrangCfg *) get_sym_ptr ("frang_cfg");
    }
  frang_cfg->http_hchunk_cnt = 1;
  mockReq->chunk_cnt = 3;
  mockReq->frang_st = 0;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
  frang_cfg->http_hchunk_cnt = 0;
  frang_cfg->http_bchunk_cnt = 1;
  mockReq->chunk_cnt = 3;
  res = req_handler (mockReq);
  EXPECT_EQ (TFW_BLOCK, res);
}

TEST_SUITE (frang)
{
  TEST_RUN (frang, req_count);
  TEST_RUN (frang, max_conn);
  TEST_RUN (frang, uri);
  TEST_RUN (frang, body_len);
  TEST_RUN (frang, ct_check);
  TEST_RUN (frang, field_len);
  TEST_RUN (frang, host);
  TEST_RUN (frang, req_method);
  TEST_RUN (frang, chunk_cnt);
  TEST_RUN (frang, body_timeout);
  TEST_RUN (frang, hdr_timeout);
}
