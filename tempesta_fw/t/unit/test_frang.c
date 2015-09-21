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
//#include "/usr/include/arpa/inet.h"
#include <linux/socket.h>
//#include <arpa/inet.h>
#include <linux/slab.h>
//#include <netinet/in.h>
#include "../../tempesta_fw.h"
#include "../../lib.h"
#include "../../log.h"
#include "../../msg.h"
#include "../../http.h"
#include "cfg.h"
#include "../../gfsm.h"
#include "../../client.h"
#include "../../connection.h"
//#ifdef module_init
//#undef module_init
//#endif

//#ifndef _INCLUDE_FRANG_CODE
//#define _INCLUDE_FRANG_CODE
//#include <linux/module.h> 
//#include "../../classifier/frang.c"
//#endif
//#undef module_init
#include "test.h"
#include "kallsyms_helper.h"

#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/ipv6.h>

#include "../../addr.h"
#include "../../classifier.h"
#include "../../client.h"
#include "../../connection.h"
#include "../../gfsm.h"
#include "../../http_msg.h"
#include "../../log.h"
#include "../../lib.h"
#include "../../tempesta_fw.h"

#include "addr.h"
#include "helpers.h"
#define TFW_GFSM_FRANG_STATE(s)	((TFW_FSM_FRANG << \
TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* Run the FSM for each HTTP request chunk. */
	TFW_FRANG_FSM_INIT	= TFW_GFSM_FRANG_STATE(0),
	/* Run the FSM for fully read HTTP request. */
	TFW_FRANG_FSM_MSG	= TFW_GFSM_FRANG_STATE(1),
	TFW_FRANG_FSM_DONE	= TFW_GFSM_FRANG_STATE(TFW_GFSM_STATE_LAST)
};

enum {
	/* TODO Enter FSM with this state for each HTTP request chunk. */
	__Frang_Chunk_0,

	Frang_Req_0 = __Frang_Chunk_0,

	Frang_Req_Hdr_Start,
	Frang_Req_Hdr_Method,
	Frang_Req_Hdr_UriLen,
	Frang_Req_Hdr_FieldDup,
	Frang_Req_Hdr_FieldLenRaw,
	Frang_Req_Hdr_FieldLenSpecial,
	Frang_Req_Hdr_Crlf,
	Frang_Req_Hdr_Host,
	Frang_Req_Hdr_ContentType,

	Frang_Req_Hdr_NoState,

	/* TODO Enter FSM with this state when HTTP request if fully read. */
	__Frang_Msg_0,

	Frang_Req_Body_Start = __Frang_Msg_0,
	Frang_Req_Body_Timeout,
	Frang_Req_Body_ChunkCnt,
	Frang_Req_Body_Len,

	Frang_Req_Body_NoState,

	__Frang_LastState,

	Frang_Req_NothingToDo = __Frang_LastState,
};




//#include "classifier.h"
typedef struct {
	struct hlist_head	list;
	spinlock_t		lock;
} FrangHashBucket;
#define FRANG_HASH_BITS 17

	FrangHashBucket *frang_hash/*[1 << FRANG_HASH_BITS]*/;
#define FRANG_FREQ 8
typedef struct {
	unsigned long	ts;
	unsigned int	conn_new;
	unsigned int	req;
} FrangRates;

typedef struct frang_account_t {
	struct hlist_node	hentry;
	struct in6_addr		addr; /* client address */
	unsigned long		last_ts; /* last access time */
	unsigned int		conn_curr; /* current connections number */
	FrangRates		history[FRANG_FREQ];
} FrangAcc;
//extern void frang_get_ipv6addr(struct sock *sk,struct in6_addr *addr);
//extern void *get_sym_ptr(const char* name);
// void (*frang_get_ipv6addr_ptr)(struct sock *sk,struct in6_addr *addr);
#define FRANG_HASH_BITS 17
static void
get_ipv6addr(struct sock *sk, struct in6_addr *addr)
{
	struct inet_sock *isk = (struct inet_sock *)sk;
TFW_DBG("frang_getipv6:%s;%lu\n","isk from sk:",(unsigned long)isk);
#if IS_ENABLED(CONFIG_IPV6)
	if (isk->pinet6)
		memcpy(addr, &isk->pinet6->saddr, sizeof(*addr));
	else
#endif
	ipv6_addr_set_v4mapped(isk->inet_saddr, addr);
}



FrangAcc* get_frang_acc(struct sock *sk){
struct in6_addr addr;
FrangHashBucket *hb;
struct hlist_node *tmp;
FrangAcc *ra;
unsigned int key;
struct inet_sock *insk;
//frang_get_ipv6addr_ptr = get_sym_ptr("frang_get_ipv6addr");
insk = (struct inet_sock *)sk;

 
get_ipv6addr(sk,&addr);
TFW_DBG("frang_conn_get_acc:after addr %d",addr.s6_addr32[1]);

key = addr.s6_addr32[0] ^ addr.s6_addr32[1] ^ addr.s6_addr32[2] \
^ addr.s6_addr32[3];

TFW_DBG("frang_conn_get_acc:%s;%d\n","key",key);
frang_hash = (FrangHashBucket*)get_sym_ptr("frang_hash");
hb = &frang_hash[hash_min(key,FRANG_HASH_BITS)];
hlist_for_each_entry_safe(ra,tmp,&hb->list,hentry){
TFW_DBG("frang_conn_get_acc:%s;%d\n","in_list",ra->addr.s6_addr32[1]);

if(ipv6_addr_equal(&addr,&ra->addr))
break;
}
return ra;
}

const int (*frang_conn_new_ptr)(struct sock*);
	struct sock mockSock;
 	struct inet_sock *isk;
	int res;

 	TfwCfgMod frang_cfg_mod;
	
	
	#define FRANG_FREQ 8
	const char* inet_addr = "192.168.168.245.1";
unsigned short i = 0;
typedef struct {
	char   *str;
	size_t len;	/* The pre-computed strlen(@str). */
} FrangCtVal;
typedef struct {
	/* Limits (zero means unlimited). */
	unsigned int 	req_rate;
	unsigned int 	req_burst;
	unsigned int 	conn_rate;
	unsigned int 	conn_burst;
	unsigned int 	conn_max;

	/*
	 * Limits on time it takes to receive
	 * a full header or a body chunk.
	 */
	unsigned long	clnt_hdr_timeout;
	unsigned long	clnt_body_timeout;

	/* Limits for HTTP request contents: uri, headers, body, etc. */
	unsigned int 	http_uri_len;
	unsigned int 	http_field_len;
	unsigned int 	http_body_len;
	unsigned int	http_hchunk_cnt;
	unsigned int	http_bchunk_cnt;
	bool 		http_ct_required;
	bool 		http_host_required;
	/* The bitmask of allowed HTTP Method values. */
	unsigned long 	http_methods_mask;
	/* The list of allowed Content-Type values. */
	FrangCtVal	*http_ct_vals;
} FrangCfg;
FrangCfg *frang_cfg;
	struct inet_sock *isk;
static  int (*frang_conn_limit_ptr)(FrangAcc *ra, struct sock *sk);
//extern int frang_account_do(struct sock *sk, int *func(FrangAcc *ra,struct sock *sk));
extern TfwConnection* tfw_cli_conn_alloc(void);
static int (*frang_http_req_handler_ptr)(void *obj, 
		                         struct sk_buff *skb , 
					 unsigned int off);

int req_handler(TfwHttpReq *req)
{
TfwConnection *conn;

//conn =  (TfwConnection*)req->msg->conn;
//tfw_cli_conn_alloc_ptr = get_sym_ptr("tfw_cli_conn_alloc");
//if(!tfw_cli_conn_alloc_ptr){
//	TFW_DBG("req_handler: alloc is null\n");
 //}

conn = (TfwConnection*)tfw_cli_conn_alloc();
conn->msg = &req->msg;
if(!conn){
	TFW_DBG("req_handler: conn is null\n");

}

//tfw_http_conn_msg_alloc(conn);

//conn->msg = req->msg;

frang_http_req_handler_ptr = get_sym_ptr("frang_http_req_handler");
/*TFW_DBG("req_handler:%s;%lu\n","hand_ptr:",(unsigned long)frang_http_req_handler_ptr);*/
if(! frang_http_req_handler_ptr){
TFW_DBG("frang_req_handleris null str:%d\n",392); 
}
//if(&mockReq->msg == NULL  || &mockReq->msg.skb_list == NULL){
//TFW_DBG("frang_req_handleris null param:%d\n",404); 
//}
return frang_http_req_handler_ptr((void*)conn,req->msg.skb_list.first,25);
}

TEST(frang, max_conn){
FrangAcc *ra;
unsigned long ts;
//unsigned long ts;
frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");	 
frang_cfg->conn_max =5;
isk = (struct inet_sock*)(&mockSock); 
	isk->inet_saddr = htonl(in_aton("127.0.0.1"));
	frang_conn_new_ptr = get_sym_ptr("frang_conn_new");
	res = frang_conn_new_ptr(&mockSock);
TFW_DBG("frang_conn_max:%s;%d\n","before ra",isk->inet_saddr);
ra = get_frang_acc(&mockSock);
TFW_DBG("frang_conn_max:%s;%d\n","after ra",ra->conn_curr);

/*while(i<5){
	ndelay(1000);
	isk = (struct inet_sock*)(&mockSock); 
//	isk->inet_saddr = in_aton(inet_addr);
	frang_conn_limit(ra,&mockSock);
	i++;
	};*/
	isk = (struct inet_sock*)(&mockSock); 
//	isk->inet_saddr = in_aton(inet_addr);
	ra->conn_curr = 5;
	frang_conn_limit_ptr = get_sym_ptr("frang_conn_limit");
	res = frang_conn_limit_ptr(ra,&mockSock);
	EXPECT_EQ(TFW_BLOCK, res);
ts = jiffies * FRANG_FREQ / HZ;
i = ts % FRANG_FREQ;
	frang_cfg->conn_max = 0;
	frang_cfg->conn_rate = 5;
	ra->history[i].conn_new =5;
	res = frang_conn_limit_ptr(ra, &mockSock);
	EXPECT_EQ(TFW_BLOCK,res);
	frang_cfg->conn_max =0;
	frang_cfg->conn_rate = 0;
	frang_cfg->conn_burst = 5;
	ra->history[i].conn_new = 5;
	res = frang_conn_limit_ptr(ra,&mockSock);
	EXPECT_EQ(TFW_BLOCK,res);



	}
//static int (*frang_http_uri_ptr)(const TfwHttpReq *req);
//extern int frang_http_uri_len(const TfwHttpReq *req);

TEST(frang,uri){
TfwHttpReq *mockReq;
TfwStr uri;
mockReq = test_req_alloc(26);
tfw_http_parse_req(mockReq,"GET /index.html HTTP /1.1",25);
//	const char* conf_max_uri = "http_uri_len=10";frang_cfg = get_sym_ptr("frang_cfg");
//TFW_DBG("uri_len:%s;%lu\n","start conf:",(unsigned long)frang_cfg); 
	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}

	frang_cfg->http_uri_len = 5;
//	LIST_HEAD(frang_cfg_mod);
//	tfw_cfg_start_mods(conf_max_uri, &frang_cfg_mod);

uri.len = 17;
uri.ptr = (void*)"/home/index.html";
mockReq->uri_path = uri;
//frang_http_uri_ptr = get_sym_ptr("frang_http_uri_len");
//TFW_DBG("uri_len funk ptr:%lu\n",(unsigned long)frang_http_uri_ptr);
res = req_handler(mockReq);
//res = frang_http_uri_len(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}
//static int (*frang_http_methods_ptr)(const TfwHttpReq *req);

//static int (*frang_http_ct_check_ptr)(const TfwHttpReq *req);
TEST(frang,ct_check){
TfwHttpReq * mockReq;
FrangCtVal ctval[1];

	mockReq = test_req_alloc(22);
	tfw_http_parse_req(mockReq,"POST /foo HTTP/1.1\r\n",20);
	TFW_DBG("ct_check:%s;%lu\n","after parse req req:",(unsigned long)mockReq); 
	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}
//TFW_DBG("ct_check:%s;%lu\n","after conf conf:",(unsigned long)frang_cfg); 
ctval[0].len = 17;
ctval[0].str ="application/html";
	frang_cfg->http_ct_required = true;
	res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);

//	frang_cfg->http_ct_vals = ctval;
//	frang_cfg->http_ct_vals[0].len = 17;
//W_DBG("ct_check:%s;%d\n","after conf ct_vals:",358); 
	mockReq->frang_st = 9; 
	res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}

//frang_http_ct_check_ptr = get_sym_ptr("frang_http_ct_check");
//res = frang_http_ct_check_ptr(mockReq);
//EXPECT_EQ(TFW_BLO/CK,res);
//test_req_free(mockReq);
//mockReq = test_req_alloc(92);
//TFW_DBG("ct_check:%s\n","after parse");
//frang_cfg->http_ct_vals[0].len =17;
//res = frang_http_ct_check_ptr(mockReq);
//EXPECT_EQ(TFW_BLOCK,res);
//}
//extern int frang_http_methods(const TfwHttpReq *req);
TEST(frang,req_method){
TfwHttpReq *mockReq;

mockReq = test_req_alloc(17);
tfw_http_parse_req(mockReq,"PUT /index.html",16);
TFW_DBG("frang_req_method:%d",mockReq->method);
	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}

frang_cfg->http_methods_mask = 2;
//frang_http_methods_ptr = get_sym_ptr("frang_http_methods");
res =req_handler(mockReq);//frang_http_methods_ptr(mockReq);
	EXPECT_EQ(TFW_BLOCK,res);
}
//static int (*frang_http_field_len_raw_ptr)(const TfwHttpReq *req);
TEST(frang,field_len){
TfwHttpReq *mockReq;
mockReq = test_req_alloc(20);
tfw_http_parse_req(mockReq,"GET /foo HTTP/1.1\r\n",19);

	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}
	frang_cfg->http_field_len =3;
//frang_http_field_len_raw_ptr = get_sym_ptr("frang_http_field_len_raw");
res = req_handler(mockReq);//frang_http_field_len_raw_ptr(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}
//static int (*frang_http_host_check_ptr)(TfwHttpReq* req);
TEST(frang,host){
TfwHttpReq *mockReq;

mockReq = test_req_alloc(7);
tfw_http_parse_req(mockReq,"GET /foo HTTP/1.1\r\n",19);

//tfw_http_parse_req(&mockReq,"GET /\n",6);
	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}
	frang_cfg->http_host_required = true;
//frang_http_host_check_ptr = get_sym_ptr("frang_http_host_check");
res = req_handler(mockReq);//frang_http_host_check_ptr(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}
static int (*frang_req_limit_ptr)(FrangAcc *ra, struct sock *sk);
//	static int (*frang_http_req_handler_ptr)(void *obj, 
//			                  struct sk_buff *skb , 
//					  unsigned int off);
TEST(frang, req_count){
	TfwConnection mockConn;
unsigned long ts; 
//TfwHttpReq *mockReq;
	FrangAcc *ra;  
	frang_cfg->conn_max =0;
	frang_cfg->conn_burst = 0;
	frang_cfg->conn_rate = 0;
	frang_cfg->req_rate = 5;
	//frang_cfg.req_rate = 0;
			mockConn.sk = &mockSock;
//	mockReq = test_req_alloc(15);
//	tfw_http_parse_req(&mockReq,"GET / HTTP /1.1",15);
//	mockConn.msg = (TfwMsg*)&mockReq;
//	res = frang_http_req_handler(&mockConn, "GET / HTTP /1.1",15);
	ra = (FrangAcc*)get_frang_acc(&mockSock);
//	TFW_DBG("frang conn:%d",ra->conn_curr);
//	i = 0;
//while(i<5){
//ndelay(1000);
//	frang_req_limit(ra,&mockSock);
//	i++;
//}
ts = jiffies * FRANG_FREQ / HZ;
i = ts % FRANG_FREQ;
ra->history[i].req = 5;
TFW_DBG("frang_req_i:%d;%d",i,ra->history[i].req);
frang_req_limit_ptr = get_sym_ptr("frang_req_limit");
res = frang_req_limit_ptr(ra,&mockSock);
EXPECT_EQ(TFW_BLOCK,res);
frang_cfg->req_burst = 5;
ra->history[i].req = 5;
res = frang_req_limit_ptr(ra,&mockSock);
EXPECT_EQ(TFW_BLOCK,res);

}
//TFW_DBG("frang_req_method:%d",mockReq->method);
//extern TfwMsg *tfw_http_conn_msg_alloc(TfwConnection *conn);
	static int (*frang_http_req_handler_ptr)(void *obj, 
			                  struct sk_buff *skb , 
					  unsigned int off);
/*int req_handler(TfwHttpReq *req)
{
TfwConnection *conn;

//conn =  (TfwConnection*)req->msg->conn;
//tfw_cli_conn_alloc_ptr = get_sym_ptr("tfw_cli_conn_alloc");
//if(!tfw_cli_conn_alloc_ptr){
//	TFW_DBG("req_handler: alloc is null\n");
 //}

conn = (TfwConnection*)tfw_cli_conn_alloc();
conn->msg = &req->msg;
if(!conn){
	TFW_DBG("req_handler: conn is null\n");

}

//tfw_http_conn_msg_alloc(conn);

//conn->msg = req->msg;

frang_http_req_handler_ptr = get_sym_ptr("frang_http_req_handler");
TFW_DBG("req_handler:%s;%lu\n","hand_ptr:",(unsigned long)frang_http_req_handler_ptr);
if(! frang_http_req_handler_ptr){
TFW_DBG("frang_req_handleris null str:%d\n",392); 
}
//if(&mockReq->msg == NULL  || &mockReq->msg.skb_list == NULL){
//TFW_DBG("frang_req_handleris null param:%d\n",404); 
//}
return frang_http_req_handler_ptr((void*)conn,req->msg.skb_list.first,25);
}*/

TEST(frang,body_len)
{
TfwHttpReq *mockReq;
TfwStr body;
TfwStr crlf;
mockReq = test_req_alloc(22);
TFW_DBG("body_len:%s;%lu\n","after req_alloc:",(unsigned long)mockReq);

tfw_http_parse_req(mockReq,"POST /foo HTTP/1.1\r\n",20);
TFW_DBG("body_len:%s;%lu\n","after parse:",(unsigned long)mockReq);

body.ptr = "GET http://natsys-lab.com/foo";	
body.len = 29;
crlf.len = 2;
crlf.ptr = "\r\n";
TFW_DBG("body_len:%s;%lu\n","after body params:",(unsigned long)mockReq->body.len);

//mockReq->body = body;
mockReq->crlf = crlf;

mockReq->body.len = 29;
	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}

TFW_DBG("body_len:%s;%lu\n","before set params:",(unsigned long)frang_cfg);

frang_cfg->http_body_len = 3;
mockReq->frang_st = 0;
TFW_DBG("body_len:%s;%lu\n","before handler:",(unsigned long)mockReq);

res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}
TEST(frang,body_timeout)
{
TfwHttpReq *mockReq;
mockReq = test_req_alloc(62);
tfw_http_parse_req(mockReq,"POST http://natsys-lab.com/foo HTTP/1.1\r\n \
Content-Length:29\r\n",61);
	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}

frang_cfg->clnt_body_timeout = 1;
mockReq->frang_st = 12;
mockReq->tm_bchunk = jiffies - 100;
res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}
TEST(frang,hdr_timeout)
{
TfwHttpReq *mockReq;
mockReq = test_req_alloc(62);
tfw_http_parse_req(mockReq,"POST http://natsys-lab.com/foo HTTP/1.1\r\n \
Content-Length:29\r\n",61);


	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}

frang_cfg->clnt_body_timeout = 0;
frang_cfg->clnt_hdr_timeout = 1;
mockReq->frang_st = 12;
mockReq->tm_header = jiffies - 100;
res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}
TEST(frang,chunk_cnt)
{
TfwHttpReq *mockReq;
mockReq = test_req_alloc(62);
tfw_http_parse_req(mockReq,"POST http://natsys-lab.com/foo HTTP/1.1\r\n \
Content-Length:29\r\n",61);


	if(!frang_cfg){
	frang_cfg = (FrangCfg*)get_sym_ptr("frang_cfg");
	}
frang_cfg->http_hchunk_cnt = 1;
mockReq->chunk_cnt = 3;
mockReq->frang_st = 2;
res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
frang_cfg->http_hchunk_cnt = 0;
frang_cfg->http_bchunk_cnt = 1;
mockReq->chunk_cnt =3;
res = req_handler(mockReq);
EXPECT_EQ(TFW_BLOCK,res);
}

TEST_SUITE(frang){
	TEST_RUN(frang,uri);
	TEST_RUN(frang,body_len);
	TEST_RUN(frang,ct_check);
	TEST_RUN(frang,field_len);
	TEST_RUN(frang,host);
	TEST_RUN(frang,req_method);
	TEST_RUN(frang,max_conn);
	TEST_RUN(frang,chunk_cnt);
	TEST_RUN(frang,req_count);
		TEST_RUN(frang,body_timeout);
	TEST_RUN(frang,hdr_timeout);
	
	}
