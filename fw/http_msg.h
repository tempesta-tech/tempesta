/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_MSG_H__
#define __TFW_HTTP_MSG_H__

#include "http.h"

#define S_CRLF			"\r\n"
#define S_DLM			": "
#define S_SET_COOKIE		"set-cookie"
#define S_F_SET_COOKIE		S_SET_COOKIE S_DLM
#define S_LOCATION		"location"
#define S_F_LOCATION		S_LOCATION S_DLM
#define S_VIA			"via"
#define S_F_VIA			S_VIA S_DLM
#define S_VIA_H2_PROTO		"2.0 "
#define S_VERSION11		"HTTP/1.1"
#define S_0			S_VERSION11 " "

/*
 * The size of the buffer to store the value for ':status' pseudo-header
 * of HTTP/2-response.
 */
#define H2_STAT_VAL_LEN		3

TfwStr *tfw_http_msg_make_hdr(TfwPool *pool, const char *name, const char *val);
unsigned int tfw_http_msg_resp_spec_hid(const TfwStr *hdr);
unsigned int tfw_http_msg_req_spec_hid(const TfwStr *hdr);

const void *__tfw_http_msg_find_hdr(const TfwStr *hdr, const void *array,
				    size_t n, size_t member_sz);
#define tfw_http_msg_find_hdr(hdr, array)				\
	(TfwStr *)__tfw_http_msg_find_hdr(hdr, array,			\
					  ARRAY_SIZE(array), sizeof(TfwStr))

#define tfw_http_msg_set_str_data(hm, str, data)			\
	__tfw_str_set_data(str, data,					\
			   ss_skb_peek_tail(&hm->msg.skb_head))

void __h2_msg_hdr_val(TfwStr *hdr, TfwStr *out_val);
void __http_msg_hdr_val(TfwStr *hdr, unsigned id, TfwStr *val, bool client);

static inline void
tfw_http_msg_clnthdr_val(const TfwHttpReq *req, TfwStr *hdr, unsigned id,
			 TfwStr *val)
{
	if (TFW_MSG_H2(req))
		__h2_msg_hdr_val(hdr, val);
	else
		__http_msg_hdr_val(hdr, id, val, true);
}

static inline void
tfw_http_msg_srvhdr_val(TfwStr *hdr, unsigned id, TfwStr *val)
{
	__http_msg_hdr_val(hdr, id, val, false);
}

void tfw_http_msg_pair(TfwHttpResp *resp, TfwHttpReq *req);
void tfw_http_msg_unpair(TfwHttpMsg *msg);
TfwHttpMsg *__tfw_http_msg_alloc(void *owner, int type, bool full);

static inline TfwHttpReq *
tfw_http_msg_alloc_req_light(void *owner)
{
	return (TfwHttpReq *)__tfw_http_msg_alloc(owner, Conn_Clnt, false);
}

static inline TfwHttpResp *
__tfw_http_msg_alloc_resp(TfwHttpReq *req, bool full)
{
	TfwHttpResp *resp = (TfwHttpResp *)
		__tfw_http_msg_alloc(req->conn->peer, Conn_Srv, full);
	if (resp)
		tfw_http_msg_pair(resp, req);

	return resp;
}

static inline TfwHttpResp *
tfw_http_msg_alloc_resp(TfwHttpReq *req)
{
	return __tfw_http_msg_alloc_resp(req, true);
}

static inline TfwHttpResp *
tfw_http_msg_alloc_resp_light(TfwHttpReq *req)
{
	return __tfw_http_msg_alloc_resp(req, false);
}

static inline void
tfw_msg_transform_setup(TfwMsgIter *iter, struct sk_buff *skb)
{
	BUG_ON(!skb);

	iter->frag = -1;
	iter->skb = skb;
	if (!iter->skb_head)
		iter->skb_head = skb;
}

static inline int
tfw_h2_msg_hdr_add(TfwHttpResp *resp, char *name, size_t nlen, char *val,
		   size_t vlen, unsigned short idx)
{
	TfwStr hdr = {
		.chunks = (TfwStr []){
			{ .data = name,		.len = nlen },
			{ .data = val,		.len = vlen },
		},
		.len = nlen + vlen,
		.nchunks = 2,
		.hpack_idx = idx
	};

	return tfw_hpack_encode(resp, &hdr, true, true);
}

int __must_check __tfw_http_msg_add_str_data(TfwHttpMsg *hm, TfwStr *str,
					     void *data, size_t len,
					     struct sk_buff *skb);
#define tfw_http_msg_add_str_data(hm, str, data, len)			\
	__tfw_http_msg_add_str_data(hm, str, data, len,			\
				    ss_skb_peek_tail(&hm->msg.skb_head))

unsigned int tfw_http_msg_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr);

int tfw_http_msg_del_str(TfwHttpMsg *hm, TfwStr *str);
int tfw_http_msg_cutoff_body_chunks(TfwHttpResp *resp);
int tfw_http_msg_append_skb(TfwHttpMsg *hm);
void tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start);
int tfw_http_msg_hdr_close(TfwHttpMsg *hm);
int tfw_http_msg_grow_hdr_tbl(TfwHttpMsg *hm);
void tfw_http_msg_free(TfwHttpMsg *m);
int tfw_http_msg_expand_data(TfwHttpMsg *hm, struct sk_buff **skb_head,
			     const TfwStr *src, unsigned int *start_off);
int tfw_http_msg_setup_transform_pool(TfwHttpTransIter *mit, TfwHttpMsg *hm,
				      TfwPool* pool);
int tfw_http_msg_expand_from_pool(TfwHttpMsg *hm, const TfwStr *str);
int tfw_h2_msg_expand_from_pool(TfwHttpMsg *hm, const TfwStr *str,
				TfwHttpTransIter *mit);
int tfw_h2_msg_expand_from_pool_lc(TfwHttpMsg *hm, const TfwStr *str,
				   TfwHttpTransIter *mit);
int __hdr_name_cmp(const TfwStr *hdr, const TfwStr *cmp_hdr);
int __http_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr);
int tfw_http_msg_cutoff_headers(TfwHttpMsg *hm, TfwHttpMsgCleanup* cleanup);

#define TFW_H2_MSG_HDR_ADD(hm, name, val, idx)				\
	tfw_h2_msg_hdr_add(hm, name, sizeof(name) - 1, val,		\
			   sizeof(val) - 1, idx)

/**
* Special case for storing HTTP1.1 method to HTTP message headers list.
*/
static inline void
tfw_http_msg_method_close(TfwHttpMsg *hm)
{
	TfwHttpParser *parser = &hm->stream->parser;

	BUG_ON(parser->_hdr_tag != TFW_HTTP_METHOD);

	/* Close just parsed method. */
	parser->hdr.flags |= TFW_STR_COMPLETE;
	hm->h_tbl->tbl[parser->_hdr_tag] = parser->hdr;
	TFW_STR_INIT(&parser->hdr);
}

#endif /* __TFW_HTTP_MSG_H__ */
