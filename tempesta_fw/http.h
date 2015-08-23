/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_HTTP_H__
#define __TFW_HTTP_H__

#include "connection.h"
#include "msg.h"
#include "str.h"

/**
 * All helping information for current HTTP parsing state of a message.
 */
#define TFW_HTTP_PF_CR			0x01
#define TFW_HTTP_PF_LF			0x02
#define TFW_HTTP_PF_CRLF		(TFW_HTTP_PF_CR | TFW_HTTP_PF_LF)

typedef enum {
	TFW_HTTP_METH_NONE,
	TFW_HTTP_METH_GET,
	TFW_HTTP_METH_HEAD,
	TFW_HTTP_METH_POST,
	_TFW_HTTP_METH_COUNT
} tfw_http_meth_t;

#define TFW_HTTP_CC_NO_CACHE		0x001
#define TFW_HTTP_CC_NO_STORE		0x002
#define TFW_HTTP_CC_NO_TRANS		0x004
#define TFW_HTTP_CC_NO_OIC		0x008
#define TFW_HTTP_CC_MAX_STALE		0x010
#define TFW_HTTP_CC_MUST_REV		0x020
#define TFW_HTTP_CC_PROXY_REV		0x040
#define TFW_HTTP_CC_PUBLIC		0x080
#define TFW_HTTP_CC_PRIVATE		0x100
typedef struct {
	unsigned int	flags;
	unsigned int	max_age;
	unsigned int	s_maxage;
	unsigned int	max_fresh;
} TfwCacheControl;

/**
 * We use goto/switch-driven automaton, so compiler typically generates binary
 * search code over jump labels, so it gives log(N) lookup complexity where
 * N is number of states. However, DFA for full HTTP processing can be quite
 * large and log(N) becomes expensive and hard to code.
 *
 * So we use states space splitting to avoid states explosion.
 * @_i_st is used to save current state and go to interior sub-automaton
 * (e.g. process LWS using @state while current state is saved in @_i_st
 * or using @_i_st parse value of a header described.
 *
 * @state	- current parser state;
 * @_i_st	- helping (interior) state;
 * @to_go	- remaining number of bytes to process in the data chunk;
 *		  (limited by single packet size and never exceeds 64KB)
 * @to_read	- remaining number of bytes to read;
 * @_tmp_acc	- integer accumulator for parsing chunked integers;
 * @_tmp_chunk	- currently parsed (sub)string, possibly chunked;
 * @hdr		- currently parsed header.
 */
typedef struct tfw_http_parser {
	unsigned char	flags;
	unsigned short	to_go;
	int		state;
	int		_i_st;
	int		to_read;
	unsigned int	_tmp_acc;
	TfwStr		_tmp_chunk;
	TfwStr		hdr;
} TfwHttpParser;

/**
 * Http headers table.
 *
 * Singular headers (in terms of RFC 7230 3.2.2) go first to protect header
 * repetition attacks. See __header_is_singular() and don't forget to
 * update the static headers array when add a new singular header here.
 *
 * Note: don't forget to update hdr_val_eq() upon adding a new header.
 */
typedef enum {
	TFW_HTTP_HDR_HOST,
	TFW_HTTP_HDR_CONTENT_LENGTH,

	/* End of list of singular header. */
	TFW_HTTP_HDR_NONSINGULAR,

	TFW_HTTP_HDR_CONNECTION = TFW_HTTP_HDR_NONSINGULAR,
	TFW_HTTP_HDR_X_FORWARDED_FOR,

	/* Start of list of generic (raw) headers. */
	TFW_HTTP_HDR_RAW,

	TFW_HTTP_HDR_NUM	= 16,
	TFW_HTTP_HDR_NUM_MAX	= PAGE_SIZE / sizeof(int) / 2
} tfw_http_hdr_t;

typedef struct {
	TfwStr		field;
	struct sk_buff	*skb;
} TfwHttpHdr;

typedef struct {
	unsigned int	size;	/* number of elements in the table */
	unsigned int	off;
	TfwHttpHdr	tbl[0];
} TfwHttpHdrTbl;

#define __HHTBL_SZ(o)			(TFW_HTTP_HDR_NUM * (o))
#define TFW_HHTBL_SZ(o)			(sizeof(TfwHttpHdrTbl)		\
					 + sizeof(TfwHttpHdr) * __HHTBL_SZ(o))

/* Common flags for requests and responses. */
#define TFW_HTTP_CONN_CLOSE		0x0001
#define TFW_HTTP_CONN_KA		0x0002
#define __TFW_HTTP_CONN_MASK		(TFW_HTTP_CONN_CLOSE | TFW_HTTP_CONN_KA)
#define TFW_HTTP_CHUNKED		0x0004

/* Request flags */
#define TFW_HTTP_STICKY_SET		0x0100	/* Need 'Set-Cookie` */
#define TFW_HTTP_FIELD_DUPENTRY		0x0200	/* Duplicate field */

/**
 * Common HTTP message members.
 *
 * @conn	- connection which the message was received on;
 * @crlf	- pointer to CRLF between headers and body
 */
#define TFW_HTTP_MSG_COMMON						\
	TfwMsg		msg;						\
	TfwPool		*pool;						\
	TfwHttpHdrTbl	*h_tbl;						\
	TfwHttpParser	parser;						\
	TfwCacheControl	cache_ctl;					\
	unsigned int	flags;						\
	unsigned int	content_length;					\
	TfwConnection	*conn;						\
	unsigned char	*crlf;						\
	TfwStr		body;

/**
 * A helper structure for operations common for requests and responses.
 * Just don't want to use explicit inheritance.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
} TfwHttpMsg;

/**
 * HTTP Request.
 *
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @host	- host in URI, may differ from Host header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @frang_st	- current state of FRANG classifier;
 * @hdr_rawid	- id of the latest RAW header that was checked;
 * @tm_header	- time HTTP header started coming;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value calculated for the request;
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
	unsigned char		method;
	TfwStr			host;
	TfwStr			uri_path;
	unsigned int		frang_st;
	unsigned int		hdr_rawid;
	unsigned long		tm_header;
	unsigned long		tm_bchunk;
	unsigned long		hash;
	unsigned int		chunk_cnt;
} TfwHttpReq;

typedef struct {
	TFW_HTTP_MSG_COMMON;
	unsigned short	status;
	unsigned int	keep_alive;
	unsigned int	expires;
} TfwHttpResp;

#define FOR_EACH_HDR_FIELD(pos, end, msg)				\
	__FOR_EACH_HDR_FIELD(pos, end, msg, 0, (msg)->h_tbl->off)

#define FOR_EACH_HDR_FIELD_SPECIAL(pos, end, msg)			\
	__FOR_EACH_HDR_FIELD(pos, end, msg, 0, TFW_HTTP_HDR_RAW)

#define FOR_EACH_HDR_FIELD_RAW(pos, end, msg)				\
	__FOR_EACH_HDR_FIELD(pos, end, msg, TFW_HTTP_HDR_RAW,		\
					    (msg)->h_tbl->off)

#define FOR_EACH_HDR_FIELD_FROM(pos, end, msg, soff)			\
	__FOR_EACH_HDR_FIELD(pos, end, msg, soff, (msg)->h_tbl->off)

#define __FOR_EACH_HDR_FIELD(pos, end, msg, soff, eoff)			\
	for ((pos) = &(msg)->h_tbl->tbl[soff].field, 			\
	     (end) = &(msg)->h_tbl->tbl[eoff].field;			\
	     (pos) < (end); 						\
	     pos = (TfwStr *)((TfwHttpHdr *)(pos) + 1))

typedef void (*tfw_http_req_cache_cb_t)(TfwHttpReq *, TfwHttpResp *, void *);

/* Internal (parser) HTTP functions. */
int tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);
int tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);

/* HTTP message header add/del/sub API */
int tfw_http_hdr_add(TfwHttpMsg *, const char *, size_t);
int tfw_http_hdr_sub(TfwHttpMsg *, TfwStr *, const char *, size_t);
int tfw_http_hdr_del(TfwHttpMsg *, TfwStr *);

/*
 * Helper functions for preparation of an HTTP message.
 */
size_t tfw_http_prep_date(char *buf);
size_t tfw_http_prep_hexstring(char *buf, u_char *value, size_t len);
/*
 * Functions to send an HTTP error response to a client.
 */
TfwHttpMsg *tfw_http_prep_302(TfwHttpMsg *hm, TfwStr *cookie);
TfwHttpMsg *tfw_http_prep_502(TfwHttpMsg *hm);

/*
 * Functions to create SKBs with data stream.
 *
 * These are designed to work together. tfw_msg_setup() returns a handle
 * that is passed on each call to tfw_msg_add_data().
 */
void *tfw_msg_setup(TfwHttpMsg *hm, size_t len);
void tfw_msg_add_data(void *handle, TfwMsg *msg, char *data, size_t len);

#endif /* __TFW_HTTP_H__ */
