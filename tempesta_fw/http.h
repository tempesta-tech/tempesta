/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_H__
#define __TFW_HTTP_H__

#include "connection.h"
#include "gfsm.h"
#include "msg.h"
#include "str.h"

/**
 * HTTP Generic FSM states.
 *
 * We (as Apache HTTP Server and other Web-servers do) define several phases
 * on HTTP messgas processing. However we set the hooks also to response
 * processing (local and received from backend server) as well as to request
 * processing. We can depict the phases as following:
 *
 *	Client			Tempesta			Server
 *	~~~~~~			~~~~~~~~			~~~~~~
 *
 * 	[req]		-->	(I) (process)	-->		[req]
 *
 * 	[resp]		<--	(process) (II)	<--		[resp]
 *
 * 	[resp]		<--	(III) (process) <-+
 * 						   \
 * 						(local cache)
 *
 * So generally hooks are called on receiving client request (I), on receiving
 * server response (II) and after generation of local response (III).
 *
 * TODO generic callback note. We need to:
 * 1. store all callbacks in fixed size array to eliminate random memory access
 *    on callbacks;
 * 2. modules must register a callback only if it has work to do (not just when
 *    it's loaded into kernel).
 */
#define TFW_GFSM_HTTP_STATE(s)	((TFW_FSM_HTTP << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* HTTP FSM initial state, not hookable. */
	TFW_HTTP_FSM_INIT		= TFW_GFSM_HTTP_STATE(0),

	/* Called on request End-Of-Skb (EOS). */
	TFW_HTTP_FSM_REQ_CHUNK		= TFW_GFSM_HTTP_STATE(1),

	/* Whole request is read. */
	TFW_HTTP_FSM_REQ_MSG		= TFW_GFSM_HTTP_STATE(2),

	/* Called on response EOS. */
	TFW_HTTP_FSM_RESP_CHUNK		= TFW_GFSM_HTTP_STATE(3),

	/* Whole response is read. */
	TFW_HTTP_FSM_RESP_MSG		= TFW_GFSM_HTTP_STATE(4),

	/* Run just before localy generated response sending. */
	TFW_HTTP_FSM_LOCAL_RESP_FILTER	= TFW_GFSM_HTTP_STATE(5),

	TFW_HTTP_FSM_DONE	= TFW_GFSM_HTTP_STATE(TFW_GFSM_STATE_LAST)
};

typedef enum {
	TFW_HTTP_METH_NONE,
	TFW_HTTP_METH_GET,
	TFW_HTTP_METH_HEAD,
	TFW_HTTP_METH_POST,
	_TFW_HTTP_METH_COUNT
} tfw_http_meth_t;

/* HTTP protocol versions. */
enum {
	__TFW_HTTP_VER_INVALID,
	TFW_HTTP_VER_09,
	TFW_HTTP_VER_10,
	TFW_HTTP_VER_11,
	TFW_HTTP_VER_20,
};

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
 * @to_go	- remaining number of bytes to process in the data chunk;
 *		  (limited by single packet size and never exceeds 64KB)
 * @state	- current parser state;
 * @_i_st	- helping (interior) state;
 * @to_read	- remaining number of bytes to read;
 * @_hdr_tag	- describes, which header should be closed in case of
 *		  the empty header (see RGEN_LWS_empty)
 * @_tmp	- temporary register used to store context-specific data
 *                  acc) integer accumulator for parsing chunked integers;
 *                  eol) track of CR/LF delimiters while hunting for EOL;
 * @_tmp_chunk	- currently parsed (sub)string, possibly chunked;
 * @hdr		- currently parsed header.
 */
typedef struct {
	unsigned short	to_go;
	int		state;
	int		_i_st;
	int		to_read;
	union {
		unsigned long acc;
		unsigned long eol;
	} _tmp;
	unsigned int	_hdr_tag;
	TfwStr		_tmp_chunk;
	TfwStr		hdr;
} TfwHttpParser;

/**
 * Http headers table.
 *
 * Singular headers (in terms of RFC 7230 3.2.2) go first to protect header
 * repetition attacks. See __hdr_is_singular() and don't forget to
 * update the static headers array when add a new singular header here.
 *
 * Note: don't forget to update __http_msg_hdr_val() upon adding a new header.
 *
 * Cookie: singular according to RFC 6265 5.4.
 *
 * TODO split the enumeration to separate server and client sets to avoid
 * vasting of headers array slots.
 */
typedef enum {
	TFW_HTTP_HDR_HOST,
	TFW_HTTP_HDR_CONTENT_LENGTH,
	TFW_HTTP_HDR_CONTENT_TYPE,
	TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_SERVER = TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_COOKIE,

	/* End of list of singular header. */
	TFW_HTTP_HDR_NONSINGULAR,

	TFW_HTTP_HDR_CONNECTION = TFW_HTTP_HDR_NONSINGULAR,
	TFW_HTTP_HDR_X_FORWARDED_FOR,

	/* Start of list of generic (raw) headers. */
	TFW_HTTP_HDR_RAW,

	TFW_HTTP_HDR_NUM	= 16,
} tfw_http_hdr_t;

typedef struct {
	unsigned int	size;	/* number of elements in the table */
	unsigned int	off;
	TfwStr		tbl[0];
} TfwHttpHdrTbl;

#define __HHTBL_SZ(o)			(TFW_HTTP_HDR_NUM * (o))
#define TFW_HHTBL_EXACTSZ(s)		(sizeof(TfwHttpHdrTbl)		\
					 + sizeof(TfwStr) * (s))
#define TFW_HHTBL_SZ(o)			TFW_HHTBL_EXACTSZ(__HHTBL_SZ(o))

/* Common flags for requests and responses. */
#define TFW_HTTP_CONN_CLOSE		0x000001
#define TFW_HTTP_CONN_KA		0x000002
#define __TFW_HTTP_CONN_MASK		(TFW_HTTP_CONN_CLOSE | TFW_HTTP_CONN_KA)
#define TFW_HTTP_CHUNKED		0x000004

/* Request flags */
#define TFW_HTTP_STICKY_SET		0x000100	/* Need 'Set-Cookie` */
#define TFW_HTTP_FIELD_DUPENTRY		0x000200	/* Duplicate field */
/* URI has form http://authority/path, not just /path */
#define TFW_HTTP_URI_FULL		0x000400

/* Response flags */
#define TFW_HTTP_VOID_BODY		0x010000	/* Resp to HEAD req */

/**
 * Common HTTP message members.
 *
 * @conn	- connection which the message was received on;
 * @crlf	- pointer to CRLF between headers and body;
 * @version	- HTTP version (1.0 and 1.1 are only supported);
 *
 * TfwStr members must be the last for efficient scanning.
 */
#define TFW_HTTP_MSG_COMMON						\
	TfwMsg		msg;						\
	TfwPool		*pool;						\
	TfwHttpHdrTbl	*h_tbl;						\
	TfwHttpParser	parser;						\
	TfwCacheControl	cache_ctl;					\
	unsigned char	version;					\
	unsigned int	flags;						\
	unsigned long	content_length;					\
	TfwConnection	*conn;						\
	TfwStr		crlf;						\
	TfwStr		body;

/**
 * A helper structure for operations common for requests and responses.
 * Just don't want to use explicit inheritance.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
} TfwHttpMsg;

#define __MSG_STR_START(m)		(&(m)->crlf)

/**
 * HTTP Request.
 *
 * @userinfo	- userinfo in URI, not mandatory.
 * @host	- host in URI, may differ from Host header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @node	- NUMA node where request is serviced;
 * @frang_st	- current state of FRANG classifier;
 * @tm_header	- time HTTP header started coming;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value calculated for the request;
 *
 * TfwStr members must be the first for efficient scanning.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
	TfwStr			userinfo;
	TfwStr			host;
	TfwStr			uri_path;
	tfw_http_meth_t		method;
	unsigned short		node;
	unsigned int		frang_st;
	unsigned int		chunk_cnt;
	unsigned long		tm_header;
	unsigned long		tm_bchunk;
	unsigned long		hash;
} TfwHttpReq;

#define TFW_HTTP_REQ_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_REQ_STR_END(r)		((&(r)->uri_path) + 1)

/**
 * HTTP Response.
 *
 * TfwStr members must be the first for efficient scanning.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
	TfwStr			s_line;
	unsigned short		status;
	unsigned int		keep_alive;
	unsigned int		expires;
} TfwHttpResp;

#define TFW_HTTP_RESP_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_RESP_STR_END(r)	((&(r)->body) + 1)

#define __FOR_EACH_HDR_FIELD(pos, end, msg, soff, eoff)			\
	for ((pos) = &(msg)->h_tbl->tbl[soff], 				\
	     (end) = &(msg)->h_tbl->tbl[eoff];				\
	     (pos) < (end); 						\
	     ++(pos))

#define FOR_EACH_HDR_FIELD(pos, end, msg)				\
	__FOR_EACH_HDR_FIELD(pos, end, msg, 0, (msg)->h_tbl->off)

#define FOR_EACH_HDR_FIELD_SPECIAL(pos, end, msg)			\
	__FOR_EACH_HDR_FIELD(pos, end, msg, 0, TFW_HTTP_HDR_RAW)

#define FOR_EACH_HDR_FIELD_RAW(pos, end, msg)				\
	__FOR_EACH_HDR_FIELD(pos, end, msg, TFW_HTTP_HDR_RAW,		\
					    (msg)->h_tbl->off)

#define FOR_EACH_HDR_FIELD_FROM(pos, end, msg, soff)			\
	__FOR_EACH_HDR_FIELD(pos, end, msg, soff, (msg)->h_tbl->off)

typedef void (*tfw_http_cache_cb_t)(TfwHttpReq *, TfwHttpResp *);

/* Internal (parser) HTTP functions. */
int tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);
int tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);

/*
 * Helper functions for preparation of an HTTP message.
 */
void tfw_http_prep_hexstring(char *buf, u_char *value, size_t len);
/*
 * Functions to send an HTTP error response to a client.
 */
int tfw_http_prep_302(TfwHttpMsg *resp, TfwHttpMsg *hm, TfwStr *cookie);
int tfw_http_send_502(TfwHttpMsg *hm);

/*
 * Functions to create SKBs with data stream.
 *
 * These are designed to work together. tfw_msg_setup() returns a handle
 * that is passed on each call to tfw_msg_add_data().
 */
void *tfw_msg_setup(TfwHttpMsg *hm, size_t len);
void tfw_msg_add_data(void *handle, TfwMsg *msg, char *data, size_t len);

#endif /* __TFW_HTTP_H__ */
