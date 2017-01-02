/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include <crypto/sha.h>

#include "connection.h"
#include "gfsm.h"
#include "msg.h"
#include "str.h"
#include "vhost.h"

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
	TFW_HTTP_METH_PURGE,
	_TFW_HTTP_METH_COUNT
} tfw_http_meth_t;

/* HTTP protocol versions. */
enum {
	__TFW_HTTP_VER_INVALID,
	TFW_HTTP_VER_09,
	TFW_HTTP_VER_10,
	TFW_HTTP_VER_11,
	TFW_HTTP_VER_20,
	_TFW_HTTP_VER_COUNT
};

/* CC directives common to requests and responses. */
#define TFW_HTTP_CC_NO_CACHE		0x00000001
#define TFW_HTTP_CC_NO_STORE		0x00000002
#define TFW_HTTP_CC_NO_TRANSFORM	0x00000004
#define TFW_HTTP_CC_MAX_AGE		0x00000008
/* Request only CC directives. */
#define TFW_HTTP_CC_MAX_STALE		0x00000010
#define TFW_HTTP_CC_MIN_FRESH		0x00000020
#define TFW_HTTP_CC_OIFCACHED		0x00000040
/* Response only CC directives. */
#define TFW_HTTP_CC_MUST_REVAL		0x00000100
#define TFW_HTTP_CC_PROXY_REVAL		0x00000200
#define TFW_HTTP_CC_PUBLIC		0x00000400
#define TFW_HTTP_CC_PRIVATE		0x00000800
#define TFW_HTTP_CC_S_MAXAGE		0x00001000
/* Mask to indicate that CC header is present. */
#define TFW_HTTP_CC_IS_PRESENT		0x0000ffff
/* Headers that affect Cache Control. */
#define TFW_HTTP_CC_PRAGMA_NO_CACHE	0x00010000
#define TFW_HTTP_CC_HDR_AGE		0x00020000
#define TFW_HTTP_CC_HDR_EXPIRES		0x00040000
#define TFW_HTTP_CC_HDR_AUTHORIZATION	0x00080000
/* Config directives that affect Cache Control. */
#define TFW_HTTP_CC_CFG_CACHE_BYPASS	0x01000000

typedef struct {
	unsigned int	flags;
	unsigned int	max_age;
	unsigned int	s_maxage;
	unsigned int	max_stale;
	unsigned int	min_fresh;
	time_t		timestamp;
	time_t		age;
	time_t		expires;
} TfwCacheControl;

/**
 * Http headers table.
 *
 * Singular headers (in terms of RFC 7230 3.2.2) go first to protect header
 * repetition attacks. See __hdr_is_singular() and don't forget to
 * update the static headers array when add a new singular header here.
 * If the new header is hop-by-hop (must not be forwarded and cached by Tempesta)
 * it must be listed in __hbh_parser_init_req()/__hbh_parser_init_resp() for
 * unconditionally hop-by-hop header or in __parse_connection() otherwize.
 * If the header is end-to-end it must be listed in __hbh_parser_add_data().
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
	TFW_HTTP_HDR_KEEP_ALIVE,
	TFW_HTTP_HDR_TRANSFER_ENCODING,

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

/** Maximum of hop-by-hop tokens listed in Connection header. */
#define TFW_HBH_TOKENS_MAX		16

/**
 * Non-cacheable hop-by-hop headers in terms of RFC 7230.
 *
 * We don't store the headers in cache and create them from scratch if needed.
 * Adding a header is faster then modify it, so this speeds up headers
 * adjusting as well as saves cache storage.
 *
 * Headers unconditionaly treated as hop-by-hop must be listed in
 * __hbh_parser_init_req()/__hbh_parser_init_resp() functions and must be
 * members of Special headers.
 * group.
 *
 * @spec	- bit array for special headers. Hop-by-hop special header is
 *		  stored as (0x1 << tfw_http_hdr_t[hid]);
 * @raw		- table of raw headers names, parsed form connection field;
 * @off		- offset of last added raw header name;
 */
typedef struct {
	unsigned int	spec;
	unsigned int	off;
	TfwStr		raw[TFW_HBH_TOKENS_MAX];
} TfwHttpHbhHdrs;

/**
 * We use goto/switch-driven automaton, so compiler typically generates binary
 * search code over jump labels, so it gives log(N) lookup complexity where
 * N is number of states. However, DFA for full HTTP processing can be quite
 * large and log(N) becomes expensive and hard to code.
 *
 * So we use states space splitting to avoid states explosion.
 * @_i_st is used to save current state and go to interior sub-automaton
 * (e.g. process OWS using @state while current state is saved in @_i_st
 * or using @_i_st parse value of a header described.
 *
 * @to_go	- remaining number of bytes to process in the data chunk;
 *		  (limited by single packet size and never exceeds 64KB)
 * @state	- current parser state;
 * @_i_st	- helping (interior) state;
 * @to_read	- remaining number of bytes to read;
 * @_hdr_tag	- stores header id which must be closed on generic EoL handling
 *		  (see RGEN_EOL());
 * @_acc	- integer accumulator for parsing chunked integers;
 * @_tmp_chunk	- currently parsed (sub)string, possibly chunked;
 * @hdr		- currently parsed header.
 * @hbh_parser	- list of special and raw headers names to be treated as
 *		  hop-by-hop
 */
typedef struct {
	unsigned short	to_go;
	int		state;
	int		_i_st;
	int		to_read;
	unsigned long	_acc;
	time_t		_date;
	unsigned int	_hdr_tag;
	TfwStr		_tmp_chunk;
	TfwStr		hdr;
	TfwHttpHbhHdrs	hbh_parser;
} TfwHttpParser;

/* Common flags for requests and responses. */
#define TFW_HTTP_CONN_CLOSE		0x000001
#define TFW_HTTP_CONN_KA		0x000002
#define __TFW_HTTP_CONN_MASK		(TFW_HTTP_CONN_CLOSE | TFW_HTTP_CONN_KA)
#define TFW_HTTP_CONN_EXTRA		0x000004
#define TFW_HTTP_CHUNKED		0x000008
#define TFW_HTTP_MSG_SENT		0x000010

/* Request flags */
#define TFW_HTTP_HAS_STICKY		0x000100
#define TFW_HTTP_FIELD_DUPENTRY		0x000200	/* Duplicate field */
/* URI has form http://authority/path, not just /path */
#define TFW_HTTP_URI_FULL		0x000400

/* Response flags */
#define TFW_HTTP_VOID_BODY		0x010000	/* Resp to HEAD req */
#define TFW_HTTP_HAS_HDR_DATE		0x020000	/* Has Date: header */
/* It is stale, but pass with a warning */
#define TFW_HTTP_RESP_STALE		0x040000

/**
 * HTTP session descriptor.
 *
 * @hmac	- crypto hash from values of an HTTP request;
 * @hentry	- hash list entry for all sessions hash;
 * @users	- the session use counter;
 * @ts		- timestamp for the client's session;
 * @expire	- expiration time for the session;
 * @srv_conn	- upstream server connection servicing the session;
 */
typedef struct {
	unsigned char		hmac[SHA1_DIGEST_SIZE];
	struct hlist_node	hentry;
	atomic_t		users;
	unsigned long		ts;
	unsigned long		expires;
	TfwConnection		*srv_conn;
} TfwHttpSess;

/**
 * Common HTTP message members.
 *
 * @version		- HTTP version (1.0 and 1.1 are only supported);
 * @flags		- message related flags. The flags are used in
 *			  concurrent read and writes, but concurrent writes
 *			  aren't alowed. So use atomic operations if concurrent
 *			  updates are possible;
 * @content_length	- the value of Content-Length header field;
 * @conn		- connection which the message was received on;
 * @jtstamp		- time the message has been received, in jiffies;
 * @keep_alive		- the value of timeout specified in Keep-Alive header;
 * @crlf		- pointer to CRLF between headers and body;
 * @body		- pointer to the body of a message;
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
	unsigned long	jtstamp;					\
	unsigned int	keep_alive;					\
	TfwConnection	*conn;						\
	void (*destructor)(void *msg);					\
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
 * @vhost	- virtual host for the request;
 * @location	- URI location;
 * @sess	- HTTP session descriptor, required for scheduling;
 * @userinfo	- userinfo in URI, not mandatory.
 * @host	- host in URI, may differ from Host header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @node	- NUMA node where request is serviced;
 * @frang_st	- current state of FRANG classifier;
 * @tm_header	- time HTTP header started coming;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value for caching calculated for the request;
 *
 * TfwStr members must be the first for efficient scanning.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
	TfwVhost		*vhost;
	TfwLocation		*location;
	TfwHttpSess		*sess;
	TfwStr			userinfo;
	TfwStr			host;
	TfwStr			uri_path;
	unsigned char		method;
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
	time_t			date;
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

/* Get current timestamp in secs. */
static inline time_t
tfw_current_timestamp(void)
{
	struct timespec ts;
	getnstimeofday(&ts);
	return ts.tv_sec;
}

typedef void (*tfw_http_cache_cb_t)(TfwHttpReq *, TfwHttpResp *);

/* Internal (parser) HTTP functions. */
int tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);
int tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len);
bool tfw_http_parse_terminate(TfwHttpMsg *hm);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);
void tfw_http_req_destruct(void *msg);

/*
 * Functions to send an HTTP error response to a client.
 */
int tfw_http_send_200(TfwHttpReq *req);
int tfw_http_prep_302(TfwHttpMsg *resp, TfwHttpReq *req, TfwStr *cookie);
int tfw_http_send_403(TfwHttpReq *req, const char *reason);
int tfw_http_send_404(TfwHttpReq *req, const char *reason);
int tfw_http_send_502(TfwHttpReq *req, const char *reason);
int tfw_http_send_504(TfwHttpReq *req, const char *reason);

/*
 * Functions to create SKBs with data stream.
 *
 * These are designed to work together. tfw_msg_setup() returns a handle
 * that is passed on each call to tfw_msg_add_data().
 */
void *tfw_msg_setup(TfwHttpMsg *hm, size_t len);
void tfw_msg_add_data(void *handle, TfwMsg *msg, char *data, size_t len);

/*
 * HTTP session routines.
 */
int tfw_http_sess_obtain(TfwHttpReq *req);
int tfw_http_sess_resp_process(TfwHttpResp *resp, TfwHttpReq *req);
void tfw_http_sess_put(TfwHttpSess *sess);

#endif /* __TFW_HTTP_H__ */
