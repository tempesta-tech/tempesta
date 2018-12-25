/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include "server.h"
#include "str.h"
#include "vhost.h"

typedef struct tfw_http_sess_t TfwHttpSess;

/**
 * HTTP Generic FSM states.
 *
 * We (as Apache HTTP Server and other Web-servers do) define several phases
 * on HTTP message processing. However we set the hooks also to response
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

	/* Run just before locally generated response sending. */
	TFW_HTTP_FSM_LOCAL_RESP_FILTER	= TFW_GFSM_HTTP_STATE(5),

	TFW_HTTP_FSM_RESP_MSG_FWD	= TFW_GFSM_HTTP_STATE(6),

	TFW_HTTP_FSM_DONE	= TFW_GFSM_HTTP_STATE(TFW_GFSM_STATE_LAST)
};

/* TODO: When CONNECT will be added, add it to tfw_handle_validation_req() */
typedef enum {
	_TFW_HTTP_METH_NONE,
	/*
	 * Most popular methods, registered in IANA.
	 * https://www.iana.org/assignments/http-methods/http-methods.xhtml
	 */
	TFW_HTTP_METH_COPY,
	TFW_HTTP_METH_DELETE,
	TFW_HTTP_METH_GET,		/* Safe. */
	TFW_HTTP_METH_HEAD,		/* Safe. */
	TFW_HTTP_METH_LOCK,		/* Non-idempotent. */
	TFW_HTTP_METH_MKCOL,
	TFW_HTTP_METH_MOVE,
	TFW_HTTP_METH_OPTIONS,		/* Safe. */
	TFW_HTTP_METH_PATCH,		/* Non-idempotent. */
	TFW_HTTP_METH_POST,		/* Non-idempotent. */
	TFW_HTTP_METH_PROPFIND,		/* Safe. */
	TFW_HTTP_METH_PROPPATCH,
	TFW_HTTP_METH_PUT,
	TFW_HTTP_METH_TRACE,		/* Safe. */
	TFW_HTTP_METH_UNLOCK,
	/* Well-known methods, not listed in RFCs. */
	TFW_HTTP_METH_PURGE,
	/* Unknown method, passed to upstream without additional processing. */
	_TFW_HTTP_METH_UNKNOWN,
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
 * it must be listed in tfw_http_init_parser_req()/tfw_http_init_parser_resp()
 * for unconditionally hop-by-hop header or in __parse_connection() otherwize.
 * If the header is end-to-end it must be listed in __hbh_parser_add_data().
 *
 * Note: don't forget to update __http_msg_hdr_val() and
 * tfw_http_msg_(resp|req)_spec_hid() upon adding a new header.
 *
 * Cookie: singular according to RFC 6265 5.4.
 *
 * TODO split the enumeration to separate server and client sets to avoid
 * wasting of headers array slots.
 */
typedef enum {
	TFW_HTTP_HDR_HOST,
	TFW_HTTP_HDR_CONTENT_LENGTH,
	TFW_HTTP_HDR_CONTENT_TYPE,
	TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_SERVER = TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_COOKIE,
	TFW_HTTP_HDR_REFERER,
	TFW_HTTP_HDR_IF_NONE_MATCH,
	TFW_HTTP_HDR_ETAG = TFW_HTTP_HDR_IF_NONE_MATCH,

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
 * Headers unconditionally treated as hop-by-hop must be listed in
 * tfw_http_init_parser_req()/tfw_http_init_parser_resp() functions and must be
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
 * @_cnt	- currently the count of hex digits in a body chunk size;
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
 * @_date	- currently parsed http date value;
 */
typedef struct {
	unsigned short	_cnt;
	unsigned int	_hdr_tag;
	int		state;
	int		_i_st;
	long		to_read;
	unsigned long	_acc;
	time_t		_date;
	TfwStr		_tmp_chunk;
	TfwStr		hdr;
	TfwHttpHbhHdrs	hbh_parser;
} TfwHttpParser;

enum {
	/* Common flags for requests and responses. */
	TFW_HTTP_FLAGS_COMMON	= 0,
	/* 'Connection:' header contains 'close'. */
	TFW_HTTP_B_CONN_CLOSE	= TFW_HTTP_FLAGS_COMMON,
	/* 'Connection:' header contains 'keep-alive'. */
	TFW_HTTP_B_CONN_KA,
	/* 'Connection:' header contains additional terms. */
	TFW_HTTP_B_CONN_EXTRA,
	/* Chunked transfer encoding. */
	TFW_HTTP_B_CHUNKED,
	/* Singular header presents more than once. */
	TFW_HTTP_B_FIELD_DUPENTRY,

	/* Request flags. */
	TFW_HTTP_FLAGS_REQ,
	/* Sticky cookie is found and verified. */
	TFW_HTTP_B_HAS_STICKY	= TFW_HTTP_FLAGS_REQ,
	/* URI has form http://authority/path, not just /path */
	TFW_HTTP_B_URI_FULL,
	/* Request is non-idempotent. */
	TFW_HTTP_B_NON_IDEMP,
	/* Request was sent by attacker. */
	TFW_HTTP_B_SUSPECTED,
	/* Request stated 'Accept: text/html' header */
	TFW_HTTP_B_ACCEPT_HTML,
	/* Request is created by HTTP health monitor. */
	TFW_HTTP_B_HMONITOR,
	/* Request from whitelist: skip frang and sticky modules processing. */
	TFW_HTTP_B_WHITELIST,
	/* Client was disconnected, drop the request. */
	TFW_HTTP_B_REQ_DROP,
	/* Request was received on TLS connection. */
	TFW_HTTP_B_REQ_TLS,

	/* Response flags */
	TFW_HTTP_FLAGS_RESP,
	/* Response has no body. */
	TFW_HTTP_B_VOID_BODY	= TFW_HTTP_FLAGS_RESP,
	/* Response has header 'Date:'. */
	TFW_HTTP_B_HDR_DATE,
	/* Response has header 'Last-Modified:'. */
	TFW_HTTP_B_HDR_LMODIFIED,
	/* Response is stale, but pass with a warning. */
	TFW_HTTP_B_RESP_STALE,
	/* Response is fully processed and ready to be forwarded to the client. */
	TFW_HTTP_B_RESP_READY,

	_TFW_HTTP_FLAGS_NUM
};

#define TFW_HTTP_F_CONN_CLOSE		(1U << TFW_HTTP_B_CONN_CLOSE)
#define TFW_HTTP_F_CONN_KA		(1U << TFW_HTTP_B_CONN_KA)
#define __TFW_HTTP_MSG_M_CONN_MASK	\
	(TFW_HTTP_F_CONN_KA | TFW_HTTP_F_CONN_CLOSE)
#define TFW_HTTP_F_CONN_EXTRA		(1U << TFW_HTTP_B_CONN_EXTRA)
#define TFW_HTTP_F_CHUNKED		(1U << TFW_HTTP_B_CHUNKED)
#define TFW_HTTP_F_FIELD_DUPENTRY	(1U << TFW_HTTP_B_FIELD_DUPENTRY)

#define TFW_HTTP_F_HAS_STICKY		(1U << TFW_HTTP_B_HAS_STICKY)
#define TFW_HTTP_F_URI_FULL		(1U << TFW_HTTP_B_URI_FULL)
#define TFW_HTTP_F_NON_IDEMP		(1U << TFW_HTTP_B_NON_IDEMP)
#define TFW_HTTP_F_SUSPECTED		(1U << TFW_HTTP_B_SUSPECTED)
#define TFW_HTTP_F_ACCEPT_HTML		(1U << TFW_HTTP_B_ACCEPT_HTML)
#define TFW_HTTP_F_HMONITOR		(1U << TFW_HTTP_B_HMONITOR)
#define TFW_HTTP_F_WHITELIST		(1U << TFW_HTTP_B_WHITELIST)
#define TFW_HTTP_F_REQ_DROP		(1U << TFW_HTTP_B_REQ_DROP)
#define TFW_HTTP_F_REQ_TLS		(1U << TFW_HTTP_B_REQ_TLS)

#define TFW_HTTP_F_VOID_BODY		(1U << TFW_HTTP_B_VOID_BODY)
#define TFW_HTTP_F_HDR_DATE		(1U << TFW_HTTP_B_HDR_DATE)
#define TFW_HTTP_F_HDR_LMODIFIED	(1U << TFW_HTTP_B_HDR_LMODIFIED)
#define TFW_HTTP_F_RESP_STALE		(1U << TFW_HTTP_B_RESP_STALE)
#define TFW_HTTP_F_RESP_READY		(1U << TFW_HTTP_B_RESP_READY)

/*
 * The structure to hold data for an HTTP error response.
 * An error response is sent later in an unlocked queue context.
 *
 * @reason	- the error response message;
 * @status	- HTTP error response status;
 */
typedef struct {
	const char	*reason;
	unsigned short	status;
} TfwHttpError;

typedef struct tfw_http_msg_t	TfwHttpMsg;
typedef struct tfw_http_req_t	TfwHttpReq;
typedef struct tfw_http_resp_t	TfwHttpResp;

/**
 * Common HTTP message members.
 *
 * @msg			- the base data of an HTTP message;
 * @pool		- message's memory allocation pool;
 * @h_tbl		- table of message's HTTP headers in internal form;
 * @parser		- parser state data while a message is parsed;
 * @httperr		- HTTP error data used to form an error response;
 * @pair		- the message paired with this one;
 * @req			- the request paired with this response;
 * @resp		- the response paired with this request;
 * @cache_ctl		- cache control data for a message;
 * @version		- HTTP version (1.0 and 1.1 are only supported);
 * @flags		- message related flags. The flags are tested
 *			  concurrently, but concurrent updates aren't
 *			  allowed. Use atomic operations if concurrent
 *			  updates are possible;
 * @content_length	- the value of Content-Length header field;
 * @keep_alive		- the value of timeout specified in Keep-Alive header;
 * @conn		- connection which the message was received on;
 * @destructor		- called when a connection is destroyed;
 * @crlf		- pointer to CRLF between headers and body;
 * @body		- pointer to the body of a message;
 *
 * TfwStr members must be the last for efficient scanning.
 *
 * NOTE: The space taken by @parser member is shared with @httperr member.
 * When a message results in an error, the parser state data is not used
 * anymore, so this is safe. The reason for reuse is that it's imperative
 * that saving the error data succeeds. If it fails, that will lead to
 * a request without a response - a hole in @seq_queue. Alternatively,
 * memory allocation from pool may fail, even if that's a rare case.
 * BUILD_BUG_ON() is used in tfw_http_init() to ensure that @httperr
 * doesn't make the whole structure bigger.
 */
#define TFW_HTTP_MSG_COMMON						\
	TfwMsg		msg;						\
	TfwPool		*pool;						\
	TfwHttpHdrTbl	*h_tbl;						\
	union {								\
		TfwHttpMsg	*pair;					\
		TfwHttpReq	*req;					\
		TfwHttpResp	*resp;					\
	};								\
	union {								\
		TfwHttpParser	parser;					\
		TfwHttpError	httperr;				\
	};								\
	TfwCacheControl	cache_ctl;					\
	unsigned char	version;					\
	unsigned int	flags;						\
	unsigned long	content_length;					\
	unsigned int	keep_alive;					\
	TfwConn		*conn;						\
	void (*destructor)(void *msg);					\
	TfwStr		crlf;						\
	TfwStr		body;

/**
 * A helper structure for operations common for requests and responses.
 * Just don't want to use explicit inheritance.
 */
struct tfw_http_msg_t {
	TFW_HTTP_MSG_COMMON;
};

#define __MSG_STR_START(m)		(&(m)->crlf)

#define TFW_HTTP_COND_IF_MSINCE		0x0001
#define TFW_HTTP_COND_ETAG_ANY		0x0002
#define TFW_HTTP_COND_ETAG_LIST		0x0004

/**
 * Conditional Request.
 *
 * @flags	- Which conditional headers are used,
 * @m_date	- requested modification date
 */
typedef struct {
	unsigned int	flags;
	time_t		m_date;
} TfwHttpCond;

/**
 * HTTP Request.
 *
 * @vhost	- virtual host for the request;
 * @location	- URI location;
 * @sess	- HTTP session descriptor, required for scheduling;
 * @userinfo	- userinfo in URI, not mandatory.
 * @host	- host in URI, may differ from Host header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @mark	- special hash mark for redirects handling in session module;
 * @fwd_list	- member in the queue of forwarded/backlogged requests;
 * @nip_list	- member in the queue of non-idempotent requests;
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @node	- NUMA node where request is serviced;
 * @frang_st	- current state of FRANG classifier;
 * @chunk_cnt	- header or body chunk count for Frang classifier;
 * @jtxtstamp	- time the request is forwarded to a server, in jiffies;
 * @jrxtstamp	- time the request is received from a client, in jiffies;
 * @tm_header	- time HTTP header started coming;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value for caching calculated for the request;
 * @retries	- the number of re-send attempts;
 *
 * TfwStr members must be the first for efficient scanning.
 */
struct tfw_http_req_t {
	TFW_HTTP_MSG_COMMON;
	TfwVhost		*vhost;
	TfwLocation		*location;
	TfwHttpSess		*sess;
	TfwHttpCond		cond;
	TfwStr			userinfo;
	TfwStr			host;
	TfwStr			uri_path;
	TfwStr			mark;
	struct list_head	fwd_list;
	struct list_head	nip_list;
	unsigned char		method;
	unsigned short		node;
	unsigned int		frang_st;
	unsigned int		chunk_cnt;
	unsigned long		jtxtstamp;
	unsigned long		jrxtstamp;
	unsigned long		tm_header;
	unsigned long		tm_bchunk;
	unsigned long		hash;
	unsigned short		retries;
};

#define TFW_HTTP_REQ_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_REQ_STR_END(r)		((&(r)->uri_path) + 1)

/**
 * HTTP Response.
 * TfwStr members must be the first for efficient scanning.
 *
 * @jrxtstamp	- time the message has been received, in jiffies;
 */
struct tfw_http_resp_t {
	TFW_HTTP_MSG_COMMON;
	TfwStr			s_line;
	unsigned short		status;
	time_t			date;
	time_t			last_modified;
	unsigned long		jrxtstamp;
};

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

/* Bit flags for block action behaviour. */
#define TFW_BLK_ERR_REPLY		0x0001
#define TFW_BLK_ATT_REPLY		0x0002
#define TFW_BLK_ERR_NOLOG		0x0004
#define TFW_BLK_ATT_NOLOG		0x0008

/* HTTP codes enumeration for predefined responses */
typedef enum {
	RESP_200,
	RESP_4XX_BEGIN,
	RESP_400	= RESP_4XX_BEGIN,
	RESP_403,
	RESP_404,
	RESP_412,
	RESP_4XX_END,
	RESP_5XX_BEGIN	= RESP_4XX_END,
	RESP_500	= RESP_5XX_BEGIN,
	RESP_502,
	RESP_503,
	RESP_504,
	RESP_5XX_END,
	RESP_NUM	= RESP_5XX_END
} resp_code_t;

enum {
	HTTP_STATUS_1XX = 1,
	HTTP_STATUS_2XX,
	HTTP_STATUS_3XX,
	HTTP_STATUS_4XX,
	HTTP_STATUS_5XX
};

#define HTTP_CODE_MIN 100
#define HTTP_CODE_MAX 599
#define HTTP_CODE_BIT_NUM(code) ((code) - HTTP_CODE_MIN)

/* Get current timestamp in secs. */
static inline time_t
tfw_current_timestamp(void)
{
	struct timespec ts;
	getnstimeofday(&ts);
	return ts.tv_sec;
}

static inline int
tfw_http_resp_code_range(const int n)
{
	return n <= HTTP_CODE_MAX && n >= HTTP_CODE_MIN;
}

typedef void (*tfw_http_cache_cb_t)(TfwHttpMsg *);

/* Internal (parser) HTTP functions. */
void tfw_http_init_parser_req(TfwHttpReq *req);
void tfw_http_init_parser_resp(TfwHttpResp *resp);
int tfw_http_parse_req(void *req_data, unsigned char *data, size_t len,
		       unsigned int *parsed);
int tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len,
			unsigned int *parsed);
bool tfw_http_parse_terminate(TfwHttpMsg *hm);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, TfwFsmData *data);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);
void tfw_http_req_destruct(void *msg);
void tfw_http_resp_fwd(TfwHttpResp *resp);
void tfw_http_resp_build_error(TfwHttpReq *req);
int tfw_cfgop_parse_http_status(const char *status, int *out);
void tfw_http_hm_srv_send(TfwServer *srv, char *data, unsigned long len);

/*
 * Functions to send an HTTP error response to a client.
 */
int tfw_http_prep_redirect(TfwHttpMsg *resp, unsigned short status,
			   TfwStr *rmark, TfwStr *cookie, TfwStr *body);
int tfw_http_prep_304(TfwHttpMsg *resp, TfwHttpReq *req, TfwMsgIter *msg_it,
		      size_t hdrs_size);
void tfw_http_send_resp(TfwHttpReq *req, int status, const char *reason);

/* Helper functions */
char *tfw_http_msg_body_dup(const char *filename, size_t *len);

#endif /* __TFW_HTTP_H__ */
