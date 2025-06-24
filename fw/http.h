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
#ifndef __TFW_HTTP_H__
#define __TFW_HTTP_H__

#include <crypto/sha512_base.h>

#include "http_types.h"
#include "connection.h"
#include "gfsm.h"
#include "msg.h"
#include "server.h"
#include "str.h"
#include "vhost.h"
#include "client.h"
#include "lib/tf.h"

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

/* TODO: When CONNECT will be added, add it to tfw_handle_validation_req()
 * and to tfw_http_parse_check_bodyless_meth() */
/* New safe methods MUST be added to TFW_HTTP_IS_METH_SAFE macro */
/* When adding new method id here, one should also update @tfw_http_meth_str2id() */
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
	_TFW_HTTP_METH_INCOMPLETE,
	_TFW_HTTP_METH_COUNT
} tfw_http_meth_t;

#define TFW_HTTP_IS_METH_SAFE(meth)					\
	((meth) == TFW_HTTP_METH_GET || (meth) == TFW_HTTP_METH_HEAD	\
	 || (meth) == TFW_HTTP_METH_OPTIONS || (meth) == TFW_HTTP_METH_PROPFIND)

#define TFW_HTTP_IS_METH_BODYLESS(meth)					\
	((meth) == TFW_HTTP_METH_GET || (meth) == TFW_HTTP_METH_HEAD	\
	 || (meth) == TFW_HTTP_METH_DELETE || (meth) == TFW_HTTP_METH_TRACE)

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
#define TFW_HTTP_CC_STALE_IF_ERROR	0x00000010
/* Request only CC directives. */
#define TFW_HTTP_CC_MAX_STALE		0x00000020
#define TFW_HTTP_CC_MIN_FRESH		0x00000040
#define TFW_HTTP_CC_OIFCACHED		0x00000080
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
/* Config directives that affect Cache Control and http_chain cache_disable. */
#define TFW_HTTP_CC_CFG_CACHE_BYPASS	0x01000000

typedef struct {
	unsigned int	flags;
	unsigned int	max_age;
	unsigned int	s_maxage;
	unsigned int	max_stale;
	unsigned int	min_fresh;
	/* Default TTL inferred from HTTP tables or global constant */
	unsigned int	default_ttl;
	long		timestamp;
	long		age;
	long		expires;
	/* Cache Control: stale-if-error. RFC 5861. */
	long		stale_if_error;
} TfwCacheControl;

/**
 * Http headers table.
 *
 * Singular headers (in terms of RFC 7230 3.2.2) go first to protect header
 * repetition attacks. Don't forget to update the static headers array when add
 * a new singular header here. If the new header is hop-by-hop (must not be
 * forwarded and cached by Tempesta) it must be listed in
 * tfw_http_init_parser_req()/tfw_http_init_parser_resp() for unconditionally
 * hop-by-hop header or in __parse_connection() otherwise. If the header is
 * end-to-end it must be listed in __hbh_parser_add_data().
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
	TFW_HTTP_STATUS_LINE,
	TFW_HTTP_METHOD = TFW_HTTP_STATUS_LINE,
	TFW_HTTP_HDR_H2_STATUS = TFW_HTTP_STATUS_LINE,
	TFW_HTTP_HDR_H2_METHOD = TFW_HTTP_METHOD,
	TFW_HTTP_HDR_H2_SCHEME,
	TFW_HTTP_HDR_H2_AUTHORITY,
	TFW_HTTP_HDR_H2_PATH,
	TFW_HTTP_HDR_REGULAR,
	TFW_HTTP_HDR_HOST = TFW_HTTP_HDR_REGULAR,
	TFW_HTTP_HDR_CONTENT_LENGTH,
	TFW_HTTP_HDR_CONTENT_LOCATION, /* response specific header. */
	TFW_HTTP_HDR_CONTENT_TYPE,
	TFW_HTTP_HDR_EXPECT,
	TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_SERVER = TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_COOKIE,
	TFW_HTTP_HDR_REFERER,
	TFW_HTTP_HDR_IF_NONE_MATCH,
	TFW_HTTP_HDR_ETAG = TFW_HTTP_HDR_IF_NONE_MATCH,
	TFW_HTTP_HDR_X_TEMPESTA_CACHE,
	TFW_HTTP_HDR_AGE,

	/* End of list of singular header. */
	TFW_HTTP_HDR_NONSINGULAR,

	TFW_HTTP_HDR_CONNECTION = TFW_HTTP_HDR_NONSINGULAR,
	TFW_HTTP_HDR_SET_COOKIE,
	TFW_HTTP_HDR_X_FORWARDED_FOR,
	TFW_HTTP_HDR_FORWARDED,
	TFW_HTTP_HDR_KEEP_ALIVE,
	TFW_HTTP_HDR_TRANSFER_ENCODING,
	TFW_HTTP_HDR_CONTENT_ENCODING,
	TFW_HTTP_HDR_UPGRADE,

	/* Start of list of generic (raw) headers. */
	TFW_HTTP_HDR_RAW,

	TFW_HTTP_HDR_NUM,
} tfw_http_hdr_t;

#define __TFW_HTTP_MSG_M_CONN						\
	(BIT(TFW_HTTP_B_CONN_CLOSE) | BIT(TFW_HTTP_B_CONN_KA))

#define TFW_MSG_H2(hmmsg)						\
	test_bit(TFW_HTTP_B_H2, ((TfwHttpMsg *)hmmsg)->flags)

#define TFW_RESP_TO_H2(hmmsg)						\
	((!hmmsg->conn || TFW_CONN_TYPE(hmmsg->conn) & Conn_Srv) &&	\
	 hmmsg->pair && TFW_MSG_H2(hmmsg->pair))

/**
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

/**
 * Common HTTP message members.
 *
 * @msg			- the base data of an HTTP message;
 * @pool		- message's memory allocation pool;
 * @h_tbl		- table of message's HTTP headers in internal form;
 * @pair		- the message paired with this one;
 * @req			- the request paired with this response;
 * @resp		- the response paired with this request;
 * @stream		- stream which the message is linked with;
 * @httperr		- HTTP error data used to form an error response;
 * @cache_ctl		- cache control data for a message;
 * @version		- HTTP version (1.0 and 1.1 are only supported);
 * @keep_alive		- the value of timeout specified in Keep-Alive header;
 * @iter		- skb expansion iterator;
 * @content_length	- the value of Content-Length header field;
 * @jrxtstamp		- time the message has been received, in jiffies;
 * @flags		- message related flags. The flags are tested
 *			  concurrently, but concurrent updates aren't
 *			  allowed. Use atomic operations if concurrent
 *			  updates are possible;
 * @conn		- connection which the message was received on;
 * @destructor		- called when a connection is destroyed;
 * @crlf		- pointer to CRLF between headers and body;
 * @body		- contains start of the body of a message and length of
 * 			  whole body. Do not use as regular TfwStr;
 *
 * TfwStr members must be the last for efficient scanning.
 *
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
	TfwStream	*stream;					\
	TfwHttpError	httperr;					\
	TfwCacheControl	cache_ctl;					\
	unsigned char	version;					\
	unsigned int	keep_alive;					\
	TfwMsgIter	iter;						\
	unsigned long	content_length;					\
	unsigned long	jrxtstamp;					\
	DECLARE_BITMAP	(flags, _TFW_HTTP_FLAGS_NUM);			\
	TfwConn		*conn;						\
	void (*destructor)(void *msg);					\
	TfwStr		crlf;						\
	TfwStr		body;


static inline void
tfw_http_copy_flags(unsigned long *to, unsigned long *from)
{
	bitmap_copy(to, from, _TFW_HTTP_FLAGS_NUM);
}

/**
 * A helper structure for operations common for requests and responses.
 * Just don't want to use explicit inheritance.
 */
struct tfw_http_msg_t {
	TFW_HTTP_MSG_COMMON;
};

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
	long		m_date;
} TfwHttpCond;

/**
 * Represents the data that should be cleaned up after message transformation.
 *
 * @skb_head	- head of skb list that must be freed;
 * @pages	- pages that must be freed;
 * @pages_sz	- current number of @pages;
 */
typedef struct {
	struct sk_buff	*skb_head;
	netmem_ref	pages[MAX_SKB_FRAGS];
	unsigned char	pages_sz;
} TfwHttpMsgCleanup;

/**
 * HTTP Request.
 *
 * @vhost	- virtual host for the request;
 * @location	- URI location;
 * @sess	- HTTP session descriptor, required for scheduling;
 * @peer	- end-to-end peer. The peer is not set if
 *		  hop-by-hop peer (TfwConnection->peer) and end-to-end peer are
 *		  the same;
 * @stale_ce	- Stale cache entry retrieved from the cache. Must be assigned
 *		  only when "cache_use_stale" is configured;
 * @cleanup	- Original request data. Required for keeping request data until
 * 		  the response is sent to the client;
 * @pit		- iterator for tracking transformed data allocation (applicable
 *		  for HTTP/2 mode only);
 * @host	- host that was picked from request URI, Host or HTTP/2
 *		  authority header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @multipart_boundary_raw - multipart boundary as is, maybe with escaped chars;
 * @multipart_boundary - decoded multipart boundary;
 * @fwd_list	- member in the queue of forwarded/backlogged requests;
 * @nip_list	- member in the queue of non-idempotent requests;
 * @jtxtstamp	- time the request is forwarded to a server, in jiffies;
 * @tm_header	- time HTTP header started coming. Only rx path;
 * @stale_ce_age - calculated age of stale response. Must be assigned only when
 *		  "cache_use_stale" is configured on tx path with cache;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value for caching calculated for the request;
 * @frang_st	- current state of FRANG classifier;
 * @chunk_cnt	- header or body chunk count for Frang classifier;
 * @host_port	- Port parsed from Host header.
 * @uri_port	- Port parser from request's URI.
 * @node	- NUMA node where request is serviced;
 * @retries	- the number of re-send attempts;
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @method_override - Overridden HTTP request method, passed in request headers;
 * @header_list_sz - total size of headers in bytes;
 * @headers_cnt - total headers count;
 *
 * TfwStr members must be the first for efficient scanning.
 */
struct tfw_http_req_t {
	TFW_HTTP_MSG_COMMON;
	TfwVhost		*vhost;
	TfwLocation		*location;
	TfwHttpSess		*sess;
	TfwClient		*peer;
	void			*stale_ce;
	TfwHttpMsgCleanup	*cleanup;
	TfwHttpCond		cond;
	TfwMsgParseIter		pit;
	HttpTfh			tfh;
	TfwStr			host;
	TfwStr			uri_path;
	TfwStr			multipart_boundary_raw;
	TfwStr			multipart_boundary;
	struct list_head	fwd_list;
	struct list_head	nip_list;
	unsigned long		jtxtstamp;
	union {
		unsigned long		tm_header;
		long			stale_ce_age;
	};
	unsigned long		tm_bchunk;
	unsigned long		hash;
	unsigned int		frang_st;
	unsigned int		chunk_cnt;
	unsigned short		host_port;
	unsigned short		uri_port;
	unsigned short		node;
	unsigned short		retries;
	unsigned char		method;
	unsigned char		method_override;
	unsigned int		header_list_sz;
	unsigned int		headers_cnt;
};

#define TFW_IDX_BITS		24
#define TFW_D_IDX_BITS		8

/**
 * The indirection map entry.
 *
 * @idx		- header index in @h_tbl;
 * @d_idx	- header's order in the array of duplicates of particular
 *		  @h_tbl record.
 */
typedef struct {
	unsigned int	idx	: TFW_IDX_BITS;
	unsigned int	d_idx	: TFW_D_IDX_BITS;
} TfwHdrIndex;

/**
 * Indirection map which links the header's order with its index in @h_tbl.
 *
 * @count	- the actual count of headers in the map (equal to the amount
 *		  of all headers in the message);
 * @size	- the size of the map (in entries);
 * @trailer_idx	- the start index of the trailer section, 0 means no trailers;
 * @index	- array of the indexes (which are located in the order of
 *		  corresponding headers' appearance in the message).
 */
typedef struct {
	unsigned int	size;
	unsigned int	count;
	unsigned int	trailer_idx;
	DECLARE_FLEX_ARRAY(TfwHdrIndex, index);
} TfwHttpHdrMap;

/**
 * Iterator for message HTTP/2 transformation process.
 *
 * @map		- indirection map for tracking headers order in skb;
 * @start_off	- initial offset during copying response data into
 *		  skb (for subsequent insertion of HTTP/2 frame header);
 * @frame_head	- pointer to reserved space for frame header. Used during
 * 		  http2 framing. Simplifies framing of paged SKBs.
 * 		  Framing function may not worry about paged and liner SKBs.
 * @acc_len	- accumulated length of transformed message.
 */
typedef struct {
	TfwHttpHdrMap	*map;
	unsigned int	start_off;
	char		*frame_head;
	unsigned long	acc_len;
} TfwHttpTransIter;

/**
 * HTTP Response.
 * TfwStr members must be the first for efficient scanning.
 *
 * @mit		    - iterator for controlling HTTP/1.1 => HTTP/2 message
 *		      transformation process (applicable for HTTP/2 mode only).
 * @no_cache_tokens - tokens for cache-control directive e.g.
 *		      Cache-Control: no-cache="token1, token2"
 * @private_tokens  - similar to @no_cache_tokens but for private="tokens"
 * @body_start_data - beginning of body used during HTTP1 to HTTP2 body
 *		      transformation. Must be deprecated when new cutting
 *		      strategy will be implemented (TODO #1852);
 * @body_start_skb  - skb with start of the body;
 * @cut 	    - descriptors of http chunked body to be cut during
 *		      HTTP1 to HTTP2 transformation and ignored during
 *		      caching;
 * trailers_len     - length of trailers headers, if present or 0;
 */
struct tfw_http_resp_t {
	TFW_HTTP_MSG_COMMON;
	unsigned short		status;
	long			date;
	long			last_modified;
	TfwHttpTransIter	mit;
	TfwStr			no_cache_tokens;
	TfwStr			private_tokens;
	char			*body_start_data;
	struct sk_buff		*body_start_skb;
	TfwStr			cut;
	int			trailers_len;
};

#define TFW_HDR_MAP_INIT_CNT		32
#define TFW_HDR_MAP_SZ(cnt)		(sizeof(TfwHttpHdrMap)		\
					 + sizeof(TfwHdrIndex) * (cnt))

#define TFW_HTTP_RESP_CUT_BODY_SZ(r) 					\
	(r)->stream ? 							\
	(r)->body.len - (r)->cut.len : 					\
	(r)->body.len

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
	RESP_100,
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

int tfw_http_init(void);
void tfw_http_exit(void);

#define HTTP_CODE_MIN 100
#define HTTP_CODE_MAX 599
#define HTTP_CODE_BIT_NUM(code) ((code) - HTTP_CODE_MIN)

#define T_WARN_ADDR_STATUS(msg, addr_ptr, print_port, status)		\
	TFW_WITH_ADDR_FMT(addr_ptr, print_port, addr_str,		\
			  T_WARN("%s, status %d: %s\n",			\
				 msg, status, addr_str))

static inline int
tfw_http_resp_code_range(const int n)
{
	return n <= HTTP_CODE_MAX && n >= HTTP_CODE_MIN;
}

/*
 * Static index determination for response ':status' pseudo-header (see RFC
 * 7541 Appendix A for details).
 */
static inline unsigned short
tfw_h2_pseudo_index(unsigned short status)
{
	switch (status) {
	case 200:
		return 8;
	case 204:
		return 9;
	case 206:
		return 10;
	case 304:
		return 11;
	case 400:
		return 12;
	case 404:
		return 13;
	case 500:
		return 14;
	default:
		return 0;
	}
}

static inline size_t
tfw_http_req_header_table_size(void)
{
	return TFW_HTTP_HDR_RAW - TFW_HTTP_HDR_REGULAR - 3;
}

static inline size_t
tfw_http_resp_header_table_size(void)
{
	return TFW_HTTP_HDR_RAW - TFW_HTTP_HDR_REGULAR - 2;
}

/**
 * Initialize body iterator. Should be used as helper for iterating over
 * HTTP message body.
 *
 * @it		- Generic message iterator that be used as body iterator.
 * @chunk	- Current body chunk to init.
 * @body_start	- Position in sk_buff @start to start itarating.
 * @start	- sk_buff to start with.
 * @end		- sk_buff where stop itarating. Usually skb_head of message.
 */
static inline int
tfw_body_iter_init(TfwMsgIter* it, TfwStr* chunk, char* body_start,
		   struct sk_buff* start, struct sk_buff* end)
{
	int r;

	it->skb_head = end;
	it->skb = start;
	it->frag = -1;

	/* Set starting position. */
	r = ss_skb_find_frag_by_offset(it->skb, body_start, &it->frag);
	if (unlikely(r))
		return r;

	if (it->frag == -1) {
		unsigned int size = skb_headlen(it->skb);

		chunk->len = (char*)(it->skb->data + size) - body_start;
	} else {
		skb_frag_t *f = &skb_shinfo(it->skb)->frags[it->frag];
		unsigned int size = skb_frag_size(f);

		chunk->len = (char*)(skb_frag_address(f) + size) - body_start;
	}

	chunk->data = body_start;

	return 0;
}

/**
 * Move to next body @chunk for iterator @it.
 */
static inline void
tfw_body_iter_next(TfwMsgIter* it, TfwStr* chunk)
{
	if (++it->frag >= skb_shinfo(it->skb)->nr_frags) {
		it->skb = it->skb->next;
		if (it->skb == it->skb_head) {
			chunk->data = NULL;
			chunk->len = 0;
			return;
		}

		it->frag = -(!!skb_headlen(it->skb));
	}

	if (it->frag == -1) {
		chunk->data = it->skb->data;
		chunk->len = skb_headlen(it->skb);
	} else {
		skb_frag_t *f = &skb_shinfo(it->skb)->frags[it->frag];

		chunk->data = skb_frag_address(f);
		chunk->len = skb_frag_size(f);
	}
}

#define TFW_BODY_ITER_WALK(it, c)					\
	for (; (c)->data; tfw_body_iter_next((it), (c)))

/**
 * Compare the HTTP status with the code parsed from
 * tfw_cfgop_parse_http_status().
 *
 * Wildcarded HTTP code values (of type 4*, 5* etc.) are allowed during
 * configuration, so these values also must be checked via
 * dividing by 100.
 */
static inline bool
tfw_http_status_eq(int status, int code)
{
	return status == code || status / 100 == code;
}

/* Check if a request is non-idempotent. */
static inline bool
tfw_http_req_is_nip(TfwHttpReq *req)
{
	return test_bit(TFW_HTTP_B_NON_IDEMP, req->flags);
}

typedef void (*tfw_http_cache_cb_t)(TfwHttpMsg *);

/**
 * According RFC 9113 6.5.2:
 * Etra 32 extra bytes which are considered the "maximum"
 * overhead that would be required to represent each header
 * entry in the hpack table.
 */
#define HTTP2_EXTRA_HDR_OVERHEAD 32

#define TFW_HTTP_MSG_HDR_OVERHEAD(hmmsg)				\
	(TFW_MSG_H2(hmmsg) ? HTTP2_EXTRA_HDR_OVERHEAD : 0)

extern unsigned int max_header_list_size;
extern bool allow_empty_body_content_type;
extern unsigned int ctrl_frame_rate_mul;
extern unsigned int wnd_update_frame_rate_mul;

/* External HTTP functions. */
int tfw_http_msg_process(TfwConn *conn, struct sk_buff *skb,
			 struct sk_buff **next);
int tfw_http_msg_process_generic(TfwConn *conn, TfwStream *stream,
				 struct sk_buff *skb, struct sk_buff **next);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);
void tfw_http_req_destruct(void *msg);
void tfw_http_resp_fwd(TfwHttpResp *resp);
void tfw_http_resp_build_error(TfwHttpReq *req);
int tfw_cfgop_parse_http_status(const char *status, int *out);
void tfw_http_hm_srv_send(TfwServer *srv, char *data, unsigned long len);
int tfw_h1_add_loc_hdrs(TfwHttpMsg *hm, const TfwHdrMods *h_mods,
			bool from_cache);
int tfw_http_expand_stale_warn(TfwHttpResp *resp);
int tfw_http_expand_hdr_date(TfwHttpResp *resp);
int tfw_http_expand_hbh(TfwHttpResp *resp, unsigned short status);
int tfw_http_expand_hdr_via(TfwHttpResp *resp);
int tfw_http_expand_hdr_server(TfwHttpResp *resp);
void tfw_h2_resp_fwd(TfwHttpResp *resp);
int tfw_h2_hdr_map(TfwHttpResp *resp, const TfwStr *hdr, unsigned int id);
int tfw_h2_add_hdr_date(TfwHttpResp *resp, bool cache);
int tfw_h2_set_stale_warn(TfwHttpResp *resp);
int tfw_h2_resp_add_loc_hdrs(TfwHttpResp *resp, const TfwHdrMods *h_mods,
			     bool cache);
int tfw_h2_resp_status_write(TfwHttpResp *resp, unsigned short status,
			     bool use_pool, bool cache);
int tfw_h2_resp_encode_headers(TfwHttpResp *resp);
/*
 * Functions to send an HTTP error response to a client.
 */
int tfw_http_prep_redir(TfwHttpResp *resp, unsigned short status,
			TfwStr *cookie, TfwStr *body);
int tfw_http_prep_304(TfwHttpReq *req, struct sk_buff **skb_head,
		      TfwHttpMsg *hm);
void tfw_http_conn_msg_free(TfwHttpMsg *hm);
void tfw_http_resp_pair_free_and_put_conn(void *opaque_data);
void tfw_http_send_err_resp(TfwHttpReq *req, int status, const char *reason);

/* Helper functions */
char *tfw_http_msg_body_dup(const char *filename, size_t *len);
unsigned long tfw_http_hdr_split(TfwStr *hdr, TfwStr *name_out, TfwStr *val_out,
				 bool inplace);
unsigned long tfw_h2_hdr_size(unsigned long n_len, unsigned long v_len,
			      unsigned short st_index);
int tfw_h2_frame_local_resp(TfwHttpResp *resp, unsigned long h_len,
			    const TfwStr *body);
int tfw_http_resp_copy_encodings(TfwHttpResp *resp, TfwStr* dst,
				 size_t max_len);
void tfw_http_extract_request_authority(TfwHttpReq *req);
bool tfw_http_mark_is_in_whitlist(unsigned int mark);
char *tfw_http_resp_status_line(int status, size_t *len);
int tfw_http_on_send_resp(void *conn, struct sk_buff **skb_head);

#endif /* __TFW_HTTP_H__ */
