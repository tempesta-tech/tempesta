/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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
	TFW_HTTP_METH_GET	= 0,
	TFW_HTTP_METH_HEAD	= 1,
	TFW_HTTP_METH_POST	= 2,
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
 * @_stashed_st is used to save current state and go to inferior sub-automaton
 * (e.g. process LWS using @state while current state is saved in @_stashed_st
 * or using @_stashed_st parse value of a header described
 */
typedef struct tfw_http_parser {
	unsigned char	flags;
	int		state;		/* current parser state */
	int		_i_st;		/* helping (inferior) state */
	int		data_off;	/* data offset from which the parser
					   starts reading */
	int		to_read;	/* remaining data to read */
	TfwStr		_tmp_chunk;	/* stores begin of currently processed
					   string at the end of last skb */
	TfwStr		hdr;		/* currently parser header */
} TfwHttpParser;

/**
 * Http headers table.
 *
 * Note: don't forget to update hdr_val_eq() upon adding a new header.
 */
typedef enum {
	TFW_HTTP_HDR_CONNECTION,
	TFW_HTTP_HDR_HOST,
	TFW_HTTP_HDR_X_FORWARDED_FOR,

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

#define __HHTBL_SZ(o)			(TFW_HTTP_HDR_NUM * o)
#define TFW_HHTBL_SZ(o)			(sizeof(TfwHttpHdrTbl)		\
					 + sizeof(TfwHttpHdr) * __HHTBL_SZ(o))

/* Common flags for requests and responses. */
#define TFW_HTTP_CONN_CLOSE		0x0001
#define TFW_HTTP_CONN_KA		0x0002
#define __TFW_HTTP_CONN_MASK		(TFW_HTTP_CONN_CLOSE | TFW_HTTP_CONN_KA)
#define TFW_HTTP_CHUNKED		0x0004

#define TFW_HTTP_MSG_COMMON						\
	TfwMsg		msg;						\
	TfwPool		*pool;						\
	TfwHttpHdrTbl	*h_tbl;						\
	TfwHttpParser	parser;						\
	TfwCacheControl	cache_ctl;					\
	unsigned int	flags;						\
	unsigned int	content_length;					\
	TfwConnection	*conn;						\
	unsigned char	*crlf;	/* CRLF between headers and body */	\
	TfwStr		body;


/**
 * A helper structure for operations common for requests and responses.
 * Just don't want to use explicit inheritance.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
} TfwHttpMsg;

/* XXX: the @uri field name is confused. It is not an URI as defined by RFCs,
 * but rather only a part of the URI.
 */
typedef struct {
	TFW_HTTP_MSG_COMMON;
	unsigned char	method;
	TfwStr		host; /* host in URI, may differ from Host header */
	TfwStr		uri;  /* path + query + fragment from URI (RFC3986.3) */
} TfwHttpReq;

typedef struct {
	TFW_HTTP_MSG_COMMON;
	unsigned short	status;
	unsigned int	keep_alive;
	unsigned int	expires;
} TfwHttpResp;

typedef void (*tfw_http_req_cache_cb_t)(TfwHttpReq *, TfwHttpResp *, void *);

/* Internal (parser) HTTP functions. */
void tfw_http_parser_msg_inherit(TfwHttpMsg *hm, TfwHttpMsg *hm_new);
int tfw_http_parse_req(TfwHttpReq *req, unsigned char *data, size_t len);
int tfw_http_parse_resp(TfwHttpResp *resp, unsigned char *data, size_t len);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, unsigned char *data, size_t len);
unsigned long tfw_http_req_key_calc(const TfwHttpReq *req);

#endif /* __TFW_HTTP_H__ */
