#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdlib.h>
#include <stdio.h>
#include "str.h"

//something wrong happens with GCC when i try to compile code
//with this on Core i7-4820k: it generates invalid opcodes
//gcc 4.8.4

//#pragma GCC push_options
//#pragma GCC target ("mmx", "avx")
//#define  _MM_MALLOC_H_INCLUDED
#include <tmmintrin.h>
//#undef _MM_MALLOC_H_INCLUDED
//#pragma GCC pop_options


typedef enum {
    TFW_HTTP_METH_NONE,
    TFW_HTTP_METH_GET,
    TFW_HTTP_METH_HEAD,
    TFW_HTTP_METH_POST,
    TFW_HTTP_METH_PUT,
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


/**
 * A generic approach to SSE parser is incompatible with
 * current Tempesta design, because it makes us to do a LOT
 * of bookkeeping work to keep string fixups in place.
 *
 * In order to avoid this situation, we have to
 * a) rework header structure to make it less specific to
 * b) perform less efficient comparison-by-charset
 *    rather than specific per-state checks
 *
 * @state	- current parser state;
 * @charset1- pointer to SSE charset structures
 *            parser uses them to calculate amount of
 *            symbols to be consumed at any arbitrary stage
 *            without diving into switch
 * @bytes_cached - bytes stored in latch16
 * @bytes_shifted - bytes in front of latch16 which were consumed
 *            on previous iteration
 * @latch16 - aligned storage for managing sse data on interstage
 *            transitions
 * @current_field-
 * @aux_field-pointer to currently filled TfwStrs, which may require
 *            fixups on packet edges
 * @hdr		- currently parsed header.
 */
typedef struct {
    int		            state;
    int                 bytes_cached, bytes_shifted;
    const unsigned char*charset1;
    unsigned char      *header_chunk_start;
    TfwStr             *current_field;
    //FIXME: what can be done to this very-very bad structure?
    //in order to quickly work with headers we need not only
    //TfwStr(it can keep long strings, but also short buffers
    //for typical headers we need to parse
    TfwStr		        hdr;
    unsigned char       guard1[64] __attribute__((aligned(64)));
    unsigned char       latch16[16] __attribute__((aligned(64)));
    unsigned char       guard2[64] __attribute__((aligned(64)));
} TfwHttpParser;

/**
 * @msg_list	- messages queue to send to peer;
 * @state	- message processing state;
 * @skb_list	- list of sk_buff's belonging to the message;
 * @len		- total body length;
 */
typedef struct {
} TfwMsg;

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

#define TFW_HTTP_MSG_COMMON						\
    TfwMsg		msg;						\
    TfwPool		*pool;						\
    TfwHttpHdrTbl	*h_tbl;						\
    TfwHttpParser	parser;						\
    unsigned char	version;					\
    unsigned long	content_length;					\
    TfwStr		crlf;						\
    TfwStr		body;

typedef struct {
    TFW_HTTP_MSG_COMMON;
} TfwHttpMsg;

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


int
tfw_http_parse_req(void * restrict req_data, unsigned char * restrict data, size_t len);
int
tfw_http_parse_header(void *req_data, unsigned char *data, size_t len);

int
tfw_http_parse_req_ff(void * restrict req_data, unsigned char * restrict data, size_t len);
int
tfw_http_parse_header_ff(void *req_data, unsigned char *data, size_t len);

#endif // HTTP_PARSER_H

