#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdlib.h>
#include <stdio.h>

//#pragma GCC push_options
//#pragma GCC target ("mmx", "avx")
//#define  _MM_MALLOC_H_INCLUDED
#include <tmmintrin.h>
//#undef _MM_MALLOC_H_INCLUDED
//#pragma GCC pop_options

enum {
    TFW_BLOCK,
    TFW_POSTPONE,
    TFW_PASS
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


typedef enum {
    TFW_STR_EMPTY,
    TFW_STR_OPEN,
    TFW_STR_CLOSED
} tfw_str_flags_t;

typedef struct {
    //empty
}TfwPool;

typedef struct {
    tfw_str_flags_t  flags;
    unsigned char ** chunks;
    int    num_chunks;
} TfwStr;

typedef struct {
    //empty
} TfwMsg;

typedef struct {
    //empty
} TfwHttpHdrTbl;

typedef struct {
    //empty
} TfwCacheControl;

typedef struct {
    //empty
} TfwConnection;

typedef struct {
    unsigned short	to_go;
    int		state;
    int		_i_st;
    int		to_read;
    unsigned long	_acc;
    unsigned long	_eol;
    unsigned int	_hdr_tag;
    TfwStr		_tmp_chunk;
    TfwStr		hdr;
} TfwHttpParser;

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


typedef struct {
    TFW_HTTP_MSG_COMMON;
} TfwHttpMsg;

typedef struct {
    TFW_HTTP_MSG_COMMON;

    TfwStr			    userinfo;
    TfwStr			    host;
    TfwStr			    uri_path;
    tfw_http_meth_t		method;
    //unsigned short		node;
    //unsigned int		frang_st;
    //unsigned int		chunk_cnt;
    //unsigned long		tm_header;
    //unsigned long		tm_bchunk;
    //unsigned long		hash;
    //sse part
    unsigned char       latch16[32] __attribute__((aligned(16)));
    int                 bytes_cached, bytes_shifted;

    TfwStr             *current_field;
    unsigned char      *current_field_tail;
    unsigned char      *current_header_head;
    int                 current_header_len;
} TfwHttpReq;

int
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);


#endif // HTTP_PARSER_H

