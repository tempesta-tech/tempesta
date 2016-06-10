#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdlib.h>
#include <stdio.h>

//something wrong happens with GCC when i try to compile code
//with this on Core i7-4820k: it generates invalid opcodes
//gcc 4.8.4

//#pragma GCC push_options
//#pragma GCC target ("mmx", "avx")
//#define  _MM_MALLOC_H_INCLUDED
#include <tmmintrin.h>
//#undef _MM_MALLOC_H_INCLUDED
//#pragma GCC pop_options

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
    unsigned char       latch16[32] __attribute__((aligned(16)));
    const unsigned char*charset1;
    unsigned char      *header_chunk_start;
    TfwStr             *current_field;
    //FIXME: what can be done to this very-very bad structure?
    //in order to quickly work with headers we need not only
    //TfwStr(it can keep long strings, but also short buffers
    //for typical headers we need to parse
    TfwStr		        hdr;
} TfwHttpParser;

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
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);


#endif // HTTP_PARSER_H

