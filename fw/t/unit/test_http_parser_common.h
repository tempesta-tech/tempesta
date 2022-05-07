/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_PARSER_COMMON_H__
#define __TFW_HTTP_PARSER_COMMON_H__

/*
 * Need to define DEBUG before first the inclusions of
 * lib/log.h and linux/printk.h.
 */
#if DBG_HTTP_PARSER > 0
#undef DEBUG
#define DEBUG DBG_HTTP_PARSER
#endif

#include <linux/types.h>
#include <asm/fpu/api.h>
#include <linux/vmalloc.h>

#include "test.h"
#include "helpers.h"
#include "fuzzer.h"

#ifdef EXPORT_SYMBOL
#undef EXPORT_SYMBOL
#endif
#define EXPORT_SYMBOL(...)

#include "msg.h"
#include "str.h"
#include "http_msg.h"
#include "http_parser.h"
#include "http_sess.h"

static const unsigned int CHUNK_SIZES[] = { 1, 2, 3, 4, 8, 16, 32, 64, 128,
                                   256, 1500, 9216, 1024*1024
                                  /* to fit a message of 'any' size */
                                 };
static unsigned int chunk_size_index = 0;
#define CHUNK_SIZE_CNT ARRAY_SIZE(CHUNK_SIZES)

enum {
	CHUNK_OFF,
	CHUNK_ON
};

#define TOKEN_ALPHABET		"!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQ"	\
				"RSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~"
#define QETOKEN_ALPHABET	TOKEN_ALPHABET "\"="
#define OTHER_DELIMETERS	"(),/:;<=>?@[\\]{}"
#define OBS_TEXT		"\x80\x90\xC8\xAE\xFE\xFF"
#define ETAG_ALPHABET		OTHER_DELIMETERS TOKEN_ALPHABET OBS_TEXT
#define VCHAR_ALPHABET		"\x09 \"" OTHER_DELIMETERS 		\
				TOKEN_ALPHABET OBS_TEXT

#define EXPECT_BLOCK_DIGITS(head, tail, BLOCK_MACRO)		\
	BLOCK_MACRO(head tail);					\
	BLOCK_MACRO(head "  " tail);				\
	BLOCK_MACRO(head "5a" tail);				\
	BLOCK_MACRO(head "\"" tail);				\
	BLOCK_MACRO(head "=" tail);				\
	BLOCK_MACRO(head "-1" tail);				\
	BLOCK_MACRO(head "0.99" tail);				\
	BLOCK_MACRO(head "dummy" tail);				\
	BLOCK_MACRO(head "4294967296" tail);			\
	BLOCK_MACRO(head "9223372036854775807" tail);		\
	BLOCK_MACRO(head "9223372036854775808" tail);		\
	BLOCK_MACRO(head "18446744073709551615" tail);		\
	BLOCK_MACRO(head "18446744073709551616" tail)

#define EXPECT_BLOCK_SHORT(head, tail, BLOCK_MACRO)		\
	BLOCK_MACRO(head "65536" tail);				\
	BLOCK_MACRO(head "2147483647" tail);			\
	BLOCK_MACRO(head "2147483648" tail);			\
	BLOCK_MACRO(head "4294967295" tail)

/* For ETag and If-None-Match headers */
#define COMMON_ETAG_BLOCK(head, BLOCK_MACRO)			\
	BLOCK_MACRO(head "\"dummy");				\
	BLOCK_MACRO(head "dummy\"");				\
	BLOCK_MACRO(head "'dummy'");				\
	BLOCK_MACRO(head "W/ \"dummy\"");			\
	BLOCK_MACRO(head "w/\"dummy\"");			\
	BLOCK_MACRO(head "\"\x00\"");				\
	BLOCK_MACRO(head "\"\x0F\"");				\
	BLOCK_MACRO(head "\"\x7F\"");				\
	BLOCK_MACRO(head "\" \"");				\
	BLOCK_MACRO(head "\"\"\"")

static TfwHttpReq *req, *sample_req;
static TfwHttpResp *resp;
static TfwH2Conn conn;
static TfwStream stream;

/**
 * Reference to a frame of bytes containing the request data to be parsed.
 * Such a frame corresponds to one HTTP request.
 *
 * @len:	frame length in bytes;
 * @str:	pointer to frame;
 * @subtype:	auxiliary field with HTTP/2 frame type that is used only
 *		for HTTP/2 (FUZZ_REQ_H2) requests.
 *
  * Used for types HTTP/1 and HTTP/2 requests.
 */
typedef struct
{
    unsigned int len;
    unsigned char *str;
    TfwFrameType subtype;
} TfwFrameRec;

/**
 * Service data for working with frames inside the framework
 * for building and processing HTTP requests.
 *
 * @frames:		array of TfwFrameRec entries.
 * @frames_cnt:		actual count of entries in @frames;
 * @frames_max_sz:	largest frame size in bytes;
 * @frames_total_sz:	total size of all frames in bytes.
 *
 * ALLOWED_FRAMES_CNT - explicit restriction of allowed frames count.
 *			The value is selected based on the need for test scenarios;
 *
 * Typically, @frames contains logically related entries that need
 * to be parsed during a single call to do_split_and_parse().
 *
 * Used for types HTTP/1 and HTTP/2 requests.
 */
#define ALLOWED_FRAMES_CNT 2
static TfwFrameRec frames[ALLOWED_FRAMES_CNT];
static unsigned int frames_cnt = 0;
static unsigned int frames_max_sz = 0;
static unsigned int frames_total_sz = 0;

/**
 * INIT_FRAMES - initialization of service data for frames
 *		 before the formation of new frames.
 *
 * Used for types HTTP/1 and HTTP/2 requests.
 */
#define INIT_FRAMES()								\
do {										\
	frames_cnt = 0;								\
	frames_max_sz = 0;							\
	frames_total_sz = 0;							\
	bzero_fast(frames, sizeof(frames));					\
} while (0)

#define GET_FRAMES_MAX_SZ() \
	({frames_max_sz;})

#define GET_FRAMES_TOTAL_SZ() \
	({frames_total_sz;})

/**
 * FOR_EACH_FRAME - iterates over the entries in @frames
 *		    and executes a lambda for each entry.
 *
 * To get the current frame in a lambda, you must use the GET_CURRENT_FRAME macro.
 *
 * Used for types HTTP/1 and HTTP/2 requests.
 */
#define FOR_EACH_FRAME(lambda)							\
do {										\
	unsigned int frame_index;						\
	for (frame_index = 0; frame_index < frames_cnt; ++frame_index)		\
		lambda;								\
} while(0)

/**
 * GET_CURRENT_FRAME - returns entry from @frames indexed by @frame_index
 *		       from FOR_EACH_FRAME macro.
 *
 * Used only inside the lambda from FOR_EACH_FRAME macro.
 *
 * Used for types HTTP/1 and HTTP/2 requests.
 */
#define GET_CURRENT_FRAME() \
	({frames[frame_index];})

/**
 * The special "abstract" structure for buffers with different capacity.
 *
 * @capacity:	number of bytes that the buffer has allocated space for;
 * @size:	actual count of bytes that is currently used.
 *		The @size is never can be greater than @capacity;
 * @data[]:	internal bytes array of size @capacity.
 *
 * It is part of DSL framework for building HTTP/2 requests.
 *
 * Such TfwFramesBuf-like buffer is used to store frames sequentially
 * for generated HTTP/2 messages.
 * One buffer can be used for many frames. Typically, the buffer contains several
 * logically related frames that need to be processed
 * in one call to do_split_and_parse().
 *
 * The such buffer is for HTTP/2 messages only generated by .
 * HTTP/1 messages do not need such storage for their content,
 * as they are now specified using static strings (const char*)
 * stored in the global data segment.
 *
 * There is no need to create TfwFramesBuf structures by yourself.
 * A TfwFramesBuf-like buffer must be created by the DECLARE_FRAMES_BUF macro.
 * Inside the DSL framework, the buffer declared
 * with DECLARE_FRAMES_BUF is cast to the TfwFramesBuf type.
 *
 * Used for HTTP/2 requests only.
 */
typedef struct {
	const unsigned int capacity;
	unsigned int size;
	unsigned char data[0];
} TfwFramesBuf;

/**
 * DECLARE_FRAMES_BUF - declaring a TfwFramesBuf-like buffer static instance.
 *
 * @name:	identifier of buffer instance;
 * @max_size:	max allowed size in bytes that can be to store in the buffer.
 *		Other words number of bytes that the buffer has allocated space for.
 *
 * Used for HTTP/2 requests only.
 */
#define DECLARE_FRAMES_BUF(name, max_size)					\
	static struct {								\
		const unsigned int capacity;					\
		unsigned int size;						\
		unsigned char data[max_size];					\
	} __attribute__((unused)) name = {.data = {}, .capacity = max_size, .size = 0}

/**
 * Service data for working with TfwFramesBuf-like buffers inside
 * the DSL framework for building HTTP/2 requests.
 *
 * @frames_buf_ptr:	pointer to TfwFramesBuf-like buffer;
 * @frame_buf:		pointer to write data;
 *
 * The @frames_buf_ptr refers to a TfwFramesBuf-like buffer currently used
 * to store formed frames. @frames_buf_ptr must be set by the SET_FRAMES_BUF
 * macro before the beginning the HTTP/2 message definition block.After
 * the end of the HTTP/2 message definition block, @frames_buf_ptr
 * must be reset by the RESET_FRAMES_BUF macro.
 *
 * The @frame_buf is pointer for positioning inside internal array @data[]
 * of TfwFramesBuf-like buffer. It is used for writing data.
 * Each write operation must self control @frame_buf after use and
 * shift @frame_buf to position next after the end of the data block
 * just written.
 *
 * Used for HTTP/2 requests only.
 */
static TfwFramesBuf *frames_buf_ptr __attribute__((unused)) = NULL;
static unsigned char *frame_buf __attribute__((unused)) = NULL;

/**
 * RESET_FRAMES_BUF - reset current value of @frames_buf_ptr.
 *
 * It is used after the end of the HTTP/2 message definition block.
 *
 * Used for HTTP/2 requests only.
 */
#define RESET_FRAMES_BUF()							\
do {										\
	BUG_ON(!frames_buf_ptr);						\
	frames_buf_ptr = NULL;							\
} while (0)

/**
 * SET_FRAMES_BUF - set @frames_buf_ptr to @frames_buf.
 *
 * @frames_buf:		a TfwFramesBuf-like buffer
 *			declared with DECLARE_FRAMES_BUF macro.
 *
 * It is used befor the beginning of the HTTP/2 message definition block.
 *
 * Used for HTTP/2 requests only.
 */
#define SET_FRAMES_BUF(frames_buf)						\
	BUG_ON(frames_buf_ptr);							\
	frames_buf_ptr = (TfwFramesBuf *) &frames_buf;				\
	frames_buf_ptr->size = 0;						\
	bzero_fast(frames_buf_ptr->data, frames_buf_ptr->capacity)

/**
 * FRAMES_BUF_COMMIT - commit data of a newly formed frame.
 *
 * @frame_sz: size of a newly formed frame.
 *
 * Actually, the size of the newly formed frame is simply added
 * to the size of the TfwFramesBuf-like buffer.
 *
 * Used for HTTP/2 requests only.
 */
#define FRAMES_BUF_COMMIT(frame_sz) \
	frames_buf_ptr->size += frame_sz

/**
 * FRAMES_BUF_POS - return pointer to current commited position
 *		    of the TfwFramesBuf-like buffer.
 *
 * Used for HTTP/2 requests only.
 */
#define FRAMES_BUF_POS() \
	(frames_buf_ptr->data + frames_buf_ptr->size)

/**
 * FRAMES_BUF_END - return pointer to the end of the TfwFramesBuf-like buffer.
 *
 * Used for HTTP/2 requests only.
 */
#define FRAMES_BUF_END() \
	(frames_buf_ptr->data + frames_buf_ptr->capacity)

/**
 * __FRAME_BEGIN - generic macro for mark beginning of frame.
 *
 * @type:	HTTP/2 frame type.
 *
 * Used for HTTP/2 requests only.
 */
#define __FRAME_BEGIN(type)							\
do {										\
	BUG_ON(frames_cnt >= ARRAY_SIZE(frames));				\
	frames[frames_cnt].subtype = type;					\
	frame_buf = FRAMES_BUF_POS();						\
} while (0)

static unsigned int frame_sz_tmp __attribute__((unused)) = 0;

/**
 * __FRAME_END - generic macro for mark end of frame.
 *
 * Used for HTTP/2 requests only.
 */
#define __FRAME_END()								\
do {										\
	BUG_ON(frames_cnt >= ARRAY_SIZE(frames));				\
	BUG_ON(!frame_buf);							\
	frame_sz_tmp = frame_buf - FRAMES_BUF_POS();				\
	frames[frames_cnt].str = FRAMES_BUF_POS();				\
	frames[frames_cnt].len = frame_sz_tmp;					\
	frames_max_sz = max(frames_max_sz, frame_sz_tmp);			\
	frames_total_sz += frame_sz_tmp;					\
	++frames_cnt;								\
	FRAMES_BUF_COMMIT(frame_sz_tmp);					\
} while (0)

/**
 * write_to_frame_data() - write some bytes of data to HPACK frame.
 *
 * @data:	a pointer to data;
 * @size:	a length of data in bytes.
 *
 * This function writes @data in @frame_buf using HPACK format.
 *
 * Used for HTTP/2 requests only.
 */
static
void __attribute__((unused))
write_to_frame_data(char *data, size_t size)
{
	TfwHPackInt hpint;
	write_int(size, 0x7F, 0, &hpint);
	memcpy_fast(frame_buf, hpint.buf, hpint.sz);
	memcpy_fast(frame_buf + hpint.sz, data, size);
	frame_buf += hpint.sz + size;
}

/**
 * VALUE - write string to HEADERS-frame (without Haffman encoding).
 *
 * @str:	a C-like static string.
 *
 * Used for HTTP/2 requests only.
 */
#define VALUE(str) \
	write_to_frame_data(str, SLEN(str))

/**
 * VALUE_RAW - write some bytes to HEADERS-frame.
 *
 * @data:	an array with data.
 *
 * Used for HTTP/2 requests only.
 */
#define VALUE_RAW(data) \
	write_to_frame_data(data, sizeof(data))

/**
 * write_to_frame_index() - write index to HPACK frame.
 *
 * @index:	index value;
 * @max:	max value of the prefix.
 * @mask:	n-bit pattern followed by prefix;
 *
 * This function writes @index in @frame_buf using HPACK format.
 *
 * Used for HTTP/2 requests only.
 */
static
void __attribute__((unused))
write_to_frame_index(unsigned long index,
		     unsigned short max,
		     unsigned short mask)
{
	TfwHPackInt hpint;
	write_int(index, max, mask, &hpint);
	memcpy_fast(frame_buf, hpint.buf, hpint.sz);
	frame_buf += hpint.sz;
}

/**
 * __INDEX - write index to HEADERS-frame like integer representation.
 *
* @index:	index value;
 * @max:	max value of the prefix.
 * @mask:	n-bit pattern ollowed by prefix;
 *
 * There is no need to use __INDEX macro directly.
 * Use XXX_IND-families macro or INDEX macro.
 *
 * Used for HTTP/2 requests only.
 */
#define __INDEX(index, max, mask) \
	write_to_frame_index(index, max, mask)

/**
 * __NAME - write header name filed to HEADERS-frame
 *	    like string representation.
 *
 * @hdr_name:	pointer to string buffer with header name;
 * @mask:	n-bit pattern followed by the header field name.
 *
 * There is no need to use __NAME macro directly.
 * Use XXX_IND-families macro.
 *
 * Used for HTTP/2 requests only.
 */
#define __NAME(hdr_name, mask)							\
do {										\
	*frame_buf++ = mask;							\
	VALUE(hdr_name);							\
} while (0)

/**
 * HEADERS_FRAME_BEGIN - mark beginning of HEADERS-frame.
 *
 * Used for HTTP/2 requests only.
 */
#define HEADERS_FRAME_BEGIN() \
	__FRAME_BEGIN(HTTP2_HEADERS)

/**
 * HEADER - auxiliary macro to separate header fields
 *	    during defining an HTTP/2 message.
 *
 * @header_desc:	a description of header field.
 *
 * Used for HTTP/2 requests only.
 */
#define HEADER(header_desc)							\
do {										\
	BUG_ON(!frame_buf);							\
	header_desc;								\
	BUG_ON(frame_buf > FRAMES_BUF_END());					\
} while (0)

/**
 * HEADERS_FRAME_END - mark end of HEADERS-frame.
 *
 * Used for HTTP/2 requests only.
 */
#define HEADERS_FRAME_END() \
	__FRAME_END()

/**
 * INDEX - specifying indexed representation in the header field.
 *
 * @index:	index value.
 *
 * Used for:
 * - indicating Indexed Header Field Representation in HTTP/2 header field.
 *   Example of usage:	HEADER(INDEX(2));
 * - specify to indexed name in XXX_IND-families macro.
 *   Example of usage:	HEADER(XXX_IND(INDEX(2), VALUE("POST"))).
 *
 * Used for HTTP/2 requests only.
 */
#define INDEX(index)	__INDEX((index), 0x7F, 0x80)

/**
 * NAME - specifying named representation in the header field.
 *
 * Used for XXX_IND-families macro.
 * Example of usage:	HEADER(XXX_IND(NAME(":method"), VALUE("POST"))).
 *
 * Used for HTTP/2 requests only.
 */
#define NAME(data)

/**
 * Literal Header Field with Incremental Indexing.
 * Example of usage:
 * - Indexed Name:	HEADER(INC_IND(INDEX(2), VALUE("POST")));
 * - New Name:		HEADER(INC_IND(NAME(":method"), VALUE("POST"))).
 *
 * Used for HTTP/2 requests only.
 */
#define INC_IND_BY_INDEX(data)	__INDEX((data), 0x3F, 0x40)
#define INC_IND_BY_NAME(data)	__NAME((data), 0x40)
#define INC_IND(name_desc, value_desc)						\
do {										\
	INC_IND_BY_##name_desc;							\
	value_desc;								\
} while (0)

/**
 * Literal Header Field without Indexing.
 * Example of usage:
 * - Indexed Name:	HEADER(WO_IND(INDEX(2), VALUE("POST")));
 * - New Name:		HEADER(WO_IND(NAME(":method"), VALUE("POST"))).
 *
 * Used for HTTP/2 requests only.
 */
#define WO_IND_BY_INDEX(data)	__INDEX((data), 0x0F, 0)
#define WO_IND_BY_NAME(data)	__NAME((data), 0)
#define WO_IND(name_desc, value_desc)						\
do {										\
	WO_IND_BY_##name_desc;							\
	value_desc;								\
} while (0)

/**
 * Literal Header Field Never Indexed.
 * Example of usage:
 * - Indexed Name:	HEADER(NEV_IND(INDEX(2), VALUE("POST")));
 * - New Name:		HEADER(NEV_IND(NAME(":method"), VALUE("POST"))).
 *
 * Used for HTTP/2 requests only.
 */
#define NEV_IND_BY_INDEX(data)	__INDEX((data), 0x0F, 0x10)
#define NEV_IND_BY_NAME(data)	__NAME((data), 0x10)
#define NEV_IND(name_desc, value_desc)						\
do {										\
	NEV_IND_BY_##name_desc;							\
	value_desc;								\
} while (0)

#define SZ_UPD(size) __INDEX((size), 0x1F, 0x20)

/**
 * Dynamic Table Size Update.
 * Example of usage:		HEADER(SZ_UPD(new_size)).
 *
 * Used for HTTP/2 requests only.
 */
#define SZ_UPD(size) __INDEX((size), 0x1F, 0x20)

/**
 * DATA_FRAME_BEGIN - mark beginning of DATA-frame.
 *
 * Used for HTTP/2 requests only.
 */
#define DATA_FRAME_BEGIN() \
	__FRAME_BEGIN(HTTP2_DATA)

/**
 * DATA - write some bytes to DATA-frame.
 *
 * Used for HTTP/2 requests only.
 */
#define DATA(data)								\
do {										\
	unsigned int data_len;							\
	BUG_ON(!frame_buf);							\
	data_len = SLEN(data);							\
	memcpy_fast(frame_buf, data, data_len);					\
	frame_buf += data_len;							\
	BUG_ON(frame_buf > FRAMES_BUF_END());					\
} while (0)

/**
 * DATA_FRAME_END - mark end of DATA-frame.
 *
 * Used for HTTP/2 requests only.
 */
#define DATA_FRAME_END() \
	__FRAME_END()

/**
 * ADD_HEADERS_FRAME - add HEADERS-frame to @frames.
 *
 * @frame_buf:		a pointer to external buffer with HEADERS-frame payload.
 * @frame_sz:		a size of HEADERS-frame payload in bytes.
 *
 * Used for HTTP/2 requests only.
 */
#define ADD_HEADERS_FRAME(frame_buf, frame_sz)					\
do {										\
	BUG_ON(frames_cnt >= ARRAY_SIZE(frames));				\
	bzero_fast(&frames[frames_cnt], sizeof(frames[0]));			\
	frames[frames_cnt].subtype = HTTP2_HEADERS;				\
	frames[frames_cnt].str = frame_buf;					\
	frames[frames_cnt].len = frame_sz;					\
	frames_max_sz = max(frames_max_sz, frame_sz);				\
	frames_total_sz += frame_sz;						\
	++frames_cnt;								\
} while(0)

/**
 * ADD_DATA_FRAME - add DATA-frame to @frames.
 *
 * @frame_buf:		a pointer to external buffer with DATA-frame payload.
 * @frame_sz:		a size of DATA-frame payload in bytes.
 *
 * Used for HTTP/2 requests only.
 */
#define ADD_DATA_FRAME(frame_buf, frame_sz)					\
do {										\
	BUG_ON(frames_cnt >= ARRAY_SIZE(frames));				\
	bzero_fast(&frames[frames_cnt], sizeof(frames[0]));			\
	frames[frames_cnt].subtype = HTTP2_DATA;				\
	frames[frames_cnt].str = frame_buf;					\
	frames[frames_cnt].len = frame_sz;					\
	frames_max_sz = max(frames_max_sz, frame_sz);				\
	frames_total_sz += frame_sz;						\
	++frames_cnt;								\
} while(0)

/**
 * ASSIGN_FRAMES_FOR_H1 - assign HTTP/1 request to @frames.
 *
 * @str_buf:		a pointer to external buffer with HTTP/1 request.
 * @str_len:		a size of request in bytes.
 *
 * Used for HTTP/1 requests only.
 */
#define ASSIGN_FRAMES_FOR_H1(str_buf, str_len)					\
do {										\
	bzero_fast(frames, sizeof(frames));					\
	frames_cnt = 1;								\
	frames[0].str = str_buf;						\
	frames[0].len = str_len;						\
	frames_max_sz = str_len;						\
	frames_total_sz = str_len;						\
} while(0)

/**
 * ASSIGN_FRAMES_FOR_H2 - assign HTTP/2 frame(s) to @frames.
 *
 * @frames_definition:	a description of HTTP/2 frame(s).
 *
 * Used for HTTP/2 requests only.
 */
#define ASSIGN_FRAMES_FOR_H2(frames_definition)					\
do {										\
	INIT_FRAMES();								\
	SET_FRAMES_BUF(frames_buf);						\
	frames_definition;							\
	RESET_FRAMES_BUF();							\
} while(0)

DECLARE_FRAMES_BUF(frames_buf, 3 * 1024);

static int
split_and_parse_n(unsigned char *str, int type, size_t len, size_t chunk_size)
{
	size_t pos = 0;
	unsigned int parsed;
	int r = TFW_PASS;
	TfwHttpMsg *hm = (type == FUZZ_RESP)
			? (TfwHttpMsg *)resp
			: (TfwHttpMsg *)req;

	BUG_ON(type != FUZZ_REQ && type != FUZZ_REQ_H2 && type != FUZZ_RESP);

	TEST_DBG3("%s: len=%zu, chunk_size=%zu\n", __func__, len, chunk_size);

	while (pos < len) {
		if (chunk_size >= len - pos)
			/* At the last chunk */
			chunk_size = len - pos;
		TEST_DBG3("%s: len=%zu pos=%zu\n",  __func__, len, pos);

		if (type == FUZZ_REQ)
			r = tfw_http_parse_req(req, str + pos, chunk_size, &parsed);
		else if (type == FUZZ_REQ_H2)
			r = tfw_h2_parse_req(req, str + pos, chunk_size, &parsed);
		else
			r = tfw_http_parse_resp(resp, str + pos, chunk_size, &parsed);

		pos += chunk_size;
		hm->msg.len += parsed;

		BUILD_BUG_ON((int)TFW_POSTPONE != (int)T_POSTPONE);
		if (r != TFW_POSTPONE)
			return r;
	}
	BUG_ON(pos != len);

	return r;
}

/**
 * Response must be paired with request to be parsed correctly. Update sample
 * request for further response parsing.
 */
static int __attribute__((unused))
set_sample_req(unsigned char *str)
{
	size_t len = strlen(str);
	unsigned int parsed;

	if (sample_req)
		test_req_free(sample_req);

	sample_req = test_req_alloc(len);

	return tfw_http_parse_req(sample_req, str, len, &parsed);
}

static void __attribute__((unused))
test_case_parse_prepare_http(char *str)
{
	ASSIGN_FRAMES_FOR_H1(str, strlen(str));
}

static void __attribute__((unused))
test_case_parse_prepare_h2(void)
{
	tfw_h2_context_init(&conn.h2);
	conn.h2.hdr.type = HTTP2_HEADERS;
	stream.state = HTTP2_STREAM_REM_HALF_CLOSED;
}

/**
 * The function is designed to be called in a loop, e.g.
 *   while(!do_split_and_parse(str, len, type, chunk_mode)) { ... }
 *
 * type may be FUZZ_REQ or FUZZ_REQ_H2 or FUZZ_RESP.
 *
 * On each iteration it splits the @str into fragments and pushes
 * them to the HTTP parser.
 *
 * That is done because:
 *  - HTTP pipelining: the feature implies that such a "split" may occur at
 *    any position of the input string. THe HTTP parser should be able to handle
 *    that, and we would like to test it.
 *  - Code coverage: the parser contains some optimizations for non-fragmented
 *    data, so we need to generate all possible fragments to test both "fast
 *    path" and "slow path" execution.
 *
 * The function is stateful:
 *  - It puts the parsed request or response to the global variable
 *  @req or @resp (on each call, depending on the message type).
 *  - It maintains the internal state between calls.
 *
 * Return value:
 *  == 0 - OK: current step of the loop is done without errors, proceed.
 *  <  0 - Error: the parsing is failed.
 *  >  0 - EOF: all possible fragments are parsed, terminate the loop.
 */
static int
do_split_and_parse(int type, int chunk_mode)
{
	int r;
	unsigned int chunk_size;

	if (chunk_size_index == CHUNK_SIZE_CNT)
		/*
		 * Return any positive value to indicate that
		 * all defined chunk sizes were tested and
		 * no more iterations needed.
		 */
		return 1;

	if (type == FUZZ_REQ) {
		if (req)
			test_req_free(req);

		req = test_req_alloc(GET_FRAMES_TOTAL_SZ());
	}
	else if (type == FUZZ_REQ_H2) {
		/*
		 * During the processing of a request, the HPACK dynamic table
		 * is modified. The same query is used for each chunk size.
		 * At the same time, the HPACK dynamic table does not have
		 * the property of idempotence. At least for this reason,
		 * for each chunk size, we need to use the initial state
		 * of the context that came to the input of the function.
		 */
		static TfwH2Ctx	h2_origin;
		if (chunk_size_index == 0)
			h2_origin = conn.h2;
		else
			conn.h2 = h2_origin;

		conn.h2.hpack.state = 0;
		conn.h2.hpack.length = 0;

		if (req)
			test_req_free(req);
		req = test_req_alloc(GET_FRAMES_TOTAL_SZ());
		req->conn = (TfwConn*)&conn;
		req->pit.parsed_hdr = &stream.parser.hdr;
		req->stream = &stream;
		tfw_http_init_parser_req(req);
		stream.msg = (TfwMsg*)req;
		req->pit.pool = __tfw_pool_new(0);
		BUG_ON(!req->pit.pool);
		__set_bit(TFW_HTTP_B_H2, req->flags);
	}
	else if (type == FUZZ_RESP) {
		if (resp)
			test_resp_free(resp);

		resp = test_resp_alloc(GET_FRAMES_TOTAL_SZ());
		tfw_http_msg_pair(resp, sample_req);
	}
	else {
		BUG();
	}

	chunk_size = chunk_mode == CHUNK_OFF
			? GET_FRAMES_MAX_SZ()
			: CHUNK_SIZES[chunk_size_index];

	TEST_DBG3("%s: chunk_mode=%d, chunk_size_index=%u, chunk_size=%u\n",
		    __func__, chunk_mode, chunk_size_index, chunk_size);

	FOR_EACH_FRAME({
		TfwFrameRec frame = GET_CURRENT_FRAME();

		if (type == FUZZ_REQ_H2) {
			TfwH2Ctx *ctx = tfw_h2_context(req->conn);
			ctx->hdr.type = frame.subtype;
			ctx->plen = frame.len;
		}

		if (type == FUZZ_REQ_H2
		    && frame.subtype == HTTP2_DATA
		    && !frame.len)
		{
			r = TFW_POSTPONE;
		}
		else
		{
			r = split_and_parse_n(frame.str, type, frame.len, chunk_size);
		}

		if (r != TFW_POSTPONE)
			break;

		if (type == FUZZ_REQ_H2 && frame.subtype == HTTP2_HEADERS) {
			if (!tfw_http_parse_check_bodyless_meth(req)) {
				__set_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags);
			}
			else
			{
				r = TFW_BLOCK;
				break;
			}
		}
	});

	if (type == FUZZ_REQ_H2 && r == TFW_POSTPONE) {
		r = tfw_h2_parse_req_finish(req);
	}

	if (chunk_mode == CHUNK_OFF
	    || CHUNK_SIZES[chunk_size_index] >= GET_FRAMES_MAX_SZ())
		/*
		 * Stop splitting message into pieces bigger than
		 * the message itself.
		 */
		chunk_size_index = CHUNK_SIZE_CNT;
	else
		/* Try next size, if any. on next interation */
		chunk_size_index++;

	return r;
}

/**
 * To validate message parsing we provide text string which describes
 * HTTP message from start to end. If there any unused bytes after
 * message is successfully parsed, then parsing was incorrect.
 */
static
int __attribute__((unused))
validate_data_fully_parsed(int type, size_t sz_diff)
{
	TfwHttpMsg *hm = (type == FUZZ_REQ || type == FUZZ_REQ_H2)
			? (TfwHttpMsg *)req
			: (TfwHttpMsg *)resp;

	size_t hm_exp_len = GET_FRAMES_TOTAL_SZ() - sz_diff;

	EXPECT_EQ(hm->msg.len, hm_exp_len);
	return hm->msg.len == hm_exp_len;
}

#define __TRY_PARSE_EXPECT_PASS(type, sz_diff, chunk_mode)		\
chunk_size_index = 0;							\
while (({								\
	int _err = do_split_and_parse(type, chunk_mode);		\
	if (_err == TFW_BLOCK || _err == TFW_POSTPONE			\
	    || !validate_data_fully_parsed(type, sz_diff))		\
		TEST_FAIL("can't parse %s (code=%d)\n",			\
			  (type == FUZZ_REQ	    			\
			   || type == FUZZ_REQ_H2			\
			   ? "request" : "response"),			\
			  _err);					\
	__fpu_schedule();						\
	_err == TFW_PASS;						\
}))

#define TRY_PARSE_EXPECT_PASS(type, chunk_mode) \
	__TRY_PARSE_EXPECT_PASS(type, 0, chunk_mode)

#define TRY_PARSE_EXPECT_BLOCK(type, chunk_mode)			\
chunk_size_index = 0;							\
while (({								\
	int _err = do_split_and_parse(type, chunk_mode);		\
	if (_err == TFW_PASS)						\
		TEST_FAIL("%s is not blocked as expected\n",		\
			  (type == FUZZ_REQ				\
			   || type == FUZZ_REQ_H2			\
			   ? "request" : "response"));			\
	__fpu_schedule();						\
	_err == TFW_BLOCK || _err == TFW_POSTPONE;			\
}))

#define PRINT_REQ(str)	TEST_LOG("h1 req: [%s]\n", str)

#define PRINT_REQ_H2()							\
do {									\
    BUG_ON(frames_cnt == 0);						\
    print_hex_dump(KERN_INFO, TEST_BANNER "h2 req: ", DUMP_PREFIX_NONE,	\
		   32, 1, frames[0].str, min_t(size_t, frames[0].len, 32U),\
		   true);						\
} while (0)

#define __FOR_REQ(str, sz_diff, chunk_mode)				\
	PRINT_REQ(str);							\
	test_case_parse_prepare_http(str);				\
	__TRY_PARSE_EXPECT_PASS(FUZZ_REQ, sz_diff, chunk_mode)

#define FOR_REQ(str)							\
	__FOR_REQ(str, 0, CHUNK_ON)

#define FOR_REQ_H2(frames_definition)					\
	ASSIGN_FRAMES_FOR_H2(frames_definition);			\
	PRINT_REQ_H2();							\
	test_case_parse_prepare_h2();					\
	TRY_PARSE_EXPECT_PASS(FUZZ_REQ_H2, CHUNK_ON)

#define FOR_REQ_H2_HPACK(frames_definition)				\
	ASSIGN_FRAMES_FOR_H2(frames_definition);			\
	PRINT_REQ_H2();							\
	TRY_PARSE_EXPECT_PASS(FUZZ_REQ_H2, CHUNK_ON)

#define EXPECT_BLOCK_REQ(str)						\
do {									\
	PRINT_REQ(str);							\
	test_case_parse_prepare_http(str);				\
	TRY_PARSE_EXPECT_BLOCK(FUZZ_REQ, CHUNK_ON);			\
} while (0)

#define EXPECT_BLOCK_REQ_H2(frames_definition)				\
do {									\
	ASSIGN_FRAMES_FOR_H2(frames_definition);			\
	PRINT_REQ_H2();							\
	test_case_parse_prepare_h2();					\
	TRY_PARSE_EXPECT_BLOCK(FUZZ_REQ_H2, CHUNK_ON);			\
} while (0)

#define EXPECT_BLOCK_REQ_H2_HPACK(frames_definition)			\
do {									\
	ASSIGN_FRAMES_FOR_H2(frames_definition);			\
	PRINT_REQ_H2();							\
	TRY_PARSE_EXPECT_BLOCK(FUZZ_REQ_H2, CHUNK_ON);			\
} while (0)

#define __FOR_RESP(str, sz_diff, chunk_mode)				\
	TEST_LOG("=== response: [%s]\n", str);				\
	test_case_parse_prepare_http(str);				\
	__TRY_PARSE_EXPECT_PASS(FUZZ_RESP, sz_diff, chunk_mode)

#define FOR_RESP(str)	__FOR_RESP(str, 0, CHUNK_ON)

#define EXPECT_BLOCK_RESP(str)						\
do {									\
	TEST_LOG("=== response: [%s]\n", str);				\
	test_case_parse_prepare_http(str);				\
	TRY_PARSE_EXPECT_BLOCK(FUZZ_RESP, CHUNK_ON);			\
} while (0)

#define EXPECT_TFWSTR_EQ(tfw_str, cstr)					\
	EXPECT_TRUE(tfw_str_eq_cstr(tfw_str, cstr, strlen(cstr), 0))

/*
 * Test that the parsed string was split to the right amount of chunks and all
 * the chunks has the same flags.
 */
static void __attribute__((unused))
test_string_split(const TfwStr *expected, const TfwStr *parsed)
{
	TfwStr *end_p, *end_e, *c_p, *c_e;

	BUG_ON(TFW_STR_PLAIN(expected));
	EXPECT_FALSE(TFW_STR_PLAIN(parsed));
	if (TFW_STR_PLAIN(parsed))
		return;

	EXPECT_GE(parsed->nchunks, expected->nchunks);
	EXPECT_EQ(parsed->len, expected->len);
	if (parsed->len != expected->len)
		return;

	c_p = parsed->chunks;
	end_p = c_p + parsed->nchunks;
	c_e = expected->chunks;
	end_e = c_e + expected->nchunks;

	while (c_e < end_e) {
		unsigned short flags = c_e->flags;
		TfwStr e_part = { .chunks = c_e }, p_part = { .chunks = c_p };

		while ((c_e < end_e) && (c_e->flags == flags)) {
			e_part.nchunks++;
			e_part.len += c_e->len;
			c_e++;
		}
		while ((c_p < end_p) && (c_p->flags == flags)) {
			p_part.nchunks++;
			p_part.len += c_p->len;
			c_p++;
		}
		EXPECT_EQ(p_part.len, e_part.len);
		if (p_part.len != e_part.len)
			return;
		EXPECT_OK(tfw_strcmp(&e_part, &p_part));
	}
	EXPECT_EQ(c_p, end_p);
	EXPECT_EQ(c_e, end_e);
}

static inline int
number_to_strip(TfwHttpReq *req)
{
	return
		!!test_bit(TFW_HTTP_B_NEED_STRIP_LEADING_CR, req->flags) +
		!!test_bit(TFW_HTTP_B_NEED_STRIP_LEADING_LF, req->flags);
}

static TfwStr __attribute__((unused))
get_next_str_val(TfwStr *str)
{
	TfwStr v, *c, *end;
	unsigned int nchunks = 0;

	v = *str = tfw_str_next_str_val(str);
	TFW_STR_FOR_EACH_CHUNK(c, &v, end) {
		if (!(c->flags & TFW_STR_VALUE))
			break;
		nchunks++;
	}
	v.nchunks = nchunks;

	return v;
}

#define TFW_HTTP_SESS_REDIR_MARK_ENABLE()					\
do {										\
	TfwMod *hs_mod = NULL;							\
	hs_mod = tfw_mod_find("http_sess");					\
	BUG_ON(!hs_mod);							\
	tfw_http_sess_redir_enable();						\
	hs_mod->start();							\
} while (0)

#define TFW_HTTP_SESS_REDIR_MARK_DISABLE()					\
do {										\
	TfwMod *hs_mod = NULL;							\
	hs_mod = tfw_mod_find("http_sess");					\
	BUG_ON(!hs_mod);							\
	hs_mod->stop();								\
	hs_mod->cfgstart();							\
} while (0)

#endif /* __TFW_HTTP_PARSER_COMMON_H__ */
