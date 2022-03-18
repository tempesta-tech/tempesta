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

#include "http_parser.h"
#include "http_sess.h"
#include "str.h"
#include "ss_skb.h"
#include "msg.h"
#include "http_msg.h"

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

static TfwHttpReq *req, *sample_req;
static TfwHttpResp *resp;
static TfwH2Conn conn;
static TfwStream stream;
static char h2_buf[1024];
static unsigned int h2_len = 0;
static size_t hm_exp_len = 0;

#define SAMPLE_REQ_STR	"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

#define TOKEN_ALPHABET		"!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQ"	\
				"RSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~"
#define QETOKEN_ALPHABET	TOKEN_ALPHABET "\"="
#define OTHER_DELIMETERS	"(),/:;<=>?@[\\]{}"
#define OBS_TEXT		"\x80\x90\xC8\xAE\xFE\xFF"
#define VCHAR_ALPHABET		"\x09 \"" OTHER_DELIMETERS 		\
				TOKEN_ALPHABET OBS_TEXT
#define ETAG_ALPHABET		OTHER_DELIMETERS TOKEN_ALPHABET OBS_TEXT

static
unsigned int
tfw_h2_encode_str(const char *str, char *buf)
{
	TfwHPackInt hpint;
	unsigned int len = strlen(str);
	write_int(len, 0x7f, 0, &hpint);
	memcpy_fast(buf, hpint.buf, hpint.sz);
	memcpy_fast(buf + hpint.sz, str, len);
	return hpint.sz + len;
}

#define H2_HDR_HDR_SZ 9
#define LIT_HDR_FLD_WO_IND 0x00
static
unsigned int
tfw_h2_pack_hdr_frame(const char *str, char buf[], unsigned int buf_len)
{
	unsigned long hdrs_len = 0;
	TfwFrameHdr frame_hdr = {.flags = HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM,
							 .type = HTTP2_HEADERS,
							 .stream_id = 1};
	char **strp, *hdr_one, *hdr, **hdrp, *hdr_val;
	char str_buf[256] = {0};
	char *_str = str_buf;

	BUG_ON(strlen(str) + 1 > ARRAY_SIZE(str_buf));

	memcpy_fast(_str, str, strlen(str));

	strp = &_str;
	do {
		hdr_one = strsep(strp, "\n");
		hdr = hdr_one;
		if (*hdr == ':') {
			if (!*(++hdr))
				continue;
		}
		hdrp = &hdr;
		strsep(hdrp, ":");
		hdr_val = hdrp ? strim(*hdrp) : "";
		*(buf + H2_HDR_HDR_SZ + hdrs_len++) = LIT_HDR_FLD_WO_IND;
		hdrs_len += tfw_h2_encode_str(hdr_one,
					      buf + H2_HDR_HDR_SZ + hdrs_len);
		hdrs_len += tfw_h2_encode_str(hdr_val,
					      buf + H2_HDR_HDR_SZ + hdrs_len);
	} while (*strp);

	frame_hdr.length = hdrs_len;
	tfw_h2_pack_frame_header(buf, &frame_hdr);

	BUG_ON(frame_hdr.length + H2_HDR_HDR_SZ > buf_len);
	return frame_hdr.length + H2_HDR_HDR_SZ;
}

static int
split_and_parse_n(unsigned char *str, int type, size_t len, size_t chunk_size)
{
	size_t pos = 0;
	unsigned int parsed;
	int r = 0;
	TfwHttpMsg *hm = (type == FUZZ_RESP)
			? (TfwHttpMsg *)resp
			: (TfwHttpMsg *)req;

	BUG_ON(type != FUZZ_REQ && type != FUZZ_REQ_H2 && type != FUZZ_RESP);
	while (pos < len) {
		if (chunk_size >= len - pos)
			/* At the last chunk */
			chunk_size = len - pos;
		TEST_DBG3("split: len=%zu pos=%zu\n",
			  len, pos);
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

	if (type == FUZZ_REQ_H2 && r == TFW_POSTPONE) {
		if (!(r = tfw_http_parse_req_on_headers_done(req)))
			r = tfw_h2_parse_req_finish(req);
	}

	return r;
}

static void
test_case_parse_prepare_http(const char *str, size_t sz_diff)
{
	chunk_size_index = 0;
	hm_exp_len = strlen(str) - sz_diff;
}

static void
test_case_parse_prepare_h2(const char *str, size_t sz_diff)
{
	h2_len = tfw_h2_pack_hdr_frame(str, h2_buf, ARRAY_SIZE(h2_buf));
	h2_len -= H2_HDR_HDR_SZ;

	tfw_h2_context_init(&conn.h2);
	conn.h2.hdr.type = HTTP2_HEADERS;
	stream.state = HTTP2_STREAM_REM_HALF_CLOSED;

	chunk_size_index = 0;
	hm_exp_len = h2_len - sz_diff;
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
do_split_and_parse(unsigned char *str, unsigned int len, int type, int chunk_mode)
{
	int r;
	unsigned int chunk_size;

	BUG_ON(!str);

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

		req = test_req_alloc(len);
	}
	else if (type == FUZZ_REQ_H2) {
		if (req)
			test_req_free(req);

		req = test_req_alloc(len);
		conn.h2.hpack.state = 0;
		req->conn = (TfwConn*)&conn;
		req->pit.parsed_hdr = &stream.parser.hdr;
		req->stream = &stream;
		tfw_http_init_parser_req(req);
		stream.msg = (TfwMsg*)req;
	}
	else if (type == FUZZ_RESP) {
		if (resp)
			test_resp_free(resp);

		resp = test_resp_alloc(len);
		tfw_http_msg_pair(resp, sample_req);
	}
	else {
		BUG();
	}

	chunk_size = chunk_mode == CHUNK_OFF
			? len
			: CHUNK_SIZES[chunk_size_index];

	TEST_DBG3("%s: chunk_mode=%d, chunk_size_index=%u, chunk_size=%u\n",
		    __func__, chunk_mode, chunk_size_index, chunk_size);

	r = split_and_parse_n(str, type, len, chunk_size);

	if (chunk_mode == CHUNK_OFF || CHUNK_SIZES[chunk_size_index] >= len)
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
static int
validate_data_fully_parsed(int type)
{
	TfwHttpMsg *hm = (type == FUZZ_REQ || type == FUZZ_REQ_H2)
			? (TfwHttpMsg *)req
			: (TfwHttpMsg *)resp;

	EXPECT_EQ(hm->msg.len, hm_exp_len);
	return hm->msg.len == hm_exp_len;
}

#define TRY_PARSE_EXPECT_PASS(str, type, chunk_mode)			\
({						    			\
	int _err = type == FUZZ_REQ_H2		    			\
		? do_split_and_parse(h2_buf + H2_HDR_HDR_SZ, h2_len,	\
				     type, chunk_mode)			\
		: do_split_and_parse(str, strlen(str),			\
				     type, chunk_mode);			\
	if (_err == TFW_BLOCK || _err == TFW_POSTPONE			\
	    || !validate_data_fully_parsed(type))   			\
		TEST_FAIL("can't parse %s (code=%d):\n%s",		\
			  (type == FUZZ_REQ	    			\
			   || type == FUZZ_REQ_H2			\
			   ? "request" : "response"),			\
			  _err, (str));					\
	__fpu_schedule();						\
	_err == TFW_PASS;						\
})

#define TRY_PARSE_EXPECT_BLOCK(str, type, chunk_mode)			\
({									\
	int _err = type == FUZZ_REQ_H2					\
		? do_split_and_parse(h2_buf + H2_HDR_HDR_SZ, h2_len,	\
				     type, chunk_mode)			\
		: do_split_and_parse(str, strlen(str),			\
				     type, chunk_mode);			\
	if (_err == TFW_PASS)						\
		TEST_FAIL("%s is not blocked as expected:\n%s",		\
			  (type == FUZZ_REQ				\
			   || type == FUZZ_REQ_H2			\
			   ? "request" : "response"),			\
			       (str));					\
	__fpu_schedule();						\
	_err == TFW_BLOCK || _err == TFW_POSTPONE;			\
})

#define __FOR_REQ(str, sz_diff, type, chunk_mode)			\
	TEST_LOG("=== request: [%s]\n", str);				\
	type == FUZZ_REQ_H2 ?						\
		test_case_parse_prepare_h2(str, sz_diff) :		\
		test_case_parse_prepare_http(str, sz_diff);		\
	while (TRY_PARSE_EXPECT_PASS(str, type, chunk_mode))

#define FOR_REQ(str)						\
	__FOR_REQ(str, 0, FUZZ_REQ, CHUNK_ON)
#define FOR_REQ_H2(str)						\
	__FOR_REQ(str, 0, FUZZ_REQ_H2, CHUNK_ON)
#define FOR_REQ_H2_CHUNK_OFF(str)				\
	__FOR_REQ(str, 0, FUZZ_REQ_H2, CHUNK_OFF)

#define __EXPECT_BLOCK_REQ(str, type, chunk_mode)			\
do {									\
	TEST_LOG("=== request: [%s]\n", str);				\
	type == FUZZ_REQ_H2 ?						\
		test_case_parse_prepare_h2(str, 0) :			\
		test_case_parse_prepare_http(str, 0);			\
	while (TRY_PARSE_EXPECT_BLOCK(str, type, chunk_mode));		\
} while (0)

#define EXPECT_BLOCK_REQ(str)					\
	__EXPECT_BLOCK_REQ(str, FUZZ_REQ, CHUNK_ON)
#define EXPECT_BLOCK_REQ_H2(str)				\
	__EXPECT_BLOCK_REQ(str, FUZZ_REQ_H2, CHUNK_ON)
#define EXPECT_BLOCK_REQ_H2_CHUNK_OFF(str)			\
	__EXPECT_BLOCK_REQ(str, FUZZ_REQ_H2, CHUNK_OFF)

#define __FOR_RESP(str, sz_diff, chunk_mode)				\
	TEST_LOG("=== response: [%s]\n", str);				\
	test_case_parse_prepare_http(str, sz_diff);			\
	while (TRY_PARSE_EXPECT_PASS(str, FUZZ_RESP, chunk_mode))

#define FOR_RESP(str)	__FOR_RESP(str, 0, CHUNK_ON)

#define EXPECT_BLOCK_RESP(str)						\
do {									\
	TEST_LOG("=== response: [%s]\n", str);				\
	test_case_parse_prepare_http(str, 0);				\
	while (TRY_PARSE_EXPECT_BLOCK(str, FUZZ_RESP, CHUNK_ON));	\
} while (0)

#define EXPECT_TFWSTR_EQ(tfw_str, cstr) 			\
	EXPECT_TRUE(tfw_str_eq_cstr(tfw_str, cstr, strlen(cstr), 0))

#define REQ_SIMPLE_HEAD		"GET / HTTP/1.1\r\n"
#define EMPTY_REQ		REQ_SIMPLE_HEAD "\r\n"
#define RESP_SIMPLE_HEAD	"HTTP/1.0 200 OK\r\n"		\
				"Content-Length: 0\r\n"
#define EMPTY_RESP		RESP_SIMPLE_HEAD "\r\n"

#define FOR_REQ_SIMPLE(headers)					\
	FOR_REQ(REQ_SIMPLE_HEAD headers "\r\n\r\n")
#define FOR_RESP_SIMPLE(headers)				\
	FOR_RESP(RESP_SIMPLE_HEAD headers "\r\n\r\n")

#define FOR_REQ_RESP_SIMPLE(headers, lambda)			\
	FOR_REQ_SIMPLE(headers)					\
	{							\
		TfwHttpMsg *msg = (TfwHttpMsg *)req;		\
		lambda;						\
	}							\
	FOR_RESP_SIMPLE(headers)				\
	{							\
		TfwHttpMsg *msg = (TfwHttpMsg *)resp;		\
		lambda;						\
	}

#define EXPECT_BLOCK_REQ_SIMPLE(headers)			\
	EXPECT_BLOCK_REQ(REQ_SIMPLE_HEAD headers "\r\n\r\n")

#define EXPECT_BLOCK_RESP_SIMPLE(headers)			\
	EXPECT_BLOCK_RESP(RESP_SIMPLE_HEAD headers "\r\n\r\n")

#define EXPECT_BLOCK_REQ_RESP_SIMPLE(headers)			\
	EXPECT_BLOCK_REQ_SIMPLE(headers);			\
	EXPECT_BLOCK_RESP_SIMPLE(headers)


#define FOR_REQ_HDR_EQ(header, id)				\
	FOR_REQ_SIMPLE(header)					\
	{							\
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[id],	header);\
	}

#define FOR_RESP_HDR_EQ(header, id)				\
	FOR_RESP_SIMPLE(header)					\
	{							\
		EXPECT_TFWSTR_EQ(&resp->h_tbl->tbl[id], header);\
	}

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

static inline int
number_to_strip(TfwHttpReq *req)
{
	return
		!!test_bit(TFW_HTTP_B_NEED_STRIP_LEADING_CR, req->flags) +
		!!test_bit(TFW_HTTP_B_NEED_STRIP_LEADING_LF, req->flags);
}

TEST(http2_parser, content_type_in_bodyless_requests)
{
#define EXPECT_BLOCK_BODYLESS_REQ_H2(METHOD)				\
	EXPECT_BLOCK_REQ_H2(":method: "#METHOD"\n"			\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0");			\
	EXPECT_BLOCK_REQ_H2(":method: "#METHOD"\n"			\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain");

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(METHOD)			\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0\n"			\
			    "x-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0\n"			\
			    "x-http-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0\n"			\
			    "x-http-method: "#METHOD);			\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain\n"		\
			    "x-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain\n"		\
			    "x-http-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain\n"		\
			    "x-http-method: "#METHOD);


	EXPECT_BLOCK_BODYLESS_REQ_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_H2(TRACE);

	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(TRACE);

	FOR_REQ_H2(":method: OPTIONS\n"
		   ":scheme: https\n"
		   ":path: /\n"
		   "content-type: text/plain");


#undef EXPECT_BLOCK_BODYLESS_REQ_H2
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2
}

TEST(http2_parser, http2_check_important_fields)
{
	EXPECT_BLOCK_REQ_H2(":method: GET\n"
			    ":scheme: http\n"
			    ":path: /");

	FOR_REQ_H2(":method: GET\n"
		   ":scheme: https\n"
		   ":path: /\n"
		   "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n"
		   "Cache-Control: max-age=1, dummy, no-store, min-fresh=30");

	EXPECT_BLOCK_REQ_H2(":method: GET\n"
			    ":scheme: https\n"
			    ":path: /\n"
			    "connection: Keep-Alive");
}

TEST_SUITE(http2_parser)
{
	TEST_RUN(http2_parser, content_type_in_bodyless_requests);
	TEST_RUN(http2_parser, http2_check_important_fields);
}
