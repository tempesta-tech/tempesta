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

static const unsigned int CHUNK_SIZES[] = { 9216, 1, 2, 3, 4, 8, 16, 32, 64, 128,
                                   256, 1500, 9216, 1024*1024
                                  /* to fit a message of 'any' size */
                                 };
static unsigned int chunk_size_index = 0;
//#define CHUNK_SIZE_CNT ARRAY_SIZE(CHUNK_SIZES)
#define CHUNK_SIZE_CNT 1

enum {
	CHUNK_OFF,
	CHUNK_ON
};

static TfwHttpReq *req, *sample_req;
static TfwHttpResp *resp;
static TfwH2Conn conn;
static TfwStream stream;
static char h2_buf[1024];
static char *h2_buf_ptr = h2_buf;
static unsigned int h2_len = 0;
static size_t hm_exp_len = 0;


struct header_rec
{
	char *buf;
	size_t size;
};

typedef struct header_rec	TfwHeaderRec;

static
void __attribute__((unused))
tfw_h2_encode_data(TfwHeaderRec data)
{
	TfwHPackInt hpint;

	write_int(data.size, 0x7F, 0, &hpint);
	memcpy_fast(h2_buf_ptr, hpint.buf, hpint.sz);
	h2_buf_ptr += hpint.sz;
	memcpy_fast(h2_buf_ptr, data.buf, data.size);
	h2_buf_ptr += data.size;
}

static
void __attribute__((unused))
tfw_h2_encode_header(TfwHeaderRec name, TfwHeaderRec value)
{
	static const int LIT_HDR_FLD_WO_IND  = 0x00;

	*h2_buf_ptr = LIT_HDR_FLD_WO_IND;
	++h2_buf_ptr;

	tfw_h2_encode_data(name);
	tfw_h2_encode_data(value);
}

static
TfwHeaderRec __attribute__((unused))
data_from_str(char *data, size_t data_sz)
{
	TfwHeaderRec ret = {data, data_sz};
	return ret;
}

#define STR(data) \
	data_from_str(data, sizeof(data) - 1)

#define HEADER(name, value) \
	tfw_h2_encode_header(name, value)

#define HEADERS_FRAME(...)						\
do {									\
	bzero_fast(h2_buf, sizeof(h2_buf));				\
	h2_buf_ptr = h2_buf;						\
	__VA_ARGS__;							\
	BUG_ON(h2_buf_ptr > *(&h2_buf + 1));				\
} while (0)

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

static void
test_case_parse_prepare_http(const char *str, size_t sz_diff)
{
	chunk_size_index = 0;
	hm_exp_len = strlen(str) - sz_diff;
}

static void
test_case_parse_prepare_h2(size_t sz_diff)
{
	tfw_h2_context_init(&conn.h2);
	conn.h2.hdr.type = HTTP2_HEADERS;
	stream.state = HTTP2_STREAM_REM_HALF_CLOSED;

	chunk_size_index = 0;
	h2_len = h2_buf_ptr - h2_buf;
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
static
int __attribute__((unused))
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
		? do_split_and_parse(h2_buf, h2_len,	\
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
		? do_split_and_parse(h2_buf, h2_len,			\
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
		test_case_parse_prepare_h2(sz_diff) :			\
		test_case_parse_prepare_http(str, sz_diff);		\
	while (TRY_PARSE_EXPECT_PASS(str, type, chunk_mode))

#define FOR_REQ(str)							\
	__FOR_REQ(str, 0, FUZZ_REQ, CHUNK_ON)
#define FOR_REQ_H2(HEADERS_FRAME_BLOCK)					\
	HEADERS_FRAME_BLOCK;						\
	__FOR_REQ(							\
	    "HTTP/2 request preview is not available now...",		\
	     0, FUZZ_REQ_H2, CHUNK_ON)
#define FOR_REQ_H2_CHUNK_OFF(str)					\
	__FOR_REQ(str, 0, FUZZ_REQ_H2, CHUNK_OFF)

#define __EXPECT_BLOCK_REQ(str, type, chunk_mode)			\
do {									\
	TEST_LOG("=== request: [%s]\n", str);				\
	type == FUZZ_REQ_H2 ?						\
		test_case_parse_prepare_h2(0) :				\
		test_case_parse_prepare_http(str, 0);			\
	while (TRY_PARSE_EXPECT_BLOCK(str, type, chunk_mode));		\
} while (0)

#define EXPECT_BLOCK_REQ(str)						\
	__EXPECT_BLOCK_REQ(str, FUZZ_REQ, CHUNK_ON)
#define EXPECT_BLOCK_REQ_H2(HEADERS_FRAME_BLOCK)			\
	HEADERS_FRAME_BLOCK;						\
	__EXPECT_BLOCK_REQ(						\
	    "HTTP/2 request preview is not available now...",		\
	    FUZZ_REQ_H2, CHUNK_ON)
#define EXPECT_BLOCK_REQ_H2_CHUNK_OFF(str)				\
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
