/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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

#include "test_http_parser_common.h"

static const unsigned int CHUNK_SIZES[] = {
	1, 2, 3, 4, 8, 16, 32, 64, 128,
	256, 1500, 9216, 1024*1024
        /* to fit a message of 'any' size */
};
unsigned int chunk_size_index = 0;
#define CHUNK_SIZE_CNT ARRAY_SIZE(CHUNK_SIZES)

TfwHttpReq *req, *sample_req;
TfwHttpResp *resp;
TfwH2Conn conn;
TfwStream stream;

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
TfwFrameRec frames[ALLOWED_FRAMES_CNT];
unsigned int frames_cnt = 0;
unsigned int frames_max_sz = 0;
unsigned int frames_total_sz = 0;

/**
 * GET_CURRENT_FRAME - returns entry from @frames indexed by @frame_index
 *		       from FOR_EACH_FRAME macro.
 *
 * Used only inside the lambda from FOR_EACH_FRAME macro.
 *
 * Used for types HTTP/1 and HTTP/2 requests.
 */
#define GET_CURRENT_FRAME() \
	({&frames[frame_index];})

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

static void
tfw_free_chunks(TfwTestChunk *chunks, uint32_t chunk_cnt)
{
	int i;
	TEST_DBG4("%s: chunks %pK, cnt %u\n", __func__, chunks, chunk_cnt);
	for (i = 0; i < chunk_cnt; i++)
		kfree(chunks[i].buf);
	kernel_fpu_end();
	vfree(chunks);
	kernel_fpu_begin();
}

void
tfw_frames_chunks_free(void)
{
	FOR_EACH_FRAME({
		TfwFrameRec *frame = GET_CURRENT_FRAME();
		if (frame->chunks != NULL && frame->chunk_cnt != 0) {
			TEST_DBG4("%s: f: %pK, f->chunks: %pK, f->chunk_cnt %u\n",
				__func__, frame, frame->chunks,
				frame->chunk_cnt);
			tfw_free_chunks(frame->chunks, frame->chunk_cnt);
		}
		frame->chunks	 = NULL;
		frame->chunk_cnt = 0;
	});
}

/**
 * tfw_init_frames - initialization of service data for frames
 *			before the formation of new frames.
 *
 * Used for types HTTP/1 and HTTP/2 requests.
 * If there were some chunk buffers assigned to the frame, deallocate them here.
 */
void
tfw_init_frames(void)
{
	tfw_frames_chunks_free();
	frames_cnt = 0;
	frames_max_sz = 0;
	frames_total_sz = 0;
	bzero_fast(frames, sizeof(frames));
}

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
TfwFramesBuf *frames_buf_ptr = NULL;
unsigned char *frame_buf = NULL;

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
void
write_to_frame_data(char *data, size_t size)
{
	TfwHPackInt hpint;
	write_int(size, 0x7F, 0, &hpint);
	memcpy_fast(frame_buf, hpint.buf, hpint.sz);
	memcpy_fast(frame_buf + hpint.sz, data, size);
	frame_buf += hpint.sz + size;
}

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
void
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
 * tfw_h1_frames_assign - assign HTTP/1 request to @frames.
 *
 * @str_buf:		a pointer to external buffer with HTTP/1 request.
 * @str_len:		a size of request in bytes.
 *
 * Used for HTTP/1 requests only.
 * 'frames' entity here is pure artificial thing.
 * It's used to devide large strings into smaller chunks
 * to overcome large buffer allocation restrictions.
 */
static inline void
tfw_h1_frames_assign(char *str, size_t len)
{
	int i = 0;
	uint32_t pos = 0;
	uint32_t last_frame_len;

	tfw_init_frames();
	frames_cnt = DIV_ROUND_UP(len, FRAME_MAX_SIZE);
	TEST_DBG("%s: frames cnt %u\n", __func__, frames_cnt);
	BUG_ON(frames_cnt > ALLOWED_FRAMES_CNT);

	if (frames_cnt > 1) {
		for (i = 0; i < frames_cnt - 1; i++) {
			frames[i].str = str + pos;
			frames[i].len = FRAME_MAX_SIZE;
			frames_max_sz = FRAME_MAX_SIZE;
			frames_total_sz += FRAME_MAX_SIZE;
			pos += FRAME_MAX_SIZE;
		}
	}

	last_frame_len = len % FRAME_MAX_SIZE;
	frames[frames_cnt - 1].str = str + pos;
	frames[frames_cnt - 1].len = (last_frame_len != 0) ?
				last_frame_len : FRAME_MAX_SIZE;
	if (frames_max_sz == 0)
		frames_max_sz = frames[frames_cnt - 1].len;
	frames_total_sz += frames[frames_cnt - 1].len;
}

#define TFW_CANARY_SIZE 16
#if !IS_ENABLED(CONFIG_KASAN)
#define TFW_DATA_OFF	TFW_CANARY_SIZE / 2
#else
#define TFW_DATA_OFF	0
#endif

/**
 * tfw_prep_chunks - allocate detached buffers for chunks
 *
 * @chunk_cnt:		number of chunks
 * @chunk_size:		size of the chunk
 * @str_len:		incoming linear buf len
 *
 * Used for HTTP/1 and HTTP/2 requests.
 * If CONFIG_KASAN is not set, canary would be placed before
 * and right after the payload.
 */
static TfwTestChunk *
tfw_prep_chunks(uint32_t chunk_cnt, uint32_t chunk_size, uint32_t str_len)
{
	int i;
	uint32_t last_chunk_len;
	TfwTestChunk *chunks;

	TEST_DBG4("%s: [%u] chunks, chunk size %u, pg order %u, str len %u\n",
		__func__, chunk_cnt, chunk_size, get_order(chunk_size), str_len);

	/* temprorarily allow sleeping while allocating test chunks */
	kernel_fpu_end();
	chunks = __vmalloc(chunk_cnt * sizeof(*chunks), __GFP_ZERO);
	if (!chunks) {
		TEST_DBG("%s: Failed to allocate chunk descriptors\n", __func__);
		kernel_fpu_begin();
		return ERR_PTR(-ENOMEM);
	}

	TEST_DBG4("%s: chunks buf %pK\n", __func__, chunks);

	if (chunk_cnt > 1) {
		for (i = 0; i < chunk_cnt - 1; i++) {
#if !IS_ENABLED(CONFIG_KASAN)
			chunks[i].buf = kmalloc(chunk_size + TFW_CANARY_SIZE,
						GFP_KERNEL);
#else
			chunks[i].buf = kmalloc(chunk_size, GFP_KERNEL);
#endif
			if (!chunks[i].buf) {
				TEST_DBG("%s: Failed to allocate chunk page(s)\n",
					__func__);
				kernel_fpu_begin();
				goto err_alloc;
			}
#if !IS_ENABLED(CONFIG_KASAN)
			memset(chunks[i].buf, 0x55, chunk_size + TFW_CANARY_SIZE);
#endif
		}
	}

	/* last chunk size may differ, so set it up separately */
	last_chunk_len = str_len % chunk_size;
	if (last_chunk_len != 0)
		chunk_size = last_chunk_len;

#if !IS_ENABLED(CONFIG_KASAN)
	chunks[chunk_cnt - 1].buf = kmalloc(chunk_size + TFW_CANARY_SIZE,
						GFP_KERNEL);
#else
	chunks[chunk_cnt - 1].buf = kmalloc(chunk_size, GFP_KERNEL);
#endif
	if (!chunks[chunk_cnt - 1].buf) {
		TEST_DBG("%s: Failed to allocate last chunk page(s)\n", __func__);
		kernel_fpu_begin();
		goto err_alloc;
	}
#if !IS_ENABLED(CONFIG_KASAN)
	memset(chunks[chunk_cnt - 1].buf, 0x55, chunk_size + TFW_CANARY_SIZE);
#endif
	kernel_fpu_begin();
	return chunks;

err_alloc:
	tfw_free_chunks(chunks, chunk_cnt);
	return ERR_PTR(-ENOMEM);
}

int
split_and_parse_n(unsigned char *str, uint32_t type, uint32_t len,
		uint32_t chunk_size, TfwTestChunk **fchunks)
{
	uint32_t pos = 0;
	unsigned int parsed;
	uint32_t __cs;
	int r = T_OK;
	uint32_t chunk_cnt;
	TfwHttpMsg *hm;
	uint32_t cidx;
	char *buf;
	TfwTestChunk *chunks = NULL;
	__cs = chunk_size;
	hm = (type == FUZZ_RESP)
		? (TfwHttpMsg *)resp
		: (TfwHttpMsg *)req;
	chunk_cnt = DIV_ROUND_UP(len, chunk_size);
	*fchunks = NULL;

	BUG_ON(type != FUZZ_REQ && type != FUZZ_REQ_H2 && type != FUZZ_RESP);

	TEST_DBG3("%s: type=%u, len=%u, chunk_size=%u, chunk_cnt=%u\n",
			__func__, type, len, chunk_size, chunk_cnt);

	/* prepare chunks */
	chunks = tfw_prep_chunks(chunk_cnt, chunk_size, len);
	BUG_ON(IS_ERR(chunks));

	while (pos < len) {
		if (chunk_size >= len - pos)
			/* At the last chunk */
			chunk_size = len - pos;

		cidx = DIV_ROUND_UP(pos, __cs);
		buf = chunks[cidx].buf;
		/* copy payload */
		memcpy(buf + TFW_DATA_OFF, str + pos, chunk_size);

		TEST_DBG3("%s: > chunk [%u / %u] addr %pK, pos=%u\n",  __func__,
				cidx, chunk_cnt - 1, buf, pos);

		if (type == FUZZ_REQ)
			r = tfw_http_parse_req(req, buf + TFW_DATA_OFF, chunk_size, &parsed);
		else if (type == FUZZ_REQ_H2)
			r = tfw_h2_parse_req(req, buf + TFW_DATA_OFF, chunk_size, &parsed);
		else
			r = tfw_http_parse_resp(resp, buf + TFW_DATA_OFF, chunk_size, &parsed);

		pos += chunk_size;
		hm->msg.len += parsed;

		TEST_DBG3("%s: < parser ret %d, pos %u, msg len %zu\n", __func__,
				r, pos, hm->msg.len);

		BUILD_BUG_ON((int)T_POSTPONE != (int)T_POSTPONE);
		if (r != T_POSTPONE)
			goto complete;
	}

	BUG_ON(pos != len);

complete:
	/**
	 * Chunks deallocation postponement is required here
	 * due to the fact that some @req fields would point to
	 * the data in chunks and this data would be checked later.
	 * See comments for @do_split_and_parse()/__TRY_PARSE_EXPECT_*
	 */
	*fchunks = chunks;
	return r <= T_BAD || r == T_OK ? r : T_BAD;
}

/**
 * Response must be paired with request to be parsed correctly. Update sample
 * request for further response parsing.
 */
int
set_sample_req(unsigned char *str)
{
	size_t len = strlen(str);
	unsigned int parsed;

	if (sample_req)
		test_req_free(sample_req);

	sample_req = test_req_alloc(len);

	TEST_LOG("parse sample req [%s]\n", str);
	return tfw_http_parse_req(sample_req, str, len, &parsed);
}

void
test_case_parse_prepare_http(char *str)
{
	tfw_h1_frames_assign(str, strlen(str));
}

void
test_case_alloc_h2(void)
{
	conn.h2 = tfw_h2_context_alloc();
	BUG_ON(!conn.h2);
	((TfwConn *)&conn)->peer = (TfwPeer *)&client;
	((TfwConn *)&conn)->proto.type = Conn_H2Clnt;
}

void
test_case_cleanup_h2(void)
{
	BUG_ON(!conn.h2);

	tfw_h2_context_clear(conn.h2);
	tfw_h2_context_free(conn.h2);
	conn.h2 = NULL;
}

void
test_case_parse_prepare_h2(void)
{
	BUG_ON(!conn.h2);
	tfw_h2_context_init(conn.h2, &conn);
	conn.h2->hdr.type = HTTP2_HEADERS;
	tfw_h2_set_stream_state(&stream, HTTP2_STREAM_REM_HALF_CLOSED);
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
int
do_split_and_parse(int type, int chunk_mode)
{
	int r;
	unsigned int chunk_size;
	TfwTestChunk *chunks = NULL;

	if (chunk_size_index == CHUNK_SIZE_CNT) {
		/*
		 * Return any positive value to indicate that
		 * all defined chunk sizes were tested and
		 * no more iterations needed.
		 */
		tfw_frames_chunks_free();
		return 1;
	}

	if (type == FUZZ_REQ) {
		if (req)
			test_req_free(req);

		req = test_req_alloc(frames_total_sz);
	} else if (type == FUZZ_REQ_H2) {
		TfwHttpMsg *hmreq;
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
			h2_origin = *conn.h2;
		else
			*(conn.h2) = h2_origin;

		conn.h2->hpack.state = 0;
		conn.h2->hpack.length = 0;
		conn.h2->hpack.dec_tbl.wnd_update = true;

		if (req)
			test_req_free(req);
		req = test_req_alloc(frames_total_sz);
		req->conn = (TfwConn*)&conn;
		req->pit.parsed_hdr = &stream.parser.hdr;
		req->stream = &stream;
		tfw_http_init_parser_req(req);
		stream.msg = (TfwMsg*)req;
		hmreq = (TfwHttpMsg *)req;
		req->pit.pool = __tfw_pool_new(0, tfw_http_msg_client(hmreq));
		BUG_ON(!req->pit.pool);
		__set_bit(TFW_HTTP_B_H2, req->flags);
	} else if (type == FUZZ_RESP) {
		if (resp)
			test_resp_free(resp);

		resp = test_resp_alloc(frames_total_sz, sample_req);
	} else {
		BUG();
	}

	chunk_size = chunk_mode == CHUNK_OFF
			? frames_max_sz
			: CHUNK_SIZES[chunk_size_index];

	TEST_DBG3("%s: chunk_mode=%d, chunk_size_index=%u, chunk_size=%u\n",
		    __func__, chunk_mode, chunk_size_index, chunk_size);

	FOR_EACH_FRAME({
		TfwFrameRec *frame = GET_CURRENT_FRAME();

		if (frame->chunks != NULL) {
			tfw_free_chunks(frame->chunks,
					frame->chunk_cnt);
			frame->chunks = NULL;
			frame->chunk_cnt = 0;
		}

		if (type == FUZZ_REQ_H2) {
			TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);
			ctx->hdr.type = frame->subtype;
			ctx->plen = frame->len;
		}

		if (type == FUZZ_REQ_H2
		    && frame->subtype == HTTP2_DATA
		    && !frame->len) {
			r = T_POSTPONE;
		} else {
			r = split_and_parse_n(frame->str, type, frame->len,
						chunk_size, &chunks);

			if (chunks) {
				frame->chunks = chunks;
				frame->chunk_cnt = DIV_ROUND_UP(frame->len,
								chunk_size);
				TEST_DBG4("%s: new chunks => frame %pK, "
					"frame->chunks %pK, frame->chunk_cnt %u\n",
					__func__, frame, frame->chunks,
					frame->chunk_cnt);
			}
		}

		if (r != T_POSTPONE)
			break;

		if (type == FUZZ_REQ_H2 && frame->subtype == HTTP2_HEADERS) {
			if (!tfw_http_parse_check_bodyless_meth(req)) {
				__set_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags);
				tfw_http_extract_request_authority(req);
			} else {
				r = T_BLOCK;
				break;
			}
		}
	});

	if (type == FUZZ_REQ_H2 && r == T_POSTPONE) {
		r = tfw_h2_parse_req_finish(req);
	}

	if (chunk_mode == CHUNK_OFF
	    || CHUNK_SIZES[chunk_size_index] >= frames_max_sz)
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
int
validate_data_fully_parsed(int type, size_t sz_diff)
{
	TfwHttpMsg *hm = (type == FUZZ_REQ || type == FUZZ_REQ_H2)
			? (TfwHttpMsg *)req
			: (TfwHttpMsg *)resp;

	size_t hm_exp_len = frames_total_sz - sz_diff;

	EXPECT_EQ(hm->msg.len, hm_exp_len);
	return hm->msg.len == hm_exp_len;
}

/*
 * Test that the parsed string was split to the right amount of chunks and all
 * the chunks has the same flags.
 */
void
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

TfwStr
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

void
test_req_resp_cleanup(void)
{
	if (sample_req) {
		test_req_free(sample_req);
		sample_req = NULL;
	}

	if (req) {
		test_req_free(req);
		req = NULL;
	}

	if (resp) {
		test_resp_free(resp);
		resp = NULL;
	}
}
