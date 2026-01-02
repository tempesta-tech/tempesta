/**
 *		Tempesta FW
 *
 * Core HTTP-layer processing, including HTTP/2 and HTTP/1.1 versions.
 *
 * Notes about the design of HTTP/2 implementation.
 *
 * In order to perform internal HTTP-specific analysis (HTTP-tables,
 * HTTP-limits, Sessions module, Scheduling etc.) - for both HTTP/2 and
 * HTTP/1.1 processing - we need representation of HTTP-message content.
 * In case of HTTP/1.1 we have such representation right from the message's
 * source skb - those are ASCII strings, which don't need to be decrypted
 * and allow quick processing with SIMD instructions. However, content of
 * HTTP/2-message (i.e. headers) could be encrypted with special HPACK
 * methods (static/dynamic indexing and Huffman coding), which doesn't
 * allow to analyze the message content directly. To solve this issue for
 * HTTP/2-requests processing, current implementation of HTTP-layer creates
 * HTTP/1.1-representation of HTTP/2 headers (during HPACK-decoding and
 * HTTP/2-parsing) and places that representation into the special pool
 * @TfwHttpReq.pit.pool.
 *
 * Actually, we don't need to create separate HTTP/1.1-representation
 * for all HTTP/2 headers: some of them could be not encoded (not in Huffman
 * form - in ASCII instead) and some - could be just indexed (we can keep static
 * and dynamic indexes during internal request analysis and convert them into
 * ASCII strings in-place - on demand); thus, in current implementation we save
 * memory/processor resources and create additional HTTP/1.1-representation only
 * for Huffman encoded headers. On the final stage of request processing (in
 * @tfw_h2_adjust_req() procedure, before re-sending request to backend) the
 * obtained @TfwHttpReq.pit.pool with HTTP/1.1-representation is used for
 * request assembling in case of HTTP/2 => HTTP/1.1 transformation.
 *
 * Described above approach was chosen instead of immediate HTTP/2 => HTTP/1.1
 * transformation on HTTP/2-message decoding, because the latter one is not
 * scales for the case of HTTP/2 => HTTP/2 proxying, since during request
 * receiving/processing we do not know what backend (HTTP/2 or HTTP/1.1)
 * the request attended for. Thus, until the backend determination moment,
 * we need to leave HTTP/2-representation in the source skb.
 * Yet another choice (instead of HTTP/1.1-representation creation for HTTP/2
 * message) could be an implementation HTTP/2-specific functionality set with
 * custom flags in @TfwHttpReq.h_tbl - to perform HTTP-specific analysis right
 * over source HTTP/2-representation of the message. However, there are several
 * problems with HTTP/2-representation analysis:
 * 1. HTTP/2 still allows ASCII strings, and even the same HTTP message may
 *    contain the same header in ASCII and in static table index. Thus, even
 *    with pure HTTP/2 operation we still must care about binary headers
 *    representation and plain ASCII representation. That means that the whole
 *    headers analyzing logic (mentioned above Schedulers, HTTPTables etc.) must
 *    either encode/decode strings on the fly or keep the two representations
 *    for the headers;
 * 2. Huffman decoding is extremely slow: it operates on units less than a byte,
 *    while we use SIMD operations for ASCII processing. The bytes-crossing
 *    logic doesn't allow to efficiently encode Huffman decoding in SIMD;
 * 3. Huffman encoding, also due to byte boundary crossing, mangles string
 *    information representation, so efficient strings matching algorithms
 *    required for #496 and #732 can not be applied.
 * Thus, the points specified above (and #732) leave us only one possibility:
 * since we must process ASCII-headers along with Huffman-encoded, we have to
 * decode Huffman on HTTP-message reception.
 *
 * Regarding of internal HTTP/2-responses (error and cached) generation - dual
 * logic design is used; i.e. along with existing functionality for
 * HTTP/1.1-responses creation, separate logic implemented for HTTP/2-responses
 * generation, in order to get performance benefits of creating a message right
 * away in HTTP/2-format instead of transforming into HTTP/2 from already
 * created HTTP/1.1-message.
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
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#undef DEBUG
#if DBG_HTTP > 0
#define DEBUG DBG_HTTP
#endif

#include "lib/hash.h"
#include "lib/str.h"
#include "access_log.h"
#include "apm.h"
#include "cache.h"
#include "filter.h"
#include "hash.h"
#include "http_limits.h"
#include "http_tbl.h"
#include "http_parser.h"
#include "http_frame.h"
#include "client.h"
#include "http_msg.h"
#include "http_sess.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "tls.h"
#include "apm.h"
#include "access_log.h"
#include "vhost.h"
#include "websocket.h"
#include "tf_filter.h"
#include "tf_conf.h"

#include "sync_socket.h"
#include "lib/common.h"

#define S_H2_METHOD		":method"
#define S_H2_SCHEME		":scheme"
#define S_H2_AUTH		":authority"
#define S_H2_PATH		":path"
#define S_H2_STAT		":status"

#define RESP_BUF_LEN		2048

/* Current length enough to store all possible transfer encodings. */
#define RESP_TE_BUF_LEN		128

/* General purpose per CPU buffer */
static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_buf);

#define TFW_CFG_BLK_DEF		(TFW_BLK_ERR_REPLY)
unsigned short tfw_blk_flags = TFW_CFG_BLK_DEF;

/* Array of whitelist marks for request's skb. */
static struct {
	unsigned int	*mrks;
	unsigned int	sz;
} tfw_wl_marks;

/**
 * Usually we store all limits in the frang, but this
 * limit is described in RFC 9113 6.5.2, so we place it
 * here, because it refers to HTTP layer.
 */
unsigned int max_header_list_size = 0;
bool allow_empty_body_content_type;
unsigned int ctrl_frame_rate_mul = 0;
unsigned int wnd_update_frame_rate_mul = 0;

#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"
#define S_HTTPS			"https://"

#define S_100			"HTTP/1.1 100 Continue"
#define S_200			"HTTP/1.1 200 OK"
#define S_301			"HTTP/1.1 301 Moved Permanently"
#define S_302			"HTTP/1.1 302 Found"
#define S_303			"HTTP/1.1 303 See Also"
#define S_304			"HTTP/1.1 304 Not Modified"
#define S_307			"HTTP/1.1 307 Temporary Redirect"
#define S_308			"HTTP/1.1 308 Permanent Redirect"
#define S_400			"HTTP/1.1 400 Bad Request"
#define S_403			"HTTP/1.1 403 Forbidden"
#define S_404			"HTTP/1.1 404 Not Found"
#define S_412			"HTTP/1.1 412 Precondition Failed"
#define S_500			"HTTP/1.1 500 Internal Server Error"
#define S_502			"HTTP/1.1 502 Bad Gateway"
#define S_503			"HTTP/1.1 503 Service Unavailable"
#define S_504			"HTTP/1.1 504 Gateway Timeout"

#define S_XFF			"x-forwarded-for"
#define S_WARN			"warning"

#define S_F_HOST		"host: "
#define S_F_DATE		"date: "
#define S_F_CONTENT_LENGTH	"content-length: "
#define S_F_CONTENT_TYPE	"content-type: "
#define S_F_CONNECTION		"connection: "
#define S_F_ETAG		"etag: "
#define S_F_RETRY_AFTER		"retry-after: "
#define S_F_SERVER		"server: "


#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"
#define S_V_CONN_CLOSE		"close"
#define S_V_CONN_KA		"keep-alive"
#define S_V_RETRY_AFTER		"10"
#define S_V_MULTIPART		"multipart/form-data; boundary="
#define S_V_WARN		"110 - Response is stale"

/*
 * A string with enough chunks to hold any element of `http_predef_resps`
 */
#define MAX_PREDEF_RESP {                                              \
	.chunks = (TfwStr []){ {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, \
			       {}, {}, {}, {} },                       \
	.len = 0, .nchunks = 13                                        \
}
/*
 * Array with predefined response data
 */
static TfwStr http_predef_resps[RESP_NUM] = {
	[RESP_100] = {
		.chunks = (TfwStr []){
			{ .data = S_100, .len = SLEN(S_100) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* Reserved for Connection */
			{ .data = NULL, .len = 0 }, /* Reserved for CRLFCRLF */
			{ .data = NULL, .len = 0 }, /* Body */
		},
		.len = SLEN(S_200 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	[RESP_200] = {
		.chunks = (TfwStr []){
			{ .data = S_200, .len = SLEN(S_200) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* Reserved for Connection */
			{ .data = NULL, .len = 0 }, /* Reserved for CRLFCRLF */
			{ .data = NULL, .len = 0 }, /* Body */
		},
		.len = SLEN(S_200 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	/* Response has invalid syntax, client shouldn't repeat it. */
	[RESP_400] = {
		.chunks = (TfwStr []){
			{ .data = S_400, .len = SLEN(S_400) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_400 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	/* Response is syntactically valid, but refuse to authorize it. */
	[RESP_403] = {
		.chunks = (TfwStr []){
			{ .data = S_403, .len = SLEN(S_403) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_403 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	/* Can't find the requested resource. */
	[RESP_404] = {
		.chunks = (TfwStr []){
			{ .data = S_404, .len = SLEN(S_404) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_404 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	[RESP_412] = {
		.chunks = (TfwStr []){
			{ .data = S_412, .len = SLEN(S_412) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_412 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	/* Internal error in TempestaFW. */
	[RESP_500] = {
		.chunks = (TfwStr []){
			{ .data = S_500, .len = SLEN(S_500) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_500 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	/* Error (syntax or network) while receiving request from backend. */
	[RESP_502] = {
		.chunks = (TfwStr []){
			{ .data = S_502, .len = SLEN(S_502) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_502 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	},
	/*
	 * Sticky cookie or JS challenge failed, refuse to serve the client.
	 * Add Retry-After header, normal browser will repeat the request
	 * after given time, 10s by default.
	 */
	[RESP_503] = {
		.chunks = (TfwStr []){
			{ .data = S_503, .len = SLEN(S_503) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_F_RETRY_AFTER,
			  .len = SLEN(S_CRLF S_F_RETRY_AFTER), .hpack_idx = 0 },
			{ .data = S_V_RETRY_AFTER,
			  .len = SLEN(S_V_RETRY_AFTER) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_503 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_RETRY_AFTER
			    S_V_RETRY_AFTER S_CRLF S_F_SERVER TFW_NAME "/"
			    TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 13
	},
	/* Can't get a response in time. */
	[RESP_504] = {
		.chunks = (TfwStr []){
			{ .data = S_504, .len = SLEN(S_504) },
			{ .data = S_CRLF S_F_DATE,
			  .len = SLEN(S_CRLF S_F_DATE), .hpack_idx = 33 },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
			  .hpack_idx = 28 },
			{ .data = "0", .len = SLEN("0") },
			{ .data = S_CRLF S_F_SERVER,
			  .len = SLEN(S_CRLF S_F_SERVER), .hpack_idx = 54 },
			{ .data = TFW_NAME "/" TFW_VERSION,
			  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
			{ .data = S_CRLF S_CRLF, .len = SLEN(S_CRLF S_CRLF) },
			{ .data = NULL, .len = 0 }, /* See above */
			{ .data = NULL, .len = 0 },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_504 S_CRLF S_F_DATE S_V_DATE S_CRLF
			    S_F_CONTENT_LENGTH "0" S_CRLF S_F_SERVER TFW_NAME
			    "/" TFW_VERSION S_CRLF S_CRLF),
		.nchunks = 11
	}
};

/*
 * Chunks for various message parts in @http_predef_resps array
 * have predefined positions:
 * 1: Date,
 * 2: Content-Length header,
 * 3: CRLF,
 * 4: Message body.
 * Message body is empty by default but can be overridden by 'response_body'
 * directive.
 *
 * Some position-dependent macros specific to @http_predef_resps
 * are defined below.
 */
#define TFW_STR_DATE_CH(msg)		__TFW_STR_CH(msg, 2)
#define TFW_STR_CLEN_CH(msg)		__TFW_STR_CH(msg, 4)
#define TFW_STR_CRLF_CH(msg, off)	__TFW_STR_CH(msg, \
						     (msg)->nchunks - 4 + (off))
#define TFW_STR_BODY_CH(msg)		__TFW_STR_CH(msg, (msg)->nchunks - 1)

/*
 * Two static TfwStr structures are needed due to have the opportunity
 * to set separately one page body, e.g. for 500 answer, and another
 * page body - for the remaining 5xx answers.
 */
static TfwStr http_4xx_resp_body = {
	.chunks = (TfwStr []){
		{ .data = NULL, .len = 0 },
		{ .data = NULL, .len = 0 },
	},
	.len = 0,
};
static TfwStr http_5xx_resp_body = {
	.chunks = (TfwStr []){
		{ .data = NULL, .len = 0 },
		{ .data = NULL, .len = 0 },
	},
	.len = 0,
};

typedef enum {
	TFW_ERROR_TYPE_ATTACK,
	TFW_ERROR_TYPE_DROP,
	TFW_ERROR_TYPE_BAD,
} ErrorType;

/*
 * Prepare current date in the format required for HTTP "Date:"
 * header field. See RFC 2616 section 3.3.
 */
static void
tfw_http_prep_date_from(char *buf, long date)
{
	struct tm tm;
	char *ptr = buf;

	static const char * const wday[] =
		{ "Sun, ", "Mon, ", "Tue, ",
		  "Wed, ", "Thu, ", "Fri, ", "Sat, " };
	static const char * const month[] =
		{ " Jan ", " Feb ", " Mar ", " Apr ", " May ", " Jun ",
		  " Jul ", " Aug ", " Sep ", " Oct ", " Nov ", " Dec " };

	/*
	 * If you see the function in perf top, then replace the naive
	 * printer by https://github.com/jeaiii/itoa.git
	 */
#define PRINT_2DIGIT(p, n)			\
	*p++ = (n <= 9) ? '0' : '0' + n / 10;	\
	*p++ = '0' + n % 10;

	time64_to_tm(date, 0, &tm);

	memcpy(ptr, wday[tm.tm_wday], 5);
	ptr += 5;
	PRINT_2DIGIT(ptr, tm.tm_mday);
	memcpy(ptr, month[tm.tm_mon], 5);
	ptr += 5;
	PRINT_2DIGIT(ptr, (tm.tm_year + 1900) / 100);
	PRINT_2DIGIT(ptr, (tm.tm_year + 1900) % 100);
	*ptr++ = ' ';
	PRINT_2DIGIT(ptr, tm.tm_hour);
	*ptr++ = ':';
	PRINT_2DIGIT(ptr, tm.tm_min);
	*ptr++ = ':';
	PRINT_2DIGIT(ptr, tm.tm_sec);
	memcpy(ptr, " GMT", 4);
#undef PRINT_2DIGIT
}

static inline void
tfw_http_prep_date(char *buf)
{
	tfw_http_prep_date_from(buf, tfw_current_timestamp());
}

char *
tfw_http_resp_status_line(int status, size_t *len)
{
	switch(status) {
	case 200:
		*len = SLEN(S_200);
		return S_200;
	case 301:
		*len = SLEN(S_301);
		return S_301;
	case 302:
		*len = SLEN(S_302);
		return S_302;
	case 303:
		*len = SLEN(S_303);
		return S_303;
	case 307:
		*len = SLEN(S_307);
		return S_307;
	case 308:
		*len = SLEN(S_308);
		return S_308;
	case 400:
		*len = SLEN(S_400);
		return S_400;
	case 403:
		*len = SLEN(S_403);
		return S_403;
	case 404:
		*len = SLEN(S_404);
		return S_404;
	case 412:
		*len = SLEN(S_412);
		return S_412;
	case 500:
		*len = SLEN(S_500);
		return S_500;
	case 502:
		*len = SLEN(S_502);
		return S_502;
	case 503:
		*len = SLEN(S_503);
		return S_503;
	case 504:
		*len = SLEN(S_504);
		return S_504;
	default:
		return NULL;
	}
}

/*
 * Preparing custom HTTP2 response to a client.
 * We don't use hpack dynamic indexing in this function, because
 * this function is used only for local responses and redirections
 * which are used quite rarely. Also we don't use dynamic indexing
 * for cache responses, which is much more significant (#1801). The
 * behaviour may be changed during solving #1801.
 */
static int
tfw_h2_prep_resp(TfwHttpResp *resp, unsigned short status, TfwStr *msg)
{
	int r, i;
	unsigned long hdrs_len = 0;
	TfwHttpTransIter *mit = &resp->mit;
	TfwHttpReq *req = resp->req;
	TfwStr hdr = {
		.chunks = (TfwStr []){ {}, {} },
		.nchunks = 2
	};
	TfwStr *body = NULL;

	/* Set HTTP/2 ':status' pseudo-header. */
	mit->start_off = FRAME_HEADER_SIZE;
	r = tfw_h2_resp_status_write(resp, status, false, true);
	if (unlikely(r))
		goto out;

	/*
	 * Form and write HTTP/2 response headers excluding "\r\n", ':'
	 * separators and OWS.
	 */
	for (i = 1; i < msg->nchunks - 1; i += 2) {
		TfwStr *name = __TFW_STR_CH(msg, i);
		TfwStr *val = __TFW_STR_CH(msg, i + 1);

		if (!__TFW_STR_CH(msg, i + 1)->data || !name->hpack_idx)
			continue;

		__TFW_STR_CH(&hdr, 0)->data = name->data + SLEN(S_CRLF);
		__TFW_STR_CH(&hdr, 0)->len = name->len - SLEN(S_CRLF) - 2;

		if (__TFW_STR_CH(msg, i + 1)->nchunks) {
			TfwMsgIter *iter = &mit->iter;
			struct sk_buff **skb_head = &resp->msg.skb_head;
			TfwHPackInt vlen;
			TfwStr s_vlen = {};

			__TFW_STR_CH(&hdr, 0)->hpack_idx = name->hpack_idx;
			r = tfw_hpack_encode(resp, __TFW_STR_CH(&hdr, 0),
					     false, false);
			if (unlikely(r))
				goto out;

			write_int(val->len, 0x7F, 0, &vlen);
			s_vlen.data = vlen.buf;
			s_vlen.len = vlen.sz;

			r = tfw_http_msg_expand_data(iter, skb_head, &s_vlen,
						     NULL);
			if (unlikely(r))
				goto out;

			r = tfw_http_msg_expand_data(iter, skb_head, val, NULL);
			if (unlikely(r))
				goto out;

			hdrs_len += s_vlen.len + val->len;
		} else {
			__TFW_STR_CH(&hdr, 1)->data = val->data;
			__TFW_STR_CH(&hdr, 1)->len = val->len;
			hdr.len = __TFW_STR_CH(&hdr, 0)->len +
				  __TFW_STR_CH(&hdr, 1)->len;
			hdr.hpack_idx = name->hpack_idx;

			if ((r = tfw_hpack_encode(resp, &hdr, false, false)))
				goto out;
		}
	}

	/*
	 * Responses built locally has room for frame header reserved
	 * in SKB linear data.
	 */
	mit->frame_head = mit->iter.skb->data;

	hdrs_len += mit->acc_len;

	body = TFW_STR_BODY_CH(msg);

	r = tfw_h2_frame_local_resp(resp, hdrs_len, body);

out:
	/*
	 * In case of error stream will be unlinked later in
	 * `tfw_http_conn_req_clean` if this function is called
	 * from `tfw_h2_send_resp` or the whole connection will
	 * be closed if this function is called from `tfw_http_prep_redir`.
	 */
	if (!r)
		tfw_h2_req_unlink_stream(req);

	return r;
}

static int
tfw_h1_write_resp(TfwHttpResp *resp, unsigned short status, TfwStr *msg)
{
	TfwMsgIter it;
	TfwStr *body = NULL;
	int r = 0;
	TfwStr *c, *end, *field_c, *field_end;

	if ((r = tfw_http_msg_setup((TfwHttpMsg *)resp, &it, msg->len, 0)))
		return r;

	body = TFW_STR_BODY_CH(msg);
	resp->status = status;
	resp->content_length = body->len;

	TFW_STR_FOR_EACH_CHUNK(c, msg, end) {
		if (c->data) {
			TFW_STR_FOR_EACH_CHUNK(field_c, c, field_end) {
				if ((r = tfw_msg_write(&it, field_c)))
					return r;
			}
		}
	}

	return r;
}

/*
 * Preparing custom HTTP1 response to a client.
 * Set the "Connection:" header field if it was present in the request.
 */
static int
tfw_h1_prep_resp(TfwHttpResp *resp, unsigned short status, TfwStr *msg)
{
	TfwHttpReq *req = resp->req;

	/* Set "Connection:" header field if needed. */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)) {
		TFW_STR_CRLF_CH(msg, 0)->data = S_CRLF S_F_CONNECTION;
		TFW_STR_CRLF_CH(msg, 0)->len = SLEN(S_CRLF S_F_CONNECTION);
		TFW_STR_CRLF_CH(msg, 1)->data = S_V_CONN_CLOSE;
		TFW_STR_CRLF_CH(msg, 1)->len = SLEN(S_V_CONN_CLOSE);
		TFW_STR_CRLF_CH(msg, 2)->data = S_CRLFCRLF;
		TFW_STR_CRLF_CH(msg, 2)->len = SLEN(S_CRLFCRLF);
		msg->len += SLEN(S_CRLF S_F_CONNECTION) + SLEN(S_V_CONN_CLOSE);
	} else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags)) {
		TFW_STR_CRLF_CH(msg, 0)->data = S_CRLF S_F_CONNECTION;
		TFW_STR_CRLF_CH(msg, 0)->len = SLEN(S_CRLF S_F_CONNECTION);
		TFW_STR_CRLF_CH(msg, 1)->data = S_V_CONN_KA;
		TFW_STR_CRLF_CH(msg, 1)->len = SLEN(S_V_CONN_KA);
		TFW_STR_CRLF_CH(msg, 2)->data = S_CRLFCRLF;
		TFW_STR_CRLF_CH(msg, 2)->len = SLEN(S_CRLFCRLF);
		msg->len += SLEN(S_CRLF S_F_CONNECTION) + SLEN(S_V_CONN_KA);
	}

	return tfw_h1_write_resp(resp, status, msg);
}

/**
 * The response redirects the client to the same URI as the original request,
 * but it includes 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 * If JS challenge is enabled, then body contained JS challenge is provided.
 * Body string contains the 'Content-Length' header, CRLF and body itself.
 */
int
tfw_http_prep_redir(TfwHttpResp *resp, unsigned short status,
		    TfwStr *cookie, TfwStr *body)
{
	TfwHttpReq *req = resp->req;
	static const TfwStr protos[] = {
		{ .data = S_HTTP, .len = SLEN(S_HTTP) },
		{ .data = S_HTTPS, .len = SLEN(S_HTTPS) },
	};
	char *date_val = *this_cpu_ptr(&g_buf);
	char *cl_val = *this_cpu_ptr(&g_buf) + SLEN(S_V_DATE);
	char *body_val = NULL;
	const TfwStr *proto =
		&protos[!!(TFW_CONN_PROTO(req->conn) & TFW_FSM_HTTPS)];
	size_t cl_len, len, remaining, body_len = body ? body->len : 0;
	size_t status_line_len;
	char *status_line = tfw_http_resp_status_line(status, &status_line_len);
	int r;
	TfwStr url = {
		.chunks = (TfwStr []){ {}, {}, {}, {} },
		.nchunks = 0
	};
	char *p;

#define TFW_ADD_URL_CHUNK(chunk) 				\
do { 								\
	len = tfw_str_to_cstr(chunk, p, remaining);		\
	url.chunks[url.nchunks].data = p;			\
	url.chunks[url.nchunks].len = len;			\
	url.len += len;						\
	url.nchunks++;						\
	remaining -= len;					\
	p += len;						\
} while (0)

	/* Checked early during Tempesta FW config parsing. */
	BUG_ON(!status_line);

	tfw_http_prep_date(date_val);
	cl_len = tfw_ultoa(body_len, cl_val, RESP_BUF_LEN - SLEN(S_V_DATE));
	if (!cl_len)
		return -E2BIG;

	remaining = RESP_BUF_LEN - SLEN(S_V_DATE) - cl_len;
	len = req->host.len + req->uri_path.len + body_len;
	if (likely(len) < remaining) {
		p = *this_cpu_ptr(&g_buf) + SLEN(S_V_DATE) + cl_len;
	} else {
		p = tfw_pool_alloc(resp->pool, len + 1);
		if (!p) {
			T_WARN("HTTP/2: unable to allocate memory"
			       " for redirection url\n");
			return -ENOMEM;
		}
		remaining = len + 1;
	}

	if (req->host.len) {
		url.chunks[url.nchunks++] = *proto;
		url.len += proto->len;
		TFW_ADD_URL_CHUNK(&req->host);
	}

	TFW_ADD_URL_CHUNK(&req->uri_path);
#undef TFW_ADD_URL_CHUNK

	/*
	 * We have to copy the body since tfw_h2_append_predefined_body() called
	 * from tfw_h2_frame_local_resp() expects body as plain string.
	 * At the moment this function is used for sticky session redirects, so
	 * there is no big difference wehre to copy the body.
	 */

	if (likely(body)) {
		body_val = p;
		body_len = tfw_str_to_cstr(body, body_val, remaining);
	}

	{
		TfwStr msg = {
			.chunks = (TfwStr []){
				{ .data = status_line,
				  .len = status_line_len },
				{ .data = S_CRLF S_F_DATE,
				  .len = SLEN(S_CRLF S_F_DATE),
				  .hpack_idx = 33 },
				{ .data = date_val, .len = SLEN(S_V_DATE) },
				{ .data = S_CRLF S_F_CONTENT_LENGTH,
				  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
				  .hpack_idx = 28 },
				{ .data = cl_val, .len = cl_len },
				{ .data = S_CRLF S_F_LOCATION,
				  .len = SLEN(S_CRLF S_F_LOCATION),
				  .hpack_idx = 46 },
				{ .data = url.data, .len = url.len,
				  .nchunks = url.nchunks},
				{ .data = S_CRLF S_F_SERVER,
				  .len = SLEN(S_CRLF S_F_SERVER),
				  .hpack_idx = 54 },
				{ .data = TFW_NAME "/" TFW_VERSION,
				  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
				{ .data = S_CRLF S_F_SET_COOKIE,
				  .len = SLEN(S_CRLF S_F_SET_COOKIE),
				  .hpack_idx = 55 },
				{ .data = cookie->data, .len = cookie->len,
				  .nchunks = cookie->nchunks},
				{ .data = S_CRLF S_CRLF,
				  .len = SLEN(S_CRLF S_CRLF) },
				{ .data = NULL, .len = 0 },
				{ .data = NULL, .len = 0 },
				{ .data = body_val, .len = body_len },
			},
			.len = SLEN(S_CRLF S_F_DATE S_V_DATE S_CRLF
				    S_F_CONTENT_LENGTH S_CRLF S_F_LOCATION
				    S_CRLF S_F_SERVER TFW_NAME "/" TFW_VERSION
				    S_CRLF S_F_SET_COOKIE S_CRLF S_CRLF)
				    + status_line_len + cl_len + url.len
				    + cookie->len + body_len,
			.nchunks = 15
		};

		r = TFW_MSG_H2(req)
			? tfw_h2_prep_resp(resp, status, &msg)
			: tfw_h1_prep_resp(resp, status, &msg);

		return r;
	}
}

#define S_304_PART_01	S_304 S_CRLF
#define S_304_KEEP	S_F_CONNECTION S_V_CONN_KA S_CRLF
#define S_304_CLOSE	S_F_CONNECTION S_V_CONN_CLOSE S_CRLF

/*
 * Preparing 304 response (Not Modified) for HTTP/1.1-client.
 */
int
tfw_http_prep_304(TfwHttpReq *req, struct sk_buff **skb_head, TfwMsgIter *it)
{
	int ret = 0;
	static TfwStr rh = {
		.data = S_304_PART_01, .len = SLEN(S_304_PART_01) };
	static TfwStr crlf_keep = {
		.data = S_304_KEEP, .len = SLEN(S_304_KEEP) };
	static TfwStr crlf_close = {
		.data = S_304_CLOSE, .len = SLEN(S_304_CLOSE) };
	TfwStr *end = NULL;

	/* Set "Connection:" header field if needed. */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags))
		end = &crlf_close;
	else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
		end = &crlf_keep;

	ret = tfw_http_msg_expand_data(it, skb_head, &rh, NULL);
	if (unlikely(ret))
		return ret;

	if (end) {
		ret = tfw_http_msg_expand_data(it, skb_head, end, NULL);
		if (unlikely(ret))
			return ret;
	}

	T_DBG("Send HTTP 304 response\n");

	return 0;
}

static inline void
tfw_http_conn_msg_unlink_conn(TfwHttpMsg *hm)
{
	/*
	 * Unlink the connection while there is at least one
	 * reference. Use atomic exchange to avoid races with
	 * new messages arriving on the connection.
	 *
	 * NOTE: currently this unlink operation is not needed
	 * for HTTP/2 mode; it is left here as is since it does
	 * nothing in HTTP/2 mode, because default general stream
	 * @conn->stream is not used and @conn->stream.msg must
	 * be always NULL during HTTP/2 processing.
	 */
	__cmpxchg((unsigned long *)&hm->conn->stream.msg,
		  (unsigned long)hm, 0UL, sizeof(long));
	tfw_connection_put(hm->conn);
}

/*
 * Free an HTTP message.
 * Also, free the connection instance if there's no more references.
 *
 * This function should be used anytime when there's a chance that
 * a connection instance may belong to multiple messages, which is
 * almost always. If a connection is suddenly closed then it still
 * can be safely dereferenced and used in the code.
 * In rare cases we're sure that a connection instance in a message
 * doesn't have multiple users. For example, when an error response
 * is prepared and sent by Tempesta, that HTTP message does not need
 * a connection instance. The message is then immediately destroyed,
 * and a simpler tfw_http_msg_free() can be used for that.
 *
 * NOTE: @hm->conn may be NULL if @hm is the response that was served
 * from cache.
 */
void
tfw_http_conn_msg_free(TfwHttpMsg *hm)
{
	if (unlikely(!hm))
		return;

	if (hm->conn) {
		/*
		 * Check that the paired response has been destroyed before
		 * the request.
		 */
		WARN_ON_ONCE((TFW_CONN_TYPE(hm->conn) & Conn_Clnt) && hm->pair);
		tfw_http_conn_msg_unlink_conn(hm);
	}

	tfw_http_msg_free(hm);
}

/*
 * Free request after removing it from seq_queue (or after closing the
 * corresponding stream - in case of HTTP/2 processing). This function
 * is needed in cases when response is not sent to client for some reasons.
 */
static inline void
tfw_http_conn_req_clean(TfwHttpReq *req)
{
	if (TFW_MSG_H2(req)) {
		tfw_h2_req_unlink_and_close_stream(req);
	} else {
		spin_lock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
		if (likely(!list_empty(&req->msg.seq_list)))
			list_del_init(&req->msg.seq_list);
		spin_unlock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
	}
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

/*
 * Free the request and the paired response.
 */
static inline void
tfw_http_resp_pair_free(TfwHttpReq *req)
{
	tfw_http_conn_msg_free(req->pair);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

void
tfw_http_resp_pair_free_and_put_conn(void *opaque_data)
{
	TfwHttpResp *resp = (TfwHttpResp *)(opaque_data);
	TfwHttpReq *req = resp->req;

	BUG_ON(!req || !req->conn);
	tfw_connection_put(req->conn);
	tfw_http_resp_pair_free(req);
}

/*
 * Close the client connection and free unpaired request. This function
 * is needed for cases when we cannot prepare response for this request.
 * As soon as request is not linked with any response, sending to that
 * client stops starting with that request, because that creates
 * a "hole" in the chain of requests -- a request without a response.
 * Subsequent responses cannot be sent to the client until that
 * hole is closed, which at this point will never happen. To solve
 * this situation there is no choice but to close client connection.
 *
 * Note: As a consequence of closing a client connection on error of
 * preparing a response, it's possible that some already prepared
 * responses will not be sent to the client. That depends on the
 * order in which CPUs close the connection and call tfw_http_resp_fwd().
 * This is the intended behaviour. The goal is to free some memory
 * at the cost of dropping a few clients, so that Tempesta can
 * continue working.
 */
void
tfw_http_resp_build_error(TfwHttpReq *req)
{
	tfw_connection_close(req->conn, true);
	tfw_http_conn_req_clean(req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
}

static inline resp_code_t
tfw_http_enum_resp_code(int status)
{
	switch(status) {
	case 100:
		return RESP_100;
	case 200:
		return RESP_200;
	case 400:
		return RESP_400;
	case 403:
		return RESP_403;
	case 404:
		return RESP_404;
	case 412:
		return RESP_412;
	case 500:
		return RESP_500;
	case 502:
		return RESP_502;
	case 503:
		return RESP_503;
	case 504:
		return RESP_504;
	default:
		return RESP_NUM;
	}
}

/**
 * Write HTTP/2 ':status' pseudo-header. The ':status' is only defined
 * pseudo-header for the response and all HTTP/2 responses must contain it.
 * https://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.4.
 */
int
tfw_h2_resp_status_write(TfwHttpResp *resp, unsigned short status,
			 bool use_pool, bool cache)
{
	int ret;
	unsigned short index = tfw_h2_pseudo_index(status);
	char buf[H2_STAT_VAL_LEN];
	TfwStr s_hdr = {
		.chunks = (TfwStr []){
			{ .data = S_H2_STAT,	.len = SLEN(S_H2_STAT) },
			{ .data = buf,		.len = H2_STAT_VAL_LEN }
		},
		.len = SLEN(S_H2_STAT) + H2_STAT_VAL_LEN,
		.nchunks = 2,
		.hpack_idx = index ? index : 8
	};

	/*
	 * If the status code is not in the static table, set the default
	 * static index just for the ':status' name.
	 */
	if (index) {
		s_hdr.flags |= TFW_STR_FULL_INDEX;
	}

	if (!tfw_ultoa(status, __TFW_STR_CH(&s_hdr, 1)->data, H2_STAT_VAL_LEN))
		return -E2BIG;

	if ((ret = tfw_hpack_encode(resp, &s_hdr, use_pool, !cache)))
		return ret;

	/* set status on response for access logging */
	resp->status = status;

	return 0;
}

void
tfw_h2_resp_fwd(TfwHttpResp *resp)
{
	bool resp_in_xmit =
		(TFW_SKB_CB(resp->msg.skb_head)->opaque_data == resp);
	TfwHttpReq *req = resp->req;
	TfwConn *conn = req->conn;
	int status = READ_ONCE(resp->status);

	tfw_connection_get(conn);
	do_access_log(resp);

	if (tfw_cli_conn_send((TfwCliConn *)conn, (TfwMsg *)resp)) {
		T_DBG("%s: cannot send data to client via HTTP/2\n", __func__);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		tfw_connection_close(conn, true);
		/* We can't send response, so we should free it here. */
		resp_in_xmit = false;
	} else {
		TFW_INC_STAT_BH(serv.msgs_forwarded);
		tfw_inc_global_hm_stats(status);
	}

	if (!resp_in_xmit)
		tfw_http_resp_pair_free_and_put_conn(resp);
}

/*
 * Perform operations to sending an custom HTTP2 response to a client.
 * Set current date in the header of an HTTP response.
 * If memory allocation error or message setup errors occurred, then
 * client connection should be closed, because response-request
 * pairing for pipelined requests is violated.
 *
 * NOTE: The first chunk is a status line, and then every odd chunk is a header
 * field name starting with CRLF and ending with ': ', and every even chunk is
 * a value.
 */
static void
tfw_h2_send_resp(TfwHttpReq *req, TfwStr *msg, int status,
		 bool close_after_send)
{
	TfwHttpResp *resp = tfw_http_msg_alloc_resp_light(req);
	if (unlikely(!resp))
		goto err;

	if (close_after_send)
		set_bit(TFW_HTTP_B_CLOSE_ERROR_RESPONSE, resp->flags);

	if (tfw_h2_prep_resp(resp, status, msg))
		goto err_setup;

	/* Send resulting HTTP/2 response and release HPACK encoder index. */
	tfw_h2_resp_fwd(resp);

	return;

err_setup:
	T_DBG("%s: HTTP/2 response message transformation error: conn=[%p]\n",
	      __func__, req->conn);

	tfw_http_msg_free((TfwHttpMsg *)resp);
err:
	tfw_http_resp_build_error(req);
}

/*
 * Perform operations to sending an custom HTTP1 response to a client.
 * Set current date in the header of an HTTP response.
 * If memory allocation error or message setup errors occurred, then client
 * connection should be closed, because response-request pairing for pipelined
 * requests is violated.
 *
 * NOTE: The first chunk is a status line, and then every odd chunk is a header
 * field name starting with CRLF and ending with ': ', and every even chunk is
 * a value.
 */
static void
tfw_h1_send_resp(TfwHttpReq *req, TfwStr *msg, int status)
{
	TfwHttpResp *resp;

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		goto err;

	if (tfw_h1_prep_resp(resp, status, msg))
		goto err_setup;

	tfw_http_resp_fwd(resp);

	return;
err_setup:
	T_DBG2("%s: Response message allocation error: conn=[%p]\n",
	       __func__, req->conn);
	tfw_http_msg_free((TfwHttpMsg *)resp);
err:
	tfw_http_resp_build_error(req);
}

/*
 * Preparing error response to a client.
 * Set current date in the header of an HTTP error response.
 */
static void
tfw_http_prep_err_resp(TfwHttpReq *req, int status, TfwStr *msg)
{
	resp_code_t code;
	TfwStr *date;

	code = tfw_http_enum_resp_code(status);
	if (code == RESP_NUM) {
		T_WARN("Unexpected response error code: [%d]\n", status);
		code = RESP_500;
	}

	if (tfw_strcpy_desc(msg, &http_predef_resps[code])) {
		T_WARN("Unexpected response error code: [%d]\n", status);
		return;
	}

	date = TFW_STR_DATE_CH(msg);
	date->data = *this_cpu_ptr(&g_buf);
	tfw_http_prep_date(date->data);
}

/*
 * Perform operations to sending an HTTP2 error response to a client.
 * If memory allocation error or message setup errors occurred, then
 * client connection should be closed, because response-request
 * pairing for pipelined requests is violated.
 */
static void
tfw_h2_send_err_resp(TfwHttpReq *req, int status, bool close_after_send)
{
	TfwStr msg = MAX_PREDEF_RESP;

	tfw_http_prep_err_resp(req, status, &msg);
	tfw_h2_send_resp(req, &msg, status, close_after_send);
}

/*
 * Perform operations to sending an HTTP1 error response to a client.
 * If memory allocation error or message setup errors occurred, then
 * client connection should be closed, because response-request
 * pairing for pipelined requests is violated.
 */
static void
tfw_h1_send_err_resp(TfwHttpReq *req, int status)
{
	TfwStr msg = MAX_PREDEF_RESP;

	tfw_http_prep_err_resp(req, status, &msg);
	tfw_h1_send_resp(req, &msg, status);
}

/*
 * SKB data is needed for calculation of a cache key from fields of
 * a request. It's also needed when a request may need to be re-sent.
 * In all other cases it can just be passed to the network layer.
 *
 * However, at this time requests may always be re-sent in case of
 * a connection failure. There's no option to prohibit re-sending.
 * Thus, request's SKB can't be passed to the network layer until
 * certain changes are implemented. For now there's no choice but
 * make a copy of request's SKBs in SS layer.
 *
 * TODO: Making a copy of each SKB _IS BAD_. See issues #391 and #488.
 */
static inline void
tfw_http_req_init_ss_flags(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	((TfwMsg *)req)->ss_flags |= SS_F_KEEP_SKB;
}

static inline void
tfw_http_resp_init_ss_flags(TfwHttpResp *resp)
{
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, resp->req->flags))
		resp->msg.ss_flags |= SS_F_CONN_CLOSE;
	if (test_bit(TFW_HTTP_B_CONN_CLOSE_FORCE, resp->req->flags))
		resp->msg.ss_flags |= __SS_F_FORCE;
}

/*
 * Reset the flag saying that @srv_conn has non-idempotent requests.
 */
static inline void
tfw_http_conn_nip_reset(TfwSrvConn *srv_conn)
{
	if (list_empty(&srv_conn->nip_queue))
		clear_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/*
 * Put @req on the list of non-idempotent requests in @srv_conn.
 * Raise the flag saying that @srv_conn has non-idempotent requests.
 */
static inline void
tfw_http_req_nip_enlist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	BUG_ON(!list_empty(&req->nip_list));
	list_add_tail(&req->nip_list, &srv_conn->nip_queue);
	set_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/*
 * Remove @req from the list of non-idempotent requests in @srv_conn.
 * If it is the last request on the list, then clear the flag saying
 * that @srv_conn has non-idempotent requests.
 *
 * Does nothing if @req is NOT on the list.
 */
static inline void
tfw_http_req_nip_delist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	if (!list_empty(&req->nip_list)) {
		list_del_init(&req->nip_list);
		tfw_http_conn_nip_reset(srv_conn);
	}
}

/*
 * Remove idempotent requests from the list of non-idempotent requests
 * in @srv_conn. A non-idempotent request may become idempotent when
 * another request is received from a client before a response to the
 * non-idempotent request is forwarded to the client. See the comment
 * to tfw_http_req_add_seq_queue().
 */
static inline void
tfw_http_conn_nip_adjust(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, &srv_conn->nip_queue, nip_list)
		if (!tfw_http_req_is_nip(req)) {
			BUG_ON(list_empty(&req->nip_list));
			list_del_init(&req->nip_list);
		}
	tfw_http_conn_nip_reset(srv_conn);
}

/*
 * Tell if the server connection's forwarding queue is on hold.
 * It's on hold if the request that was sent last was non-idempotent or
 * if connection marked as unscheduled (in case of protocol upgrade).
 */
static inline bool
tfw_http_conn_on_hold(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->last_msg_sent;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));
	return ((req_sent && tfw_http_req_is_nip(req_sent))
		|| tfw_srv_conn_unscheduled(srv_conn));
}

/*
 * Tell if the server connection's forwarding queue is drained.
 * It's drained if there're no requests in the queue after the
 * request that was sent last.
 */
static inline bool
tfw_http_conn_drained(TfwSrvConn *srv_conn)
{
	struct list_head *fwd_queue = &srv_conn->fwd_queue;
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->last_msg_sent;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	if (list_empty(fwd_queue))
		return true;
	if (!req_sent)
		return false;
	if (list_is_last(&req_sent->fwd_list, fwd_queue))
		return true;
	return false;
}

/*
 * Tell if the server connection's forwarding queue has requests
 * that need to be forwarded.
 */
static inline bool
tfw_http_conn_need_fwd(TfwSrvConn *srv_conn)
{
	return (!tfw_http_conn_on_hold(srv_conn)
		&& !tfw_http_conn_drained(srv_conn));
}

/*
 * Get the request that is previous to @srv_conn->last_msg_sent.
 */
static inline TfwMsg *
__tfw_http_conn_msg_sent_prev(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->last_msg_sent;

	/*
	 * There is list_is_last() function in the Linux kernel,
	 * but there is no list_is_first(). The condition below
	 * is an implementation of list_is_first().
	 */
	return (srv_conn->fwd_queue.next == &req_sent->fwd_list) ?
		NULL : (TfwMsg *)list_prev_entry(req_sent, fwd_list);
}

/*
 * Reset server connection's @fwd_queue and move all requests
 * to @dst list.
 */
static inline void
tfw_http_fwdq_reset(TfwSrvConn *srv_conn, struct list_head *dst)
{
	list_splice_tail_init(&srv_conn->fwd_queue, dst);
	srv_conn->qsize = 0;
	srv_conn->curr_msg_sent = srv_conn->last_msg_sent = NULL;
	INIT_LIST_HEAD(&srv_conn->nip_queue);
	clear_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/**
 * Add @req to the server connection's forwarding queue.
 */
static inline void
tfw_http_req_enlist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	list_add_tail(&req->fwd_list, &srv_conn->fwd_queue);
	srv_conn->qsize++;
	if (tfw_http_req_is_nip(req))
		tfw_http_req_nip_enlist(srv_conn, req);
}

/**
 * Remove @req from the server connection's forwarding queue.
 * Caller must care about @srv_conn->last_msg_sent on it's own to keep the
 * queue state consistent.
 */
static inline void
tfw_http_req_delist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	tfw_http_req_nip_delist(srv_conn, req);
	list_del_init(&req->fwd_list);
	srv_conn->qsize--;
}

/*
 * Common actions in case of an error while forwarding requests.
 * Erroneous requests are removed from the forwarding queue and placed
 * in @eq. The error code and the reason for an error response are
 * saved as well.
 */
static inline void
__tfw_http_req_err(TfwHttpReq *req, struct list_head *eq,
		   unsigned short status, const char *reason)
{
	list_add_tail(&req->fwd_list, eq);
	req->httperr.status = status;
	req->httperr.reason = reason;
}

static inline void
tfw_http_req_err(TfwSrvConn *srv_conn, TfwHttpReq *req,
		 struct list_head *eq, unsigned short status,
		 const char *reason)
{
	if (srv_conn)
		tfw_http_req_delist(srv_conn, req);

	if (!test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		__tfw_http_req_err(req, eq, status, reason);
	}
	else {
		/*
		 * Unable to send error message for the health monitor requests.
		 * Just drop it.
		 */
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
	}
}

static inline void
tfw_http_nip_req_resched_err(TfwSrvConn *srv_conn, TfwHttpReq *req,
			     struct list_head *eq)
{
	tfw_http_req_err(srv_conn, req, eq, 504,
			 "request dropped: non-idempotent requests aren't"
			  " re-forwarded or re-scheduled");
}

/**
 * The request is serviced from cache.
 * Send the response as is and unrefer its data.
 */
static void
tfw_http_req_cache_service(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	if (TFW_MSG_H2(req))
		tfw_h2_resp_fwd(resp);
	else
		tfw_http_resp_fwd(resp);

	TFW_INC_STAT_BH(clnt.msgs_fromcache);
}

/**
 * Build stale response from the @req->stale_ce and link request with response.
 * Forward response to client, free previous unsuccessful response from upstream
 * @hmresp.
 *
 * @return true if response successfully forwarded otherwise false.
 */
static bool
__tfw_http_resp_fwd_stale(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req = hmresp->req;
	TfwHttpResp *stale_resp;

	tfw_http_msg_unpair(hmresp);

	stale_resp = tfw_cache_build_resp_stale(req);
	/* For HTTP2 response will not be built if stream already closed. */
	if (unlikely(!stale_resp))
		/* hmresp will be freed in tfw_http_conn_drop() */
		return false;

	/* Unlink response. */
	tfw_stream_unlink_msg(hmresp->stream);

	req->resp->conn = hmresp->conn;
	hmresp->conn->stream.msg = (TfwMsg *)stale_resp;

	if (TFW_MSG_H2(req))
		tfw_h2_req_unlink_stream(req);

	tfw_http_req_cache_service(req->resp);

	tfw_http_msg_free(hmresp);

	return true;
}

/**
 * The same as @__tfw_http_resp_fwd_stale(), but used in case when we don't
 * have response from upstream.
 */
static bool
__tfw_http_resp_fwd_stale_noresp(TfwHttpReq *req)
{
	if (!tfw_cache_build_resp_stale(req))
		return false;

	if (TFW_MSG_H2(req))
		tfw_h2_req_unlink_stream(req);

	tfw_http_req_cache_service(req->resp);

	return true;
}

static bool
tfw_http_use_stale_if_error(unsigned short status)
{
	/* Defined by RFC 5861 section 4 */
	switch (status) {
	case 500:
	case 502:
	case 503:
	case 504:
		return true;
	default:
		return false;
	}
}

static bool
tfw_http_resp_should_fwd_stale(TfwHttpReq *req, unsigned short status)
{
	TfwCacheUseStale *stale_opt;

	if (!req->stale_ce)
		return false;

	stale_opt = tfw_vhost_get_cache_use_stale(req->location, req->vhost);

	/*
	 * cache_use_stale directive has higher priority than
	 * "Cache-control: stale-if-error" header.
	 */
	if (stale_opt && test_bit(HTTP_CODE_BIT_NUM(status), stale_opt->codes))
		return true;

	/*
	 * Checks whether stale response can be used depending on
	 * "Cache-control: stale-if-error" header.
	 *
	 * NOTE: There is inaccuracy in age calculation. Because we calculate
	 * age before forwarding request to upstream, it might take some time
	 * and age of prepared stale response might become greater than
	 * calculated age during receiving from cache. Therefore we response
	 * with inaccurate age or even with violation of max-stale param.
	 */
	return req->cache_ctl.flags & TFW_HTTP_CC_STALE_IF_ERROR &&
		tfw_http_use_stale_if_error(status);
}

static inline void
tfw_http_send_err_resp_nolog(TfwHttpReq *req, int status)
{
	const bool fwd_stale = tfw_http_resp_should_fwd_stale(req, status);

	/* Response must be freed before calling tfw_http_send_err_resp_nolog(). */
	if (!fwd_stale || !__tfw_http_resp_fwd_stale_noresp(req)) {
		if (TFW_MSG_H2(req))
			tfw_h2_send_err_resp(req, status, false);
		else
			tfw_h1_send_err_resp(req, status);
	}
}

/* Common interface for sending error responses. */
void
tfw_http_send_err_resp(TfwHttpReq *req, int status, const char *reason)
{
	if (!(tfw_blk_flags & TFW_BLK_ERR_NOLOG) && reason)
		T_WARN_ADDR_STATUS(reason, &req->conn->peer->addr,
				   TFW_NO_PORT, status);

	tfw_http_send_err_resp_nolog(req, status);
}

static void
tfw_http_send_resp(TfwHttpReq *req, TfwStr *msg, int status)
{
	if (TFW_MSG_H2(req)) {
		tfw_h2_send_resp(req, msg, status, false);
	} else {
		TfwCliConn *cli_conn = (TfwCliConn *)req->conn;

		WARN_ONCE(!list_empty_careful(&req->msg.seq_list),
			  "Request is already in seq_queue\n");
		tfw_stream_unlink_msg(req->stream);
		spin_lock(&cli_conn->seq_qlock);
		list_add_tail(&req->msg.seq_list, &cli_conn->seq_queue);
		spin_unlock(&cli_conn->seq_qlock);

		tfw_h1_send_resp(req, msg, status);
	}
}

static void
tfw_http_req_redir(TfwHttpReq *req, int status, TfwHttpRedir *redir)
{
	char *date_val = *this_cpu_ptr(&g_buf);
	TfwStr *url_chunks = (TfwStr *)(*this_cpu_ptr(&g_buf) + SLEN(S_V_DATE));
	TfwStr *url_p = url_chunks;
	size_t url_len = 0;
	TfwStr *c, *end, *c2, *end2;
	size_t status_line_len;
	char *status_line = tfw_http_resp_status_line(status, &status_line_len);
	size_t i = 0;

	/* Checked early during Tempesta FW config parsing. */
	BUG_ON(!status_line);

	tfw_http_prep_date(date_val);

#define TFW_STRCPY(from)						\
do {									\
	if ((char *)url_p + sizeof(url_chunks[0])			\
	    > (char *)url_chunks + RESP_BUF_LEN - SLEN(S_V_DATE))	\
	{								\
		T_WARN("HTTP: unable to allocate memory for redirection "\
		       "url\n");					\
		return;							\
	}								\
	TFW_STR_FOR_EACH_CHUNK(c2, (from), end2) {			\
		*url_p++ = *c2;						\
		url_len += c2->len;					\
	}								\
} while (0)

	TFW_STR_FOR_EACH_CHUNK(c, &redir->url, end) {
		if ((char *)url_p + sizeof(url_chunks[0])
		    > (char *)url_chunks + RESP_BUF_LEN - SLEN(S_V_DATE))
		{
			T_WARN("HTTP: unable to allocate memory for "
			       "redirection url\n");
			return;
		}

		*url_p++ = *c;
		url_len += c->len;

		if (i >= redir->nvar)
			break;

		switch (redir->var[i]) {
		case TFW_HTTP_REDIR_URI:
			TFW_STRCPY(&req->uri_path);
			break;
		case TFW_HTTP_REDIR_HOST:
			TFW_STRCPY(&req->host);
			break;
		default:
			BUG();
		}
		i++;
	}
#undef TFW_STRCPY

	{
		TfwStr msg = {
			.chunks = (TfwStr []){
				{ .data = status_line,
				  .len = status_line_len },
				{ .data = S_CRLF S_F_DATE,
				  .len = SLEN(S_CRLF S_F_DATE),
				  .hpack_idx = 33 },
				{ .data = date_val, .len = SLEN(S_V_DATE) },
				{ .data = S_CRLF S_F_CONTENT_LENGTH,
				  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH),
				  .hpack_idx = 28 },
				{ .data = "0", .len = SLEN("0") },
				{ .data = S_CRLF S_F_LOCATION,
				  .len = SLEN(S_CRLF S_F_LOCATION),
				  .hpack_idx = 46 },
				{ .chunks = url_chunks, .len = url_len,
				  .nchunks = url_p - url_chunks },
				{ .data = S_CRLF S_F_SERVER,
				  .len = SLEN(S_CRLF S_F_SERVER),
				  .hpack_idx = 54 },
				{ .data = TFW_NAME "/" TFW_VERSION,
				  .len = SLEN(TFW_NAME "/" TFW_VERSION) },
				{ .data = S_CRLF S_CRLF,
				  .len = SLEN(S_CRLF S_CRLF) },
				{ .data = NULL, .len = 0 },
				{ .data = NULL, .len = 0 },
				{ .data = NULL, .len = 0 },
			},
			.len = SLEN(S_CRLF S_F_DATE S_V_DATE S_CRLF
				    S_F_CONTENT_LENGTH "0" S_CRLF S_F_LOCATION
				    S_CRLF S_F_SERVER TFW_NAME "/" TFW_VERSION
				    S_CRLF S_CRLF) + status_line_len + url_len,
			.nchunks = 13
		};
		tfw_http_send_resp(req, &msg, status);
	}
}

/**
 * Try to mark server as suspended.
 * In case of HM is active do it, otherwise left unchanged.
 */
static void
tfw_http_hm_try_suspend(TfwHttpResp *resp, TfwServer *srv)
{
	unsigned long old_flags, flags = READ_ONCE(srv->flags);

	while (flags & TFW_SRV_F_HMONITOR) {

		old_flags = cmpxchg(&srv->flags, flags,
		                    flags | TFW_SRV_F_SUSPEND);

		if (likely(old_flags == flags)) {
			T_WARN_ADDR_STATUS("server has been suspended: limit "
					   "for bad responses is exceeded",
					   &srv->addr, TFW_WITH_PORT,
					   resp->status);
			break;
		}

		flags = old_flags;
	}
}

/**
* The main function of Health Monioring.
* Getting response from the server, it updates responses statistics,
* checks HM limits and makes solution about server health.
*/
static void
tfw_http_hm_control(TfwHttpResp *resp)
{
	TfwServer *srv = (TfwServer *)resp->conn->peer;

	/*
	* Total response statistics is counted permanently regardless
	* of the state of the health monitor.
	*/
	bool lim_exceeded = tfw_apm_hm_srv_limit(resp->status, srv->apmref);

	if (!(srv->flags & TFW_SRV_F_HMONITOR))
                return;

	if (tfw_srv_suspended(srv)) {
		T_DBG_ADDR("Server suspended", &srv->addr, TFW_WITH_PORT);
		return;
	}

	if (lim_exceeded) {
		T_WARN_ADDR("Error limit exceeded for server",
			&srv->addr, TFW_WITH_PORT);
		tfw_http_hm_try_suspend(resp, srv);
	}

	if (tfw_apm_hm_srv_alive(resp, srv)) {
		T_DBG_ADDR("Mark server alive", &srv->addr, TFW_WITH_PORT);
		tfw_srv_mark_alive(srv);
	}
}

static inline void
tfw_http_hm_srv_update(TfwServer *srv, TfwHttpReq *req)
{
	if (test_bit(TFW_SRV_B_HMONITOR, &srv->flags))
		tfw_apm_hm_srv_rcount_update(&req->uri_path, srv->apmref);
}

static int
tfw_http_marks_cmp(const void *l, const void *r)
{
	unsigned int m1 = *(unsigned int *)l;
	unsigned int m2 = *(unsigned int *)r;

	return (m1 < m2) ? -1 : (m1 > m2);
}

bool
tfw_http_mark_is_in_whitlist(unsigned int mark)
{
	return !!bsearch(&mark, tfw_wl_marks.mrks, tfw_wl_marks.sz,
			 sizeof(tfw_wl_marks.mrks[0]), tfw_http_marks_cmp);
}

/*
 * Forwarding of requests to a back end server is run under a lock
 * on the server connection's forwarding queue. It's performed as
 * fast as possible by moving failed requests to the error queue
 * that can be processed without the lock.
 *
 * Process requests that were not forwarded due to an error. Send
 * an error response to a client. The response will be attached to
 * the request and then sent to the client in proper seq order.
 */
static void
tfw_http_req_zap_error(struct list_head *eq)
{
	TfwHttpReq *req, *tmp;

	T_DBG2("%s: queue is %sempty\n",
	       __func__, list_empty(eq) ? "" : "NOT ");
	if (list_empty(eq))
		return;

	list_for_each_entry_safe(req, tmp, eq, fwd_list) {
		list_del_init(&req->fwd_list);
		if ((TFW_MSG_H2(req) && req->stream)
		    || (!TFW_MSG_H2(req)
			&& !test_bit(TFW_HTTP_B_REQ_DROP, req->flags)))
		{
			tfw_http_send_err_resp(req, req->httperr.status,
					       req->httperr.reason);
		}
		else {
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
		}

		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
}

/*
 * If @req is dropped since the client was disconnected for some reason,
 * just free the request w/o connection putting.
 */
static inline bool
tfw_http_req_evict_dropped(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	/*
	 * The special case are the health monitor requests, which have
	 * not corresponding client connection and, consequently, cannot
	 * be dropped.
	 */
	if (!req->conn)
		return false;

	if (TFW_MSG_H2(req)) {
		if (req->stream)
			return false;
		T_DBG2("%s: Eviction: req=[%p] corresponding stream has been"
		       " dropped\n", __func__, req);
	} else {
		if (likely(!test_bit(TFW_HTTP_B_REQ_DROP, req->flags)))
			return false;
		T_DBG2("%s: Eviction: req=[%p] client disconnected\n", __func__,
		       req);
	}

	if (srv_conn)
		tfw_http_req_delist(srv_conn, req);

	tfw_http_conn_msg_free((TfwHttpMsg *)req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);

	return true;
}

/*
 * If @req has timed out (has not been forwarded for too long), then
 * move it to the error queue @eq for sending an error response later.
 */
static inline bool
tfw_http_req_evict_timeout(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *eq)
{
	unsigned long jqage = jiffies - req->jrxtstamp;

	if (unlikely(time_after(jqage, srv->sg->max_jqage))) {
		T_DBG2("%s: Eviction: req=[%p] overdue=[%dms]\n",
		       __func__, req,
			 jiffies_to_msecs(jqage - srv->sg->max_jqage));
		tfw_http_req_err(srv_conn, req, eq, 504,
				 "request evicted: timed out");
		return true;
	}
	return false;
}

/*
 * If the number of re-forwarding attempts for @req is exceeded, then
 * move it to the error queue @eq for sending an error response later.
 */
static inline bool
tfw_http_req_evict_retries(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *eq)
{
	if (unlikely(req->retries++ >= srv->sg->max_refwd)) {
		T_DBG2("%s: Eviction: req=[%p] retries=[%d]\n",
		       __func__, req, req->retries);
		tfw_http_req_err(srv_conn, req, eq, 504,
				 "request evicted: the number"
				 " of retries exceeded");
		return true;
	}
	return false;
}

static inline bool
tfw_http_req_evict_stale_req(TfwSrvConn *srv_conn, TfwServer *srv,
			     TfwHttpReq *req, struct list_head *eq)
{
	return tfw_http_req_evict_dropped(srv_conn, req)
	       || tfw_http_req_evict_timeout(srv_conn, srv, req, eq);
}

static inline bool
tfw_http_req_evict(TfwSrvConn *srv_conn, TfwServer *srv, TfwHttpReq *req,
		   struct list_head *eq)
{
	return tfw_http_req_evict_dropped(srv_conn, req)
	       || tfw_http_req_evict_timeout(srv_conn, srv, req, eq)
	       || tfw_http_req_evict_retries(srv_conn, srv, req, eq);
}

/*
 * If forwarding of @req in @srv_conn is not successful, then move
 * it to the error queue @eq for sending an error response later.
 * If -EBADF or -EBUSY error occurred, then request should be left
 * in @fwd_queue to send it to backend later (or reschedule it to
 * other connection).
 */
static inline int
tfw_http_req_fwd_send(TfwSrvConn *srv_conn, TfwServer *srv, TfwHttpReq *req,
		      struct list_head *eq)
{
	int r;

	req->jtxtstamp = jiffies;
	tfw_http_req_init_ss_flags(srv_conn, req);

	/*
	 * We set TFW_CONN_B_UNSCHED on server connection. New requests must
	 * not be scheduled to it. It will be used only for websocket transport.
	 * If upgrade will fail, we clear it.
	 * All code paths to the function guarded by `fwd_qlock` so there is
	 * no race condition here.
	 */
	if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags)
	    && test_and_set_bit(TFW_CONN_B_UNSCHED, &srv_conn->flags))
	{
		/*
		 * The connection is already stolen by another websocket upgrade
		 * request. tfw_ws_srv_new_steal_sk() raises server connection
		 * failovering, so we return the appropriate value here.
		 *
		 * This is theoretically possible on highly concurrent scenarios
		 * the current function is called under tfw_http_conn_on_hold()
		 * check.
		 */
		return -EBADF;
	}

	if (!(r = tfw_connection_send((TfwConn *)srv_conn, (TfwMsg *)req)))
		return 0;

	T_DBG2("%s: Forwarding error: conn=[%p] req=[%p] error=[%d]\n",
	       __func__, srv_conn, req, r);

	if (r == -EBADF || r == -EBUSY)
		return r;

	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		tfw_http_req_delist(srv_conn, req);
		WARN_ON_ONCE(req->pair);
		tfw_http_msg_free((TfwHttpMsg *)req);
		T_WARN_ADDR("Unable to send health monitoring request to server",
			    &srv_conn->peer->addr, TFW_WITH_PORT);
	} else {
		tfw_http_req_err(srv_conn, req, eq, 500,
				 "request dropped: forwarding error");
	}

	return r;
}

/*
 * Forward one request @req to server connection @srv_conn. Return 0 if
 * request has been sent successfully, or error code otherwise.
 */
static inline int
tfw_http_req_fwd_single(TfwSrvConn *srv_conn, TfwServer *srv,
			TfwHttpReq *req, struct list_head *eq)
{
	int r;

	if (tfw_http_req_evict_stale_req(srv_conn, srv, req, eq))
		return -EINVAL;
	if ((r = tfw_http_req_fwd_send(srv_conn, srv, req, eq)))
		return r;
	srv_conn->curr_msg_sent = srv_conn->last_msg_sent = (TfwMsg *)req;
	TFW_INC_STAT_BH(clnt.msgs_forwarded);
	return 0;
}

/*
 * Forward unsent requests in server connection @srv_conn. The requests
 * are forwarded until a non-idempotent request is found in the queue.
 * It's assumed that the forwarding queue in @srv_conn is locked and
 * NOT drained. Returns 0 if forwarding has been finished or error code
 * otherwise (e.g. the case of hanged connection with busy work queue).
 */
static int
tfw_http_conn_fwd_unsent(TfwSrvConn *srv_conn, struct list_head *eq)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;

	T_DBG2("%s: conn=%pK\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(srv_conn->curr_msg_sent != srv_conn->last_msg_sent);
	BUG_ON(tfw_http_conn_drained(srv_conn));

	req = srv_conn->last_msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->last_msg_sent, fwd_list)
	    : list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwd_queue, fwd_list) {
		int ret = tfw_http_req_fwd_single(srv_conn, srv, req, eq);

		/*
		 * In case of busy work queue and absence of forwarded but
		 * unanswered request(s) in connection, the forwarding procedure
		 * is considered failed and the error is returned to the caller.
		 */
		if (ret == -EBUSY && srv_conn->last_msg_sent == NULL)
			return ret;
		/*
		 * If connection is broken or work queue is busy and connection
		 * has request(s) forwarded but unanswered, we can leave all
		 * requests in @fwd_queue: another attempt to send them will
		 * be made when connection will be repaired or when response(s)
		 * for unanswered request(s) will arrive from backend.
		 */
		if (ret == -EBADF || ret == -EBUSY)
			break;
		/*
		 * Connection is alive, but request has been removed from
		 * @fwd_queue due to some error.
		 */
		if (ret)
			continue;
		/* Stop forwarding if the request is non-idempotent. */
		if (tfw_http_req_is_nip(req))
			break;
		/* See if the idempotent request was non-idempotent. */
		tfw_http_req_nip_delist(srv_conn, req);
	}

	return 0;
}

/*
 * Forward the request @req to server connection @srv_conn.
 *
 * The request is added to the server connection's forwarding queue.
 * If forwarding is on hold at the moment, then the request will be
 * forwarded later. Otherwise, forward the request to the server now.
 *
 * Forwarding to a server is considered to be on hold after
 * a non-idempotent request is forwarded. The hold is removed when
 * a response is received to the holding request. The hold is also
 * removed when the holding non-idempotent request is followed by
 * another request from the same client. Effectively, that re-enables
 * pipelining. Due to we have a means to detect and recover from partial
 * failure conditions involving the pipelined sequence we can remove
 * hold and continue to pipeline requests after non-idempotent.
 * See RFC 7230 6.3.2.
 *
 * Requests must be forwarded in the same order they are put in the
 * queue, and so it must be done under the queue lock, otherwise
 * pairing of requests with responses may get broken. Take a simple
 * scenario. CPU-1 locks the queue, adds a request to it, unlocks
 * the queue. CPU-2 does the same after CPU-1 (the queue was locked).
 * After that CPU-1 and CPU-2 are fully concurrent. If CPU-2 happens
 * to proceed first with forwarding, then pairing gets broken.
 *
 * TODO: In current design @fwd_queue is locked until after a request
 * is submitted to SS for sending. It shouldn't be necessary to lock
 * @fwd_queue for that. There's the ordered @fwd_queue. Also there's
 * the ordered work queue in SS layer. Perhaps the right way of ordering
 * these actions is to use message tickets according to the ordering of
 * requests in @fwd_queue. Typically tfw_connection_send() or its pure
 * server variant must care about ticket ordering. Backoff and per-cpu
 * lock data structures could be used just like in Linux MCS locking.
 * Please see the issue #687.
 */
static int
tfw_http_req_fwd(TfwSrvConn *srv_conn, TfwHttpReq *req, struct list_head *eq,
		 bool resched)
{
	int ret = 0;

	T_DBG2("%s: srv_conn=%pK req=%pK\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_req_enlist(srv_conn, req);
	/*
	 * If we are rescheduling request and connection is on hold or
	 * forwarding procedure is failed (the case of busy hanged
	 * connection) -  evict request from the current @fwd_queue
	 * to try reschedule it via another connection.
	 */
	if ((tfw_http_conn_on_hold(srv_conn)
	     || tfw_http_conn_fwd_unsent(srv_conn, eq))
	    && resched)
	{
		tfw_http_req_delist(srv_conn, req);
		ret = -1;
	}
	spin_unlock_bh(&srv_conn->fwd_qlock);

	return ret;
}

/*
 * Treat a possible non-idempotent request in case of a connection
 * repair (re-send or re-schedule).
 *
 * A non-idempotent request that was forwarded but not responded to
 * is not re-sent or re-scheduled by default. Configuration option
 * can be used to have that request re-sent or re-scheduled.
 *
 * As forwarding is paused after a non-idempotent request is sent,
 * there can be only one such request among forwarded requests, and
 * that's @srv_conn->last_msg_sent.
 *
 * Note: @srv_conn->last_msg_sent may change in result.
 */
static inline void
tfw_http_conn_treatnip(TfwSrvConn *srv_conn, struct list_head *eq)
{
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->last_msg_sent;

	if (req_sent && tfw_http_conn_on_hold(srv_conn)
	    && !(srv->sg->flags & TFW_SRV_RETRY_NIP))
	{
		BUG_ON(list_empty(&req_sent->nip_list));
		srv_conn->last_msg_sent =
			__tfw_http_conn_msg_sent_prev(srv_conn);
		tfw_http_nip_req_resched_err(srv_conn, req_sent, eq);
	}
}

/*
 * Re-forward requests in a server connection. Requests that exceed
 * the set limits are evicted.
 *
 * Note: @srv_conn->last_msg_sent may change in result.
 */
static int
tfw_http_conn_resend(TfwSrvConn *srv_conn, bool first, struct list_head *eq)
{
	TfwHttpReq *req, *tmp, *req_resent = NULL;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwd_queue = &srv_conn->fwd_queue;

	if (!srv_conn->last_msg_sent)
		return 0;

	T_DBG2("%s: conn=[%p] first=[%s]\n",
	       __func__, srv_conn, first ? "true" : "false");
	BUG_ON(!srv_conn->last_msg_sent);
	BUG_ON(list_empty(&((TfwHttpReq *)srv_conn->last_msg_sent)->fwd_list));

	req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);
	end = ((TfwHttpReq *)srv_conn->last_msg_sent)->fwd_list.next;

	BUG_ON((first && srv_conn->curr_msg_sent)
	       || (!first && (srv_conn->curr_msg_sent &&
			      srv_conn->curr_msg_sent != (TfwMsg *)req)));

	/* Similar to list_for_each_entry_safe_from() */
	for (tmp = list_next_entry(req, fwd_list);
	     &req->fwd_list != end;
	     req = tmp, tmp = list_next_entry(tmp, fwd_list))
	{
		int err;

		if (tfw_http_req_evict(srv_conn, srv, req, eq))
			continue;
		err = tfw_http_req_fwd_send(srv_conn, srv, req, eq);
		/*
		 * If connection is broken, leave all requests in
		 * @fwd_queue in order to re-send them during next
		 * repairing attempt.
		 */
		if (err == -EBADF)
			return err;
		/*
		 * If work queue is busy during re-sending, shift
		 * @last_msg_sent back to last sent request; remaining
		 * requests will be processed in the following
		 * @tfw_http_conn_fwd_unsent call.
		 */
		if (err == -EBUSY) {
			srv_conn->last_msg_sent = (TfwMsg *)req_resent;
			return err;
		}
		/*
		 * Request has been removed from @fwd_queue due to some
		 * other error. Connection is alive, so we continue
		 * requests re-sending.
		 */
		if (err)
			continue;
		srv_conn->curr_msg_sent = (TfwMsg *)(req_resent = req);
		if (unlikely(first))
			break;
	}
	/*
	 * If only one first request is needed to be re-send, change
	 * @srv_conn->last_msg_sent only if it must be set to NULL. That
	 * means that all requests for re-sending - had not been
	 * re-sent, but instead have been evicted or removed due to
	 * some error, and we have no requests to re-send any more.
	 */
	if (!first || !req_resent) {
		srv_conn->curr_msg_sent =
			srv_conn->last_msg_sent = (TfwMsg *)req_resent;
	}

	return 0;
}

/*
 * Remove restrictions from a server connection.
 */
static inline void
__tfw_srv_conn_clear_restricted(TfwSrvConn *srv_conn)
{
	clear_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
	if (test_and_clear_bit(TFW_CONN_B_RESEND, &srv_conn->flags))
		TFW_DEC_STAT_BH(serv.conn_restricted);
}

/*
 * Make the connection full-functioning again if done with repair.
 */
static inline bool
tfw_srv_conn_reenable_if_done(TfwSrvConn *srv_conn)
{
	if (!list_empty(&srv_conn->fwd_queue))
		return false;
	BUG_ON(srv_conn->qsize);
	BUG_ON(srv_conn->last_msg_sent);
	BUG_ON(srv_conn->curr_msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	return true;
}

/*
 * Handle the complete re-forwarding of requests in a server connection
 * that is being repaired, after the first request had been re-forwarded.
 * The connection is not scheduled until all requests in it are re-sent.
 */
static int
tfw_http_conn_fwd_repair(TfwSrvConn *srv_conn, struct list_head *eq)
{
	int ret = 0;
	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(!tfw_srv_conn_restricted(srv_conn));

	if (tfw_srv_conn_reenable_if_done(srv_conn))
		return 0;
	if (test_bit(TFW_CONN_B_QFORWD, &srv_conn->flags)) {
		if (tfw_http_conn_need_fwd(srv_conn))
			ret = tfw_http_conn_fwd_unsent(srv_conn, eq);
	} else {
		/*
		 * Resend all previously forwarded requests. After that
		 * @srv_conn->last_msg_sent will be either NULL or the last
		 * request that was re-sent successfully. If re-sending
		 * of non-idempotent requests is allowed, then that last
		 * request may be non-idempotent. Continue with sending
		 * requests that were never forwarded only if the last
		 * request that was re-sent was NOT non-idempotent.
		 */
		if (tfw_http_conn_resend(srv_conn, false, eq) == -EBADF)
			return 0;
		set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		if (tfw_http_conn_need_fwd(srv_conn))
			ret = tfw_http_conn_fwd_unsent(srv_conn, eq);
	}
	tfw_srv_conn_reenable_if_done(srv_conn);

	return ret;
}

/*
 * Snip @fwd_queue (and @nip_queue) and move its contents to @out_queue.
 *
 * This is run under a lock, so spend minimum time under the lock and
 * do it fast while maintaining consistency. First destroy @nip_queue,
 * most often it has just one entry. Then snip @fwd_queue, move it to
 * @out_queue, and zero @qsize and @last_msg_sent.
 */
static void
tfw_http_conn_snip_fwd_queue(TfwSrvConn *srv_conn, struct list_head *out_queue)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, &srv_conn->nip_queue, nip_list)
		list_del_init(&req->nip_list);
	tfw_http_conn_nip_reset(srv_conn);
	list_splice_tail_init(&srv_conn->fwd_queue, out_queue);
	srv_conn->qsize = 0;
	srv_conn->curr_msg_sent = srv_conn->last_msg_sent = NULL;
}

/*
 * Find an outgoing server connection for an HTTP message.
 *
 * This function is always called in SoftIRQ context.
 */
static TfwSrvConn *
tfw_http_get_srv_conn(TfwMsg *msg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpSess *sess = req->sess;

	/* Sticky cookies are disabled or client doesn't support cookies. */
	if (!sess)
		return tfw_vhost_get_srv_conn(msg);

	return tfw_http_sess_get_srv_conn(msg);
}

/*
 * Re-schedule a request collected from a dead server connection's
 * queue to a live server connection.
 *
 * Note: the re-scheduled request is put at the tail of a new server's
 * connection queue, and NOT according to their original timestamps.
 * That's the intended behaviour. Such rescheduled requests are unlucky
 * already. They were delayed by waiting in their original server connections,
 * and then by the time spent on multiple attempts to reconnect. Now they
 * have much greater chance to be evicted when it's their turn to be
 * forwarded. The main effort is put into servicing requests that are on time.
 * Unlucky requests are just given another chance with minimal effort.
 */
static int
tfw_http_req_resched(TfwHttpReq *req, TfwServer *srv, struct list_head *eq)
{
	int ret;
	TfwSrvConn *sch_conn;

	/*
	 * Health monitoring requests must be re-scheduled to
	 * the same server (other servers may not have enabled
	 * health monitor).
	 */
	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		sch_conn = srv->sg->sched->sched_srv_conn((TfwMsg *)req, srv);
		if (!sch_conn) {
			list_del_init(&req->fwd_list);
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			T_WARN_ADDR("Unable to find connection to reschedule "
				    "health monitoring request on server",
				    &srv->addr, TFW_WITH_PORT);
			return 0;
		}
	} else if (!(sch_conn = tfw_http_get_srv_conn((TfwMsg *)req))) {
		T_DBG("Unable to find a backend server\n");
		tfw_http_send_err_resp(req, 502, "request dropped: unable to"
				   " find an available back end server");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return 0;
	} else {
		tfw_http_hm_srv_update((TfwServer *)sch_conn->peer,
				       req);
	}
	ret = tfw_http_req_fwd(sch_conn, req, eq, true);
	/*
	 * Paired with tfw_srv_conn_get_if_live() via sched_srv_conn callback or
	 * tfw_http_get_srv_conn() which increments the reference counter.
	 */
	tfw_srv_conn_put(sch_conn);

	return ret;
}

/*
 * Evict timed-out and dropped requests. Reschedule all the other
 * requests from the forwarding queue with up to limit of re-send
 * attempts.
 */
static void
tfw_http_fwdq_resched(TfwSrvConn *srv_conn, struct list_head *resch_queue,
		      struct list_head *eq)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;

	list_for_each_entry_safe(req, tmp, resch_queue, fwd_list) {
		INIT_LIST_HEAD(&req->nip_list);
		INIT_LIST_HEAD(&req->fwd_list);
		if (tfw_http_req_evict_stale_req(NULL, srv, req, eq))
			continue;
		if (unlikely(tfw_http_req_is_nip(req)
			     && !(srv->sg->flags & TFW_SRV_RETRY_NIP)))
		{
			tfw_http_nip_req_resched_err(NULL, req, eq);
			continue;
		}
		while (!tfw_http_req_evict_retries(NULL, srv, req, eq)) {
			if (!tfw_http_req_resched(req, srv, eq))
				break;
		}
	}
}

/*
 * Forward @req into server connection @srv_conn. Timed-out and dropped
 * requests are evicted to error queue @eq for sending an error response
 * later. If forwarding procedure returns error, then it considered
 * unfinished; in this case the connection's @fwd_queue will be reset
 * and all requests from it will be rescheduled to other connections.
 */
static void
tfw_http_req_fwd_resched(TfwSrvConn *srv_conn, TfwHttpReq *req,
			 struct list_head *eq)
{
	LIST_HEAD(reschq);

	T_DBG2("%s: srv_conn=[%p], req=[%p]\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_req_enlist(srv_conn, req);
	if (tfw_http_conn_on_hold(srv_conn)
	    || !tfw_http_conn_fwd_unsent(srv_conn, eq))
	{
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}
	tfw_srv_set_busy_delay(srv_conn);
	tfw_http_fwdq_reset(srv_conn, &reschq);
	spin_unlock_bh(&srv_conn->fwd_qlock);

	tfw_http_fwdq_resched(srv_conn, &reschq, eq);
}

/**
 * Process forwarding queue of a server connection to be released.
 * Timed-out requests and requests depleted number of re-send attempts are
 * evicted.
 *
 * Note: The limit on re-forward attempts is checked against the maximum value
 * for the current server group. Later the request is placed in another
 * connection in the same group. It's essential that all servers in a group have
 * the same limit. Otherwise, it will be necessary to check requests for
 * eviction _after_ a new connection is found.
 */
static void
tfw_http_conn_shrink_fwdq(TfwSrvConn *srv_conn)
{
	LIST_HEAD(eq);
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwdq = &srv_conn->fwd_queue;

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	spin_lock_bh(&srv_conn->fwd_qlock);
	if (list_empty(fwdq)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}

	BUG_ON(srv_conn->curr_msg_sent);

	/*
	 * Evict timed-out requests, NOT including the request that was sent
	 * last. Do it for requests that were sent before, no NIP requests are
	 * here. Don't touch unsent requests so far.
	 */
	if (srv_conn->last_msg_sent) {
		TfwMsg *msg_sent_prev;

		/* Similar to list_for_each_entry_safe_from() */
		req = list_first_entry(fwdq, TfwHttpReq, fwd_list);
		end = &((TfwHttpReq *)srv_conn->last_msg_sent)->fwd_list;
		for (tmp = list_next_entry(req, fwd_list);
		     &req->fwd_list != end;
		     req = tmp, tmp = list_next_entry(tmp, fwd_list))
		{
			tfw_http_req_evict_stale_req(srv_conn, srv, req, &eq);
		}
		/*
		 * Process the request that was forwarded last, and then
		 * reassign @srv_conn->last_msg_sent in case it is evicted.
		 * @req is now the same as @srv_conn->last_msg_sent.
		 */
		msg_sent_prev = __tfw_http_conn_msg_sent_prev(srv_conn);
		if (tfw_http_req_evict_stale_req(srv_conn, srv, req, &eq))
			srv_conn->last_msg_sent = msg_sent_prev;
	}

	/*
	 * Process the rest of the forwarding queue. These requests were never
	 * forwarded yet through the connection. Evict some of them by timeout.
	 */
	req = srv_conn->last_msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->last_msg_sent, fwd_list)
	    : list_first_entry(fwdq, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwdq, fwd_list)
		tfw_http_req_evict_stale_req(srv_conn, srv, req, &eq);

	spin_unlock_bh(&srv_conn->fwd_qlock);

	tfw_http_req_zap_error(&eq);
}

/**
 * The same as tfw_http_conn_shrink_fwdq(), but for connections which messages
 * must be rescheduled. Non-evicted requests are rescheduled to other
 * connections or servers.
 */
static void
tfw_http_conn_shrink_fwdq_resched(TfwSrvConn *srv_conn)
{
	LIST_HEAD(eq);
	LIST_HEAD(schq);

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	spin_lock_bh(&srv_conn->fwd_qlock);
	if (list_empty(&srv_conn->fwd_queue)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}
	tfw_http_fwdq_reset(srv_conn, &schq);
	spin_unlock_bh(&srv_conn->fwd_qlock);

	tfw_http_fwdq_resched(srv_conn, &schq, &eq);

	tfw_http_req_zap_error(&eq);
}

/*
 * Repair a connection. Makes sense only for server connections.
 *
 * Find requests in the server's connection queue that were forwarded
 * to the server. These are unanswered requests. According to RFC 7230
 * 6.3.2, "a client MUST NOT pipeline immediately after connection
 * establishment". To address that, re-send the first request to the
 * server. When a response comes, that will trigger resending of the
 * rest of those unanswered requests (tfw_http_conn_fwd_repair()).
 *
 * The connection is not scheduled until all requests in it are re-sent.
 *
 * The limit on the number of reconnect attempts is used to re-schedule
 * requests that would never be forwarded otherwise.
 *
 * No need to take a reference on the server connection here as this
 * is executed as part of establishing the connection. It definitely
 * can't go away.
 */
static void
tfw_http_conn_repair(TfwConn *conn)
{
	int err;
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	LIST_HEAD(reschq);
	LIST_HEAD(eq);

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	srv_conn->curr_msg_sent = NULL;

	/* See if requests need to be rescheduled. */
	if (unlikely(!tfw_srv_conn_live(srv_conn))) {
		if (tfw_srv_conn_need_resched(srv_conn))
			tfw_http_conn_shrink_fwdq_resched(srv_conn);
		else
			tfw_http_conn_shrink_fwdq(srv_conn);
		return;
	}

	spin_lock_bh(&srv_conn->fwd_qlock);
	if (list_empty(&srv_conn->fwd_queue)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}

	/* Treat a non-idempotent request if any. */
	tfw_http_conn_treatnip(srv_conn, &eq);

	/* Re-send only the first unanswered request. */
	err = tfw_http_conn_resend(srv_conn, true, &eq);
	if (err == -EBADF) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		goto out;
	}
	/*
	 * If re-sending procedure successfully passed,
	 * but requests had not been re-sent, and removed
	 * instead, then send the remaining unsent requests.
	 */
	if (!err && !srv_conn->last_msg_sent) {
		if (!list_empty(&srv_conn->fwd_queue)) {
			set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
			err = tfw_http_conn_fwd_unsent(srv_conn, &eq);
		}
		tfw_srv_conn_reenable_if_done(srv_conn);
	}
	/*
	 * Move out if re-sending/sending procedures are
	 * passed without errors.
	 */
	if (!err) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		goto out;
	}

	/*
	 * In case of requests re-sending error (-EBUSY) or
	 * requests forwarding error (-EBUSY and @last_msg_sent
	 * is NULL) the reschedule procedure is started;
	 * @last_msg_sent is definitely NULL here, so there are
	 * no unanswered requests and we can cut all remaining
	 * requests from @fwd_queue for rescheduling.
	 */
	WARN_ON(srv_conn->curr_msg_sent || srv_conn->last_msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	tfw_srv_set_busy_delay(srv_conn);
	tfw_http_fwdq_reset(srv_conn, &reschq);
	spin_unlock_bh(&srv_conn->fwd_qlock);
	tfw_http_fwdq_resched(srv_conn, &reschq, &eq);
out:
	tfw_http_req_zap_error(&eq);
}

/*
 * Destructor for a request message.
 */
void
tfw_http_req_destruct(void *msg)
{
	TfwHttpReq *req = msg;

	WARN_ON_ONCE(!list_empty(&req->msg.seq_list));
	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	tfw_vhost_put(req->vhost);
	if (req->sess)
		tfw_http_sess_put(req->sess);

	if (req->peer)
		tfw_client_put(req->peer);

	if (req->old_head)
		ss_skb_queue_purge(&req->old_head);

	if (req->stale_ce)
		tfw_cache_put_entry(req->node, req->stale_ce);
}

/**
 * Request messages that were forwarded to a backend server are added
 * to and kept in @fwd_queue of the connection @conn for that server.
 * If a paired request is not found, then the response must be deleted.
 *
 * If a paired client request is missing, then it seems upstream server
 * is misbehaving, so the caller has to drop the server connection.
 *
 * Correct response parsing is only possible when request properties,
 * such as method, are known. Thus resp->req pairing is mandatory. In the
 * same time req->resp pairing is not required until response is ready to
 * be forwarded to client. It's needed to avoid passing both resp and req
 * across all functions and creating indirect req<->resp pairing.
 */
static int
tfw_http_resp_pair(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmresp->conn;

	spin_lock(&srv_conn->fwd_qlock);

	if (unlikely(!srv_conn->curr_msg_sent))
		goto end;

	list_for_each_entry(req, &srv_conn->fwd_queue, fwd_list) {
		if (!req->pair) {
			tfw_http_msg_pair((TfwHttpResp *)hmresp, req);
			spin_unlock(&srv_conn->fwd_qlock);

			return 0;
		}
		if (req == (TfwHttpReq *)srv_conn->curr_msg_sent)
			break;
	}

end:
	spin_unlock(&srv_conn->fwd_qlock);

	T_WARN("Paired request missing, HTTP Response Splitting attack?\n");
	TFW_INC_STAT_BH(serv.msgs_otherr);

	return -EINVAL;
}

/*
 * Allocate a new HTTP message structure and link it with the connection
 * instance. Increment the number of users of the instance. Initialize
 * GFSM for the message.
 */
static TfwMsg *
tfw_http_conn_msg_alloc(TfwConn *conn, TfwStream *stream)
{
	int type = TFW_CONN_TYPE(conn);
	TfwHttpMsg *hm = __tfw_http_msg_alloc(type, true);
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_connection_get(conn);
	hm->stream = stream;
	hm->cache_ctl.default_ttl = cache_default_ttl;

	if (type & Conn_Clnt)
		tfw_http_init_parser_req((TfwHttpReq *)hm);
	else
		tfw_http_init_parser_resp((TfwHttpResp *)hm);

	if (TFW_FSM_TYPE(conn->proto.type) == TFW_FSM_H2) {
		TfwHttpReq *req = (TfwHttpReq *)hm;

		if(!(req->pit.pool = __tfw_pool_new(0)))
			goto clean;
		req->pit.parsed_hdr = &req->stream->parser.hdr;
		__set_bit(TFW_HTTP_B_H2, req->flags);
		/* Version for HTTP/1 is filled by parser. */
		req->version = TFW_HTTP_VER_20;
	}

	if (type & Conn_Clnt) {
		TFW_INC_STAT_BH(clnt.rx_messages);
	} else {
		if (unlikely(tfw_http_resp_pair(hm)))
			goto clean;

		if (TFW_MSG_H2(hm->req)) {
			size_t sz = TFW_HDR_MAP_SZ(TFW_HDR_MAP_INIT_CNT);
			TfwHttpTransIter *mit = &((TfwHttpResp *)hm)->mit;

			mit->map = tfw_pool_alloc(hm->pool, sz);
			if (unlikely(!mit->map)) {
				T_WARN("HTTP/2: unable to allocate memory for"
				       " response header map\n");
				goto clean;
			}
			mit->map->size = TFW_HDR_MAP_INIT_CNT;
			mit->map->count = 0;
		}

		TFW_INC_STAT_BH(serv.rx_messages);
	}

	hm->jrxtstamp = jiffies;

	return (TfwMsg *)hm;
clean:
	tfw_http_conn_msg_free(hm);

	return NULL;
}

/*
 * Connection with a peer is created.
 *
 * Called when a connection is created. Initialize the connection's
 * state machine here.
 */
static int
tfw_http_conn_init(TfwConn *conn)
{
	T_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Srv) {
		TfwSrvConn *srv_conn = (TfwSrvConn *)conn;

		if (!list_empty(&srv_conn->fwd_queue)) {
			srv_conn->curr_msg_sent = NULL;
			set_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
			TFW_INC_STAT_BH(serv.conn_restricted);
		}
	}
	tfw_gfsm_state_init(&conn->state, conn, TFW_HTTP_FSM_INIT);
	return 0;
}

static int
tfw_http_conn_close(TfwConn *conn, bool sync)
{
	return ss_close(conn->sk, sync ? SS_F_SYNC : 0);
}

static int
tfw_http_conn_abort(TfwConn *c)
{
	return ss_close(c->sk, SS_F_ABORT_FORCE);
}

/*
 * Connection with a peer is released.
 *
 * This function is called when all users of a server connection are gone,
 * and the connection's resources can be released.
 *
 * If a server connection is in failover state, then the requests that were
 * sent to that server are kept in the queue until a paired response comes.
 * The responses will never come now. Keep the queue. When the connection
 * is restored the requests will be re-sent to the server.
 *
 * If a server connection is completely destroyed (on Tempesta's shutdown),
 * then all outstanding requests in @fwd_queue are dropped and released.
 * Depending on Tempesta's state, both user and kernel context threads
 * may try to do that at the same time. As @fwd_queue is moved atomically
 * to local @zap_queue, only one thread is able to proceed and release
 * the resources.
 */
static void
tfw_http_conn_release(TfwConn *conn)
{
	TfwHttpReq *req, *tmp;
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	LIST_HEAD(zap_queue);

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	if (likely(ss_active())) {
		/*
		 * Server is removed from configuration and won't be available
		 * any more, reschedule it's forward queue.
		 */
		if (unlikely(test_bit(TFW_CONN_B_DEL, &srv_conn->flags)))
			tfw_http_conn_shrink_fwdq_resched(srv_conn);
		__tfw_srv_conn_clear_restricted(srv_conn);

		return;
	}

	/*
	 * Destroy server connection's queues.
	 * Move all requests from them to @zap_queue.
	 */
	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_conn_snip_fwd_queue(srv_conn, &zap_queue);
	spin_unlock_bh(&srv_conn->fwd_qlock);

	/*
	 * Remove requests from @zap_queue (formerly @fwd_queue) and from
	 * @seq_queue of respective client connections, then destroy them.
	 */
	list_for_each_entry_safe(req, tmp, &zap_queue, fwd_list) {
		list_del_init(&req->fwd_list);
		if (!test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
			tfw_http_conn_req_clean(req);
		} else {
			BUG_ON(TFW_MSG_H2(req));
			BUG_ON(!list_empty(&req->msg.seq_list));
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
		}
	}
}

static inline void
tfw_http_free_req_carefully(TfwHttpReq *req, struct list_head *resp_del_queue)
{
	TfwHttpResp *resp = req->resp;

	/*
	 * If `resp->conn` is not zero and response keeps the last
	 * reference to the connection, we can't free this response
	 * under the `cli_conn->seq_qlock` or `cli->ret_qlock`.
	 * If response will be freed here, server connection will be
	 * released here and all requests from `fwd_list` will be freed
	 * or resent (depends on `ss_active`). Such requests are freed
	 * under the `cli_conn->seq_qlock` or resent under the
	 * `cli->ret_qlock`, where `cli_conn` is a appropriate client
	 * connection, which can be the same as current `cli_conn`.
	 */
	if (!resp->conn
	    || !__tfw_connection_get_if_last_ref(resp->conn))
	{
		tfw_http_resp_pair_free(req);
	} else {
		TfwHttpMsg *hmreq = (TfwHttpMsg *)req;

		list_add_tail(&resp->msg.seq_list, resp_del_queue);
		if (req->conn)
			tfw_http_conn_msg_unlink_conn(hmreq);
		tfw_http_msg_free(hmreq);
	}
}

static inline void
tfw_http_clear_resp_del_queue(struct list_head *resp_del_queue)
{
	TfwHttpResp *resp, *tmp_resp;
	/*
	 * TODO #687 Should be removed during reworking current architecture of
	 * the locking of `seq_queue` in client connections and `fwd_queue`
	 * in server connection.
	 */
	list_for_each_entry_safe(resp, tmp_resp, resp_del_queue, msg.seq_list) {
		tfw_connection_put(resp->conn);
		tfw_http_conn_msg_unlink_conn((TfwHttpMsg *)resp);
		tfw_http_msg_free((TfwHttpMsg *)resp);
	}
}

/*
 * Drop client connection's resources.
 *
 * Disintegrate the client connection's @seq_list. Requests without a paired
 * response have not been answered yet. They are held in the lists of server
 * connections until responses come. A paired response may be in use until
 * TFW_HTTP_B_RESP_READY flag is not set.  Don't free any of those requests.
 *
 * If a response comes or gets ready to forward after @seq_list is
 * disintegrated, then both the request and the response are dropped at the
 * sight of an empty list.
 *
 * Locking is necessary as @seq_list is constantly probed from server
 * connection threads.
 */
static void
tfw_http_conn_cli_drop(TfwCliConn *cli_conn)
{
	TfwHttpReq *req, *tmp_req;
	LIST_HEAD(resp_del_queue);
	struct list_head *seq_queue = &cli_conn->seq_queue;

	T_DBG2("%s: conn=[%p]\n", __func__, cli_conn);
	BUG_ON(!(TFW_CONN_TYPE(cli_conn) & Conn_Clnt));

	if (list_empty_careful(seq_queue))
		return;

	/*
	 * Disintegration of the list must be done under the lock.
	 * The list can't be just detached from seq_queue, and then
	 * be disintegrated without the lock. That would open a race
	 * condition with freeing of a request in tfw_http_resp_fwd().
	 */
	spin_lock(&cli_conn->seq_qlock);
	list_for_each_entry_safe(req, tmp_req, seq_queue, msg.seq_list) {
		/*
		 * Request must be destroyed if the response is fully processed
		 * and removed from fwd_queue. If the request is still in use
		 * immediately after REQ_DROP flag is set, the request-response
		 * pair can be destroyed in other thread.
		 */
		bool unused = req->resp
			&& test_bit(TFW_HTTP_B_RESP_READY, req->resp->flags);
		list_del_init(&req->msg.seq_list);
		smp_mb__before_atomic();
		set_bit(TFW_HTTP_B_REQ_DROP, req->flags);
		if (unused) {
			tfw_http_free_req_carefully(req, &resp_del_queue);			
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
	}
	spin_unlock(&cli_conn->seq_qlock);

	tfw_http_clear_resp_del_queue(&resp_del_queue);
}

/*
 * Connection with a peer is dropped.
 *
 * Release resources that are not needed anymore, and keep other
 * resources that are needed while there are users of the connection.
 */
static void tfw_http_resp_terminate(TfwHttpMsg *hm);

static void
tfw_http_conn_drop(TfwConn *conn)
{
	bool h2_mode = TFW_FSM_TYPE(conn->proto.type) == TFW_FSM_H2;

	T_DBG3("%s: conn=[%px]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		if (h2_mode) {
			TfwH2Ctx *ctx = tfw_h2_context_safe(conn);

			if (ctx)
				tfw_h2_conn_streams_cleanup(ctx);
		} else {
			tfw_http_conn_cli_drop((TfwCliConn *)conn);
		}
	}
	else if (conn->stream.msg) { /* server connection */
		if (!tfw_http_parse_terminate((TfwHttpMsg *)conn->stream.msg))
			tfw_http_resp_terminate((TfwHttpMsg *)conn->stream.msg);
	}

	if (!h2_mode)
		tfw_http_conn_msg_free((TfwHttpMsg *)conn->stream.msg);
}

/*
 * Send a message through the connection.
 *
 * Called when the connection is used to send a message through.
 */
static int
tfw_http_conn_send(TfwConn *conn, TfwMsg *msg)
{
	return ss_send(conn->sk, &msg->skb_head, msg->ss_flags);
}

/**
 * Create a sibling for @hm message.
 * Siblings in HTTP are pipelined HTTP messages that share the same SKB.
 */
static TfwHttpMsg *
tfw_http_msg_create_sibling(TfwHttpMsg *hm, struct sk_buff *skb)
{
	TfwHttpMsg *shm;

	T_DBG2("Create sibling message: conn %p, msg: %p, skb %p\n",
	       hm->conn, hm, skb);

	/* The sibling message belongs to the same connection. */
	shm = (TfwHttpMsg *)tfw_http_conn_msg_alloc(hm->conn, hm->stream);
	if (unlikely(!shm))
		return NULL;

	ss_skb_queue_tail(&shm->msg.skb_head, skb);
	return shm;
}
ALLOW_ERROR_INJECTION(tfw_http_msg_create_sibling, NULL);

/*
 * Add 'Date:' header field to an HTTP message.
 */
static int
tfw_http_set_hdr_date(TfwHttpMsg *hm)
{
	int r;
	char *s_date = *this_cpu_ptr(&g_buf);

	tfw_http_prep_date_from(s_date, ((TfwHttpResp *)hm)->date);
	r = tfw_http_msg_hdr_xfrm(hm, "date", sizeof("date") - 1,
				  s_date, SLEN(S_V_DATE),
				  TFW_HTTP_HDR_RAW, 0);
	if (r)
		T_ERR("Unable to add Date: header to msg [%p]\n", hm);
	else
		T_DBG2("Added Date: header to msg [%p]\n", hm);
	return r;
}

/*
 * Add 'Upgrade:' header for websocket upgrade messages
 */
static int
tfw_http_set_hdr_upgrade(TfwHttpMsg *hm, bool is_resp)
{
	int r = 0;

	if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, hm->flags)) {
		/*
		 * RFC7230#section-6.7:
		 * A server that sends a 101 (Switching Protocols) response
		 * MUST send an Upgrade header field to indicate the new
		 * protocol(s) to which the connection is being switched; if
		 * multiple protocol layers are being switched, the sender MUST
		 * list the protocols in layer-ascending order.
		 *
		 * We do expect neither upgrades besides 'websocket' nor
		 * multilayer upgrades. So we consider extra options as error.
		 */
		if (is_resp && ((TfwHttpResp *)hm)->status == 101
		    && test_bit(TFW_HTTP_B_UPGRADE_EXTRA, hm->flags))
		{
			T_ERR("Unable to add uncompliant 'Upgrade:' header "
			      "to msg [%p]\n", hm);
			return -EINVAL;
		}
		r = tfw_http_msg_hdr_xfrm(hm, "upgrade", SLEN("upgrade"),
				  "websocket", SLEN("websocket"),
				  TFW_HTTP_HDR_UPGRADE, 0);
		if (r)
			T_ERR("Unable to add Upgrade: header to msg [%p]\n", hm);
		else
			T_DBG2("Added Upgrade: header to msg [%p]\n", hm);
	}
	return r;
}

/*
 * Expand HTTP response with 'Date:' header field.
 */
int
tfw_http_expand_hdr_date(TfwHttpResp *resp)
{
	int r;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	TfwHttpTransIter *mit = &resp->mit;
	char *date = *this_cpu_ptr(&g_buf);
	TfwStr h_date = {
		.chunks = (TfwStr []){
			{ .data = S_F_DATE, .len = SLEN(S_F_DATE) },
			{ .data = date, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_F_DATE) + SLEN(S_V_DATE) + SLEN(S_CRLF),
		.nchunks = 3
	};

	tfw_http_prep_date_from(date, resp->date);
	r = tfw_http_msg_expand_data(&mit->iter, skb_head, &h_date, NULL);
	if (r)
		T_ERR("Unable to expand resp [%p] with 'Date:' header\n", resp);
	else
		T_DBG2("Epanded resp [%p] with 'Date:' header\n", resp);

	return r;
}

/**
 * Connection is to be closed after response for the request @req is forwarded
 * to the client. Don't process new requests from the client and update
 * message flags for proper "Connection: " header value.
 */
static inline void
tfw_http_req_set_conn_close(TfwHttpReq *req)
{
	TFW_CONN_TYPE(req->conn) |= Conn_Stop;
	set_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
}

/**
 * Expand HTTP/1.1 response with hop-by-hop headers. It is implied that this
 * procedure should be used only for cases when original hop-by-hop headers
 * is already removed from the response: e.g. creation HTTP/1.1-response from
 * the cache (see also comments for tfw_http_set_hdr_connection(),
 * tfw_http_set_hdr_keep_alive() and tfw_http_adjust_resp()).
 */
int
tfw_http_expand_hbh(TfwHttpResp *resp, unsigned short status)
{
	TfwHttpReq *req = resp->req;
	TfwHttpTransIter *mit = &resp->mit;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	bool proxy_close = test_bit(TFW_HTTP_B_CONN_CLOSE, resp->flags)
		&& (status / 100 == 4);
	TfwStr h_conn = {
		.chunks = (TfwStr []){
			{ .data = S_F_CONNECTION, .len = SLEN(S_F_CONNECTION) },
			{},
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_F_CONNECTION) + SLEN(S_CRLF),
		.nchunks = 3
	};
	bool add_h_conn = true;

	if (unlikely(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)
		     || proxy_close))
	{
		__TFW_STR_CH(&h_conn, 1)->data = S_V_CONN_CLOSE;
		__TFW_STR_CH(&h_conn, 1)->len = SLEN(S_V_CONN_CLOSE);
		h_conn.len += SLEN(S_V_CONN_CLOSE);
	}
	else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
	{
		__TFW_STR_CH(&h_conn, 1)->data = S_V_CONN_KA;
		__TFW_STR_CH(&h_conn, 1)->len = SLEN(S_V_CONN_KA);
		h_conn.len += SLEN(S_V_CONN_KA);
	}
	else
	{
		/* Empty connection: header. */
		add_h_conn = false;
	}

	if (unlikely(proxy_close))
		tfw_http_req_set_conn_close(req);

	return add_h_conn
		? tfw_http_msg_expand_data(&mit->iter, skb_head, &h_conn, NULL)
		: 0;
}

/**
 * Remove Connection header from HTTP message @msg if @conn_flg is zero,
 * and replace or set a new header value otherwise.
 *
 * SKBs may be shared by several HTTP messages. A shared SKB is not copied
 * but safely modified. Thus, a shared SKB is still owned by one CPU.
 */
static int
tfw_http_set_hdr_connection(TfwHttpMsg *hm, unsigned long conn_flg)
{
	int r;
	BUILD_BUG_ON(BIT_WORD(__TFW_HTTP_MSG_M_CONN) != 0);
	if (((hm->flags[0] & __TFW_HTTP_MSG_M_CONN) == conn_flg)
	    && (!TFW_STR_EMPTY(&hm->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION]))
	    && !test_bit(TFW_HTTP_B_CONN_EXTRA, hm->flags)
	    && !test_bit(TFW_HTTP_B_CONN_UPGRADE, hm->flags))
	{
		return 0;
	}

	/*
	 * We can see `TFW_HTTP_B_CONN_CLOSE` here only in case of 4XX
	 * response with 'Connection: close' option.
	 *
	 * For requests conn_flg by default is TFW_HTTP_B_CONN_KA.
	 */
	if (unlikely(conn_flg == BIT(TFW_HTTP_B_CONN_CLOSE)))
		return TFW_HTTP_MSG_HDR_XFRM(hm, "Connection", "close",
					     TFW_HTTP_HDR_CONNECTION, 0);

	if (conn_flg == BIT(TFW_HTTP_B_CONN_KA)) {
		if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, hm->flags)
		    && test_bit(TFW_HTTP_B_CONN_UPGRADE, hm->flags))
		{
			r = TFW_HTTP_MSG_HDR_XFRM(hm, "Connection",
						  "keep-alive, upgrade",
						  TFW_HTTP_HDR_CONNECTION, 0);
		}
		else {
			r = TFW_HTTP_MSG_HDR_XFRM(hm, "Connection",
						  "keep-alive",
						  TFW_HTTP_HDR_CONNECTION, 0);
		}
	} else {
		if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, hm->flags)
		    && test_bit(TFW_HTTP_B_CONN_UPGRADE, hm->flags))
		{
			r = TFW_HTTP_MSG_HDR_XFRM(hm, "Connection",
						  "upgrade",
						  TFW_HTTP_HDR_CONNECTION, 0);
		}
		else {
			r = TFW_HTTP_MSG_HDR_DEL(hm, "Connection",
						 TFW_HTTP_HDR_CONNECTION);
		}
	}

	return r;
}

/**
 * Add/Replace/Remove Keep-Alive header field to/from HTTP message.
 */
static int
tfw_http_set_hdr_keep_alive(TfwHttpMsg *hm, unsigned long conn_flg)
{
	int r;

	BUILD_BUG_ON(BIT_WORD(__TFW_HTTP_MSG_M_CONN) != 0);
	if ((hm->flags[0] & __TFW_HTTP_MSG_M_CONN) == conn_flg)
		return 0;

	switch (conn_flg) {
	case BIT(TFW_HTTP_B_CONN_CLOSE):
		r = TFW_HTTP_MSG_HDR_DEL(hm, "Keep-Alive",
					 TFW_HTTP_HDR_KEEP_ALIVE);
		if (unlikely(r && r != -ENOENT)) {
			T_WARN("Cannot delete Keep-Alive header (%d)\n", r);
			return r;
		}
		return 0;
	case BIT(TFW_HTTP_B_CONN_KA):
		/*
		 * If present, "Keep-Alive" header informs the other side
		 * of the timeout policy for a connection. Otherwise, it's
		 * presumed that default policy is in action.
		 *
		 * TODO: Add/Replace "Keep-Alive" header when Tempesta
		 * implements connection timeout policies and the policy
		 * for the connection differs from default policy.
		 */
		return 0;
	default:
		/*
		 * "Keep-Alive" header mandates that "Connection: keep-alive"
		 * header in present in HTTP message. HTTP/1.1 connections
		 * are keep-alive by default. If we want to add "Keep-Alive"
		 * header then "Connection: keep-alive" header must be added
		 * as well. TFW_HTTP_F_CONN_KA flag will force the addition
		 * of "Connection: keep-alive" header to HTTP message.
		 */
		return 0;
	}
}

/*
 * In case if response is stale, we should pass it with a warning.
 */
int
tfw_http_expand_stale_warn(TfwHttpResp *resp)
{
	/* TODO: adjust for #865 */
	struct sk_buff **skb_head = &resp->msg.skb_head;
	TfwHttpTransIter *mit = &resp->mit;
	TfwStr wh = {
		.chunks = (TfwStr []){
			{ .data = S_WARN, .len = SLEN(S_WARN) },
			{ .data = S_DLM, .len = SLEN(S_DLM) },
			{ .data = S_V_WARN, .len = SLEN(S_V_WARN) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_WARN) + SLEN(S_DLM) + SLEN(S_V_WARN) + SLEN(S_CRLF),
		.nchunks = 4,
	};

	return tfw_http_msg_expand_data(&mit->iter, skb_head, &wh, NULL);
}

static inline int
__tfw_http_add_hdr_via(TfwHttpMsg *hm, int http_version, bool from_cache)
{
	int r = 0;
	static const char * const s_http_version[] = {
		[0 ... _TFW_HTTP_VER_COUNT] = NULL,
		[TFW_HTTP_VER_09] = "0.9 ",
		[TFW_HTTP_VER_10] = "1.0 ",
		[TFW_HTTP_VER_11] = "1.1 ",
		[TFW_HTTP_VER_20] = "2.0 ",
	};
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	const TfwStr rh = {
		.chunks = (TfwStr []) {
			{ .data = S_F_VIA, .len = SLEN(S_F_VIA) },
			{ .data = (void *)s_http_version[http_version],
			  .len = 4 },
			{ .data = *this_cpu_ptr(&g_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_F_VIA) + 4 + g_vhost->hdr_via_len,
		.eolen = 2,
		.nchunks = 3
	};

	memcpy_fast(__TFW_STR_CH(&rh, 2)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);

	if (!from_cache) {
		r = tfw_http_msg_hdr_add(hm, &rh);
	}
	else {
		struct sk_buff **skb_head = &hm->msg.skb_head;
		TfwHttpTransIter *mit = &((TfwHttpResp *)hm)->mit;
		TfwStr crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };

		r = tfw_http_msg_expand_data(&mit->iter, skb_head, &rh, NULL);
		if (unlikely(r))
			goto finish;

		r = tfw_http_msg_expand_data(&mit->iter, skb_head,
					     &crlf, NULL);
	}

finish:
	if (r)
		T_ERR("Unable to add via: header to msg [%p]\n", hm);
	else
		T_DBG2("Added via: header to msg [%p]\n", hm);

	return r;
}

int tfw_http_expand_hdr_via(TfwHttpResp *resp)
{
	return __tfw_http_add_hdr_via((TfwHttpMsg *)resp, resp->req->version,
				      true);
}

static int
tfw_http_add_hdr_via(TfwHttpMsg *hm)
{
	return __tfw_http_add_hdr_via(hm, hm->version, false);
}

static int
tfw_http_add_x_forwarded_for(TfwHttpMsg *hm)
{
	int r;
	char *p, *buf = *this_cpu_ptr(&g_buf);

	p = ss_skb_fmt_src_addr(hm->msg.skb_head, buf);

	r = tfw_http_msg_hdr_xfrm(hm, "X-Forwarded-For",
				  sizeof("X-Forwarded-For") - 1, buf, p - buf,
				  TFW_HTTP_HDR_X_FORWARDED_FOR, 0);
	if (r)
		T_ERR("can't add X-Forwarded-For header for %.*s to msg %p",
		      (int)(p - buf), buf, hm);
	else
		T_DBG2("added X-Forwarded-For header for %.*s\n",
		       (int)(p - buf), buf);
	return r;
}

static int
tfw_http_add_hdr_clen(TfwHttpMsg *hm)
{
	int r;
	char *buf = *this_cpu_ptr(&g_buf);
	size_t cl_valsize = tfw_ultoa(hm->body.len, buf,
				      TFW_ULTOA_BUF_SIZ);

	r = tfw_http_msg_hdr_xfrm(hm, "Content-Length",
				  SLEN("Content-Length"), buf, cl_valsize,
				  TFW_HTTP_HDR_CONTENT_LENGTH, 0);

	if (unlikely(r))
		T_ERR("%s: unable to add 'content-length' header (msg=[%p])\n",
		      __func__, hm);
	else
		T_DBG3("%s: added 'content-length' header, msg=[%p]\n",
		       __func__, hm);

	return r;
}

/**
 * Compose Content-Type header field from scratch.
 *
 * A POST-request with multipart/form-data payload need a boundary, which is
 * supplied by a parameter in the Content-Type header field. There are strict
 * instructions on how to parse that parameter (see RFC 7231 and RFC 7230), but
 * application servers parse it in a non-standard way. For example, PHP checks
 * whenever parameter name contains substring "boundary", and thus happily takes
 * "xxboundaryxx". Such quirks are used to bypass web application firewalls.
 *
 * To make evasions harder, this function composes value of the Content-Type
 * field from the parsed data. All parameters other than "boundary" are dropped.
 */
static int
tfw_http_recreate_content_type_multipart_hdr(TfwHttpReq *req)
{
	TfwStr replacement = {
		.chunks = (TfwStr []) {
			TFW_STR_STRING("Content-Type"),
			TFW_STR_STRING(": "),
			TFW_STR_STRING("multipart/form-data; boundary="),
			req->multipart_boundary_raw,
		},
		.nchunks = 4,
	};
	TfwStr *c = replacement.chunks;

	BUG_ON(!TFW_STR_PLAIN(&req->multipart_boundary_raw));
	replacement.len = c[0].len + c[1].len + c[2].len + c[3].len;
	return tfw_http_msg_hdr_xfrm_str((TfwHttpMsg *)req, &replacement,
					 TFW_HTTP_HDR_CONTENT_TYPE, false);
}

static bool
tfw_http_should_validate_post_req(TfwHttpReq *req)
{
	if (req->location && req->location->validate_post_req)
		return true;

	if (WARN_ON_ONCE(!req->vhost))
		return false;

	if (req->vhost->loc_dflt && req->vhost->loc_dflt->validate_post_req)
		return true;

	if (req->vhost->vhost_dflt &&
	    req->vhost->vhost_dflt->loc_dflt->validate_post_req)
		return true;

	return false;
}

/**
 * Add local headers (defined by administrator in configuration file) to http/1
 * message.
 *
 * @hm		- Message to be updated;
 * @is_resp	- Message represents response, not request;
 * @from_cache	- The response is created from cache, not applied to requests.
 */
int
tfw_h1_set_loc_hdrs(TfwHttpMsg *hm, bool is_resp, bool from_cache)
{
	size_t i;
	int mod_type = is_resp ? TFW_VHOST_HDRMOD_RESP : TFW_VHOST_HDRMOD_REQ;
	TfwHttpReq *req = is_resp ? hm->req : (TfwHttpReq *)hm;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    mod_type);

	if(WARN_ON_ONCE(!is_resp && from_cache))
		return -EINVAL;
	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		int r;
		TfwHdrModsDesc *d = &h_mods->hdrs[i];
		/*
		 * Header is stored optimized for HTTP2: without delimiter
		 * between header and value. Add it as separate chunk as
		 * required for tfw_http_msg_hdr_xfrm_str.
		 */
		TfwStr h_mdf = {
			.chunks = (TfwStr []){
				{},
				{ .data = S_DLM, .len = SLEN(S_DLM) },
				{}
			},
			.len = SLEN(S_DLM),
			.nchunks = 2 /* header name + delimeter. */
		};

		h_mdf.chunks[0] = d->hdr->chunks[0];
		if (d->hdr->nchunks == 2) {
			h_mdf.chunks[2] = d->hdr->chunks[1];
			h_mdf.nchunks += 1;
		}
		h_mdf.len += d->hdr->len;
		h_mdf.flags = d->hdr->flags;
		h_mdf.eolen += d->hdr->eolen;

		/*
		 * A response is built from cache. Response is stored in
		 * cache optimised for h2 and it's being created
		 * header-by-header right away.
		 */
		if (from_cache) {
			TfwHttpResp *resp = (TfwHttpResp *)hm;
			struct sk_buff **skb_head = &resp->msg.skb_head;
			TfwHttpTransIter *mit = &resp->mit;
			TfwStr crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };
			/*
			 * Skip the configured header if the header is
			 * configured for deletion (without value chunk).
			 */
			if (h_mdf.nchunks < 3)
				continue;
			/* h_mdf->eolen is ignored, add explicit CRLF. */
			r = tfw_http_msg_expand_data(&mit->iter, skb_head,
						     &h_mdf, NULL);
			if (unlikely(r))
				goto finish;

			r = tfw_http_msg_expand_data(&mit->iter, skb_head,
						     &crlf, NULL);
		} else {
			r = tfw_http_msg_hdr_xfrm_str(hm, &h_mdf, d->hid,
						      d->append);
		}

finish:
		if (r) {
			T_ERR("can't update location-specific header in msg %p\n",
			      hm);
			return r;
		}

		T_DBG2("updated location-specific header in msg %p\n", hm);
	}

	return 0;
}

static int
tfw_h1_rewrite_method_to_get(struct sk_buff **head_p, size_t chop_len)
{
	const char *q = "GET";
	char *p;
	struct skb_shared_info *si;
	struct sk_buff *skb, *head;
	unsigned int f, z;
	int ret;

	/* Possible if somehow we already sent a response  */
	BUG_ON(!*head_p);

	/* Chop two bytes from the beginning of SKB data. */
	ret = ss_skb_list_chop_head_tail(head_p, chop_len, 0);
	if (ret)
		return ret;
	/* List head element *head_p could change above */
	skb = head = *head_p;

	do {
		p = skb->data;
		z = skb_headlen(skb);
		while (z--) {
			*p++ = *q++;
			if (!*q)
				return 0;
		}
		si = skb_shinfo(skb);
		for (f = 0; f < si->nr_frags; ++f) {
			p = skb_frag_address(&si->frags[f]);
			z = skb_frag_size(&si->frags[f]);
			while (z--) {
				*p++ = *q++;
				if (!*q)
					return 0;
			}
		}
		skb = skb->next;
	} while (skb != head);

	T_ERR("Not enough skb data for method rewrite?!\n");
	return -ENOMEM;
}

/*
 * Rewrite HTTP/1 "PURGE" method to "GET" directly inside a request SKB.
 */
static int
tfw_h1_rewrite_purge_to_get(struct sk_buff **head_p)
{
	return tfw_h1_rewrite_method_to_get(head_p, 2);
}

/*
 * Rewrite HTTP/1 "HEAD" method to "GET" directly inside a request SKB.
 */
static int
tfw_h1_rewrite_head_to_get(struct sk_buff **head_p)
{
	return tfw_h1_rewrite_method_to_get(head_p, 1);
}

static int
tfw_h1_req_del_expect_hdr(TfwHttpMsg *hm)
{
	static TfwStr val = {};

	if (test_bit(TFW_HTTP_B_EXPECT_CONTINUE, hm->flags))
		return tfw_http_msg_hdr_xfrm_str(hm, &val, TFW_HTTP_HDR_EXPECT,
						 false);

	return 0;
}

/**
 * Adjust the request before proxying it to real server.
 */
static int
tfw_h1_adjust_req(TfwHttpReq *req)
{
	int r;
	unsigned int n_to_strip = 0;
	TfwHttpMsg *hm = (TfwHttpMsg *)req;

	n_to_strip = !!test_bit(TFW_HTTP_B_NEED_STRIP_LEADING_CR, req->flags) +
		     !!test_bit(TFW_HTTP_B_NEED_STRIP_LEADING_LF, req->flags);
	if (unlikely(n_to_strip)) {
		r =  ss_skb_list_chop_head_tail(&hm->msg.skb_head, n_to_strip, 0);
		if (r)
			return r;
	}

	if (test_bit(TFW_HTTP_B_PURGE_GET, req->flags)) {
		r = tfw_h1_rewrite_purge_to_get(&hm->msg.skb_head);
		if (unlikely(r))
			return r;
	}
	else if (test_bit(TFW_HTTP_B_REQ_HEAD_TO_GET, req->flags)) {
		r = tfw_h1_rewrite_head_to_get(&hm->msg.skb_head);
		if (unlikely(r))
			return r;
	}

	r = tfw_h1_req_del_expect_hdr(hm);
	if (r)
		return r;

	r = tfw_http_add_x_forwarded_for(hm);
	if (r)
		return r;

	r = tfw_http_add_hdr_via(hm);
	if (r)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
	if (r < 0)
		return r;

	r = tfw_http_set_hdr_upgrade(hm, false);
	if (r < 0)
		return r;

	r = tfw_h1_set_loc_hdrs(hm, false, false);
	if (r < 0)
		return r;

	if (req->method == TFW_HTTP_METH_POST &&
	    test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags) &&
	    tfw_http_should_validate_post_req(req))
	{
		r = tfw_http_recreate_content_type_multipart_hdr(req);
		if (r)
			return r;
	}

	return tfw_http_set_hdr_connection(hm, BIT(TFW_HTTP_B_CONN_KA));
}

static inline void
__h2_hdrs_dup_decrease(TfwHttpReq *req, const TfwStr *hdr)
{
	const TfwStr *dup, *dup_end;
	TfwMsgParseIter *it = &req->pit;

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		--it->hdrs_cnt;
		it->hdrs_len -= dup->len;
	}
}

/**
 * Apply header modification. @hdr contains exactly two chunks: header name and
 * value.
 *
 * The @hdr descriptor (top level TfwStr is copied directly into header table.
 * It looks dangerous but it's safe and we avoid extra copy operations.
 * @req holds a reference to vhost, and @hdr value is stored inside that
 * vhost/location description. On reconfiguration a new vhost instance is
 * created instead of alternating its settings in place. So @hdr will valid
 * until request itself is alive.
 *
 * Since h2 requests are always converted to http1 and all headers are
 * recreated from cratch, there is no need to fragment underlying skbs and copy
 * data there, it's enough to put safe pointers inside header table.
 */
static int
__h2_req_hdrs(TfwHttpReq *req, const TfwStr *hdr, unsigned int hid, bool append)
{
	TfwStr *orig_hdr;
	TfwHttpMsg *hm = (TfwHttpMsg *)req;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwMsgParseIter *it = &req->pit;
	const TfwStr *s_val = TFW_STR_CHUNK(hdr, 1);

	if (WARN_ON_ONCE(!ht))
		return -EINVAL;

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		T_WARN("Appending to singular header %d\n", hid);
		return -ENOENT;
	}

	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		/*
		 * Insert special header if empty and exit if we have nothing
		 * to insert.
		 */
		if (TFW_STR_EMPTY(orig_hdr)) {
			if (unlikely(!s_val))
				return 0;
			++it->hdrs_cnt;
			it->hdrs_len += hdr->len;
			*orig_hdr = *hdr;
			return 0;
		}
	}
	else {
		hid = __http_hdr_lookup(hm, hdr);
		if (hid == ht->off && !s_val)
			/*
			 * The raw header not found, and there is nothing
			 * to delete.
			 */
			return 0;
		if (unlikely(hid == ht->size)) {
			if (tfw_http_msg_grow_hdr_tbl(hm))
				return -ENOMEM;
			ht = hm->h_tbl;
		}
		if (hid == ht->off) {
			/*
			 * The raw header not found, but we have the new
			 * header to insert.
			 */
			++ht->off;
			++it->hdrs_cnt;
			it->hdrs_len += hdr->len;
			ht->tbl[hid] = *hdr;
			return 0;
		}
		orig_hdr = &ht->tbl[hid];
	}

	BUG_ON(TFW_STR_EMPTY(orig_hdr));
	/*
	 * The original header exists, but we have nothing to insert, thus,
	 * the original header should be evicted.
	 */
	if (!s_val) {
		__h2_hdrs_dup_decrease(req, orig_hdr);
		TFW_STR_INIT(orig_hdr);
		return 0;
	}

	if (append) {
		TfwStr h_app = {
			.chunks = (TfwStr []){
				{ .data = ", ",		.len = 2 },
				{ .data = s_val->data,	.len = s_val->len }
			},
			.len = s_val->len + 2,
			.nchunks = 2
		};
		/*
		 * Concatenate only the first duplicate header, there is no need
		 * to produce more duplicates.
		 */
		if (TFW_STR_DUP(orig_hdr))
			orig_hdr = __TFW_STR_CH(orig_hdr, 0);

		it->hdrs_len += h_app.len;
		return tfw_strcat(req->pool, orig_hdr, &h_app);
	}
	/*
	 * The remaining case is the substitution, since we have both: existing
	 * original header and the new header to insert.
	 */
	__h2_hdrs_dup_decrease(req, orig_hdr);
	++it->hdrs_cnt;
	it->hdrs_len += hdr->len;
	*orig_hdr = *hdr;

	return 0;
}

static int
tfw_h2_req_set_loc_hdrs(TfwHttpReq *req)
{
	int i;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    TFW_VHOST_HDRMOD_REQ);
	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		int r;
		TfwHdrModsDesc *d = &h_mods->hdrs[i];

		if ((r = __h2_req_hdrs(req, d->hdr, d->hid, d->append)))  {
			T_ERR("HTTP/2: can't update location-specific header in"
			      " the request [%p]\n", req);
			return r;
		}
	}

	/*
	 * When header modifications contains `req_hdr_set` rule for `Host`
	 * header, __h2_req_hdrs modifies only TFW_HTTP_HDR_HOST leaves
	 * TFW_HTTP_HDR_H2_AUTHORITY untouched. We manualy assign new `Host`
	 * to TFW_HTTP_HDR_H2_AUTHORITY for consistency between `Host` and
	 * `authority:`. Espicially because `authority:` has higher priotiy
	 * and can be used instead of `Host` header during request modification
	 * when forwarding to backend.
	 */
	if (h_mods->spec_hdrs[TFW_HTTP_HDR_HOST]) {
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];

		req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY] = *host;
	}

	return 0;
}

/**
 * Fuse multiple cookie headers into one.
 * Works only with TFW_STR_DUP strings. */
static int
write_merged_cookie_headers(TfwStr *hdr, TfwMsgIter *it)
{
	int r = 0;
	static const DEFINE_TFW_STR(h_cookie, "cookie" S_DLM);
	static const DEFINE_TFW_STR(val_dlm, "; ");
	static const DEFINE_TFW_STR(crlf, S_CRLF);
	TfwStr *dup, *dup_end;
	const TfwStr *cookie_dlm = &h_cookie;

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		TfwStr *chunk, *chunk_end, hval = {};

		if (unlikely(TFW_STR_PLAIN(dup)))
			return -EINVAL;

		hval.chunks = dup->chunks;
		hval.nchunks = dup->nchunks;
		hval.len = dup->len;
		TFW_STR_FOR_EACH_CHUNK(chunk, dup, chunk_end) {
			if (chunk->flags & TFW_STR_HDR_VALUE)
				break;
			hval.chunks++;
			hval.nchunks--;
			hval.len -= chunk->len;
		}
		r = tfw_msg_write(it, cookie_dlm);
		if (unlikely(r))
			return r;

		r = tfw_msg_write(it, &hval);
		if (unlikely(r))
			return r;

		cookie_dlm = &val_dlm;
	}

	return tfw_msg_write(it, &crlf);
}

static int
__h2_write_method(TfwHttpReq *req, TfwMsgIter *it)
{
	TfwHttpHdrTbl *ht = req->h_tbl;

	if (test_bit(TFW_HTTP_B_REQ_HEAD_TO_GET, req->flags)) {
		static const DEFINE_TFW_STR(meth_get, "GET");

		return tfw_msg_write(it, &meth_get);
	} else {
		TfwStr meth = {};

		__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_H2_METHOD], &meth);
		return tfw_msg_write(it, &meth);
	}
}

/**
 * Transform h2 request to http1.1 request before forward it to backend server.
 * Usually we prefer in-place header modifications avoid copying, but here
 * we have to insert a lot of information into header, like delimiters between
 * header name and value, and between headers. To avoid creating extreme number
 * of skb fragments we cut off skbs with h2 headers from the beginning of the
 * request and replace them with http1.1 headers.
 *
 * Note, that we keep original headers in h_tbl untouched, since the response
 * may want to access the request headers: the cache subsystem reads `Host`
 * header and `uri` part, also if 'Vary' header controls response
 * representation, any header listed inside 'Vary' one may be also read on
 * response processing (not implemented yet).
 */
static int
tfw_h2_adjust_req(TfwHttpReq *req)
{
	int r;
	TfwMsgParseIter *pit = &req->pit;
	ssize_t h1_hdrs_sz;
	TfwHttpHdrTbl *ht = req->h_tbl;
	bool auth, host;
	size_t pseudo_num;
	TfwStr host_val = {}, *field, *end;
	struct sk_buff *new_head = NULL, *old_head = NULL;
	TfwMsgIter it;
	static const DEFINE_TFW_STR(sp, " ");
	static const DEFINE_TFW_STR(dlm, S_DLM);
	static const DEFINE_TFW_STR(crlf, S_CRLF);
	static const DEFINE_TFW_STR(fl_end, " " S_VERSION11 S_CRLF S_F_HOST);
	char *buf = *this_cpu_ptr(&g_buf);
	char *xff_end = ss_skb_fmt_src_addr(req->msg.skb_head, buf);
	const TfwStr h_xff = {
		.chunks = (TfwStr []){
			{ .data = S_XFF, .len = SLEN(S_XFF) },
			{ .data = S_DLM, .len = SLEN(S_DLM) },
			{ .data = buf, .len = xff_end - buf },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_XFF) + SLEN(S_DLM) + xff_end - buf + SLEN(S_CRLF),
		.nchunks = 4
	};
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	const TfwStr h_via = {
		.chunks = (TfwStr []) {
			{ .data = S_F_VIA, .len = SLEN(S_F_VIA) },
			{ .data = "1.1 ", .len = 4 },
			{ .data = (char *)g_vhost->hdr_via,
			  .len = g_vhost->hdr_via_len },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_F_VIA) + 4 + g_vhost->hdr_via_len + SLEN(S_CRLF),
		.nchunks = 4
	};
	const TfwStr h_ct = {
		.chunks = (TfwStr []) {
			{ .data = S_F_CONTENT_TYPE S_V_MULTIPART,
			  .len = SLEN(S_F_CONTENT_TYPE S_V_MULTIPART) },
			req->multipart_boundary_raw,
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.nchunks = 3,
		.len = SLEN(S_F_CONTENT_TYPE S_V_MULTIPART)
			+ req->multipart_boundary_raw.len + SLEN(S_CRLF)
	};
	int h_ct_replace = 0;
	TfwStr h_cl = {0};
	char cl_data[TFW_ULTOA_BUF_SIZ] = {0};
	size_t cl_data_len = 0;
	size_t cl_len = 0;
	/*
	 * The Transfer-Encoding header field cannot be in the h2 request, because
	 * requests with Transfer-Encoding are blocked.
	 */
	bool need_cl = req->body.len &&
		       TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH]);

	if (need_cl) {
		cl_data_len = tfw_ultoa(req->body.len, cl_data, TFW_ULTOA_BUF_SIZ);
		if (!cl_data_len)
			return -EINVAL;
		cl_len = SLEN("Content-Length") + SLEN(S_DLM) + cl_data_len + SLEN(S_CRLF);
	}

	T_DBG3("%s: req [%p] to be converted to http1.1\n", __func__, req);

	/*
	 * First apply message modifications defined by admin in configuration
	 * file. Ideally we should do it at last stage, when h2 headers are
	 * copied into h1 buffer and apply modifications during copying. But
	 * this doesn't allow us to predict h1 headers size before memory
	 * allocation. Header modifications manual on wiki is already has a
	 * warning about performance impact, so just live it as is, a more
	 * robust algorithm will be used here if really required.
	 */
	if ((r = tfw_h2_req_set_loc_hdrs(req)))
		return r;
	/*
	 * tfw_h2_req_set_loc_hdrs() may realloc header table and user may
	 * defined headers modifications, even headers we rely on, recheck them.
	 */
	ht = req->h_tbl;
	auth = !TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY]);
	host = !TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_HOST]);
	pseudo_num = 3; /* Count authority as usual header for now. */
	/*
	 * Calculate http1.1 headers size. H2 request contains pseudo headers
	 * that are represented in different way in the http1.1 requests.
	 * pit->hdrs_cnt is aware of header duplicates. Redirection mark is
	 * ignored and not copied.
	 */
	h1_hdrs_sz = pit->hdrs_len
		+ (pit->hdrs_cnt - pseudo_num) * (SLEN(S_DLM) + SLEN(S_CRLF));
	/* First request line: remove pseudo headers names, all values are on
	 * the same line.
	 */
	h1_hdrs_sz += (long int)2 + SLEN(S_VERSION11) + SLEN(S_CRLF)
			- ht->tbl[TFW_HTTP_HDR_H2_SCHEME].len
			- SLEN(S_H2_METHOD)
			- SLEN(S_H2_PATH)
			+ SLEN(S_CRLF) /* After headers */;
	/* :authority pseudo header */
	if (auth) {
		/* RFC 7540:
		 * An intermediary that converts an HTTP/2 request to HTTP/1.1
		 * MUST create a Host header field if one is not present in a
		 * request by copying the value of the :authority pseudo-header
		 * field.
		 * AND
		 * Clients that generate HTTP/2 requests directly SHOULD use
		 * the :authority pseudo-header field instead of the Host
		 * header field.
		 */
		if (host) {
			h1_hdrs_sz -= ht->tbl[TFW_HTTP_HDR_HOST].len
					+ SLEN(S_DLM) + SLEN(S_CRLF);
			h1_hdrs_sz -= SLEN(S_H2_AUTH);
			/* S_F_HOST already contains S_DLM */
			h1_hdrs_sz += SLEN(S_F_HOST) - SLEN(S_DLM);
		}
		else {
			h1_hdrs_sz -= SLEN(S_H2_AUTH);
			/* S_F_HOST already contains S_DLM */
			h1_hdrs_sz += SLEN(S_F_HOST) - SLEN(S_DLM);
		}
	}

	/* 'x-forwarded-for' header must be updated. */
	if (!TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR])) {
		TfwStr *xff_hdr = &ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		TfwStr *dup, *dup_end;

		TFW_STR_FOR_EACH_DUP(dup, xff_hdr, dup_end) {
			h1_hdrs_sz -= dup->len + SLEN(S_DLM) + SLEN(S_CRLF);
		}
	}
	h1_hdrs_sz += h_xff.len;
	h1_hdrs_sz += h_via.len;
	h1_hdrs_sz += cl_len;

	/* Adjust header size based on how many cookie headers there were in
	 * request. */
	if (TFW_STR_DUP(&ht->tbl[TFW_HTTP_HDR_COOKIE]))
		h1_hdrs_sz -= (ht->tbl[TFW_HTTP_HDR_COOKIE].nchunks - 1)
		              * (SLEN("cookie") + SLEN(S_DLM));

	/*
	 * Conditional substitution/additions of 'content-type' header. This is
	 * singular header, so we can avoid duplicates processing.
	 */
	if (req->method == TFW_HTTP_METH_POST &&
	    test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags) &&
	    tfw_http_should_validate_post_req(req))
	{
		TfwStr *h_ct_old = &ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE];

		if (WARN_ON_ONCE(!TFW_STR_PLAIN(&req->multipart_boundary_raw)
				 || TFW_STR_EMPTY(h_ct_old)))
			return -EINVAL;

		h1_hdrs_sz -= h_ct_old->len + SLEN(S_DLM) + SLEN(S_CRLF);
		h1_hdrs_sz += h_ct.len;
		h_ct_replace = 1;
	}

	if (WARN_ON_ONCE(h1_hdrs_sz < 0))
		return -EINVAL;

	r = tfw_msg_iter_setup(&it, &new_head, h1_hdrs_sz, 0);
	if (unlikely(r))
		return r;

	/* First line. */
	r = __h2_write_method(req, &it);
	if (unlikely(r))
		goto err;

	r = tfw_msg_write(&it, &sp);
	if (unlikely(r))
		goto err;

	r = tfw_msg_write(&it, &req->uri_path);
	if (unlikely(r))
		goto err;

	r = tfw_msg_write(&it, &fl_end); /* start of Host: header */
	if (unlikely(r))
		goto err;

	if (auth)
		__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY], &host_val);
	else if (host)
		__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_HOST], &host_val);

	r = tfw_msg_write(&it, &host_val);
	if (unlikely(r))
		goto err;

	r = tfw_msg_write(&it, &crlf);
	if (unlikely(r))
		goto err;

	/* Skip host header: it's already written. */
	FOR_EACH_HDR_FIELD_FROM(field, end, req, TFW_HTTP_HDR_REGULAR) {
		TfwStr *dup, *dup_end;

		switch (field - ht->tbl)
		{
		case TFW_HTTP_HDR_HOST:
			continue; /* Already written. */
		case TFW_HTTP_HDR_X_FORWARDED_FOR:
			r = tfw_msg_write(&it, &h_xff);
			if (unlikely(r))
				goto err;
			continue;
		case TFW_HTTP_HDR_CONTENT_TYPE:
			if (h_ct_replace) {
				r = tfw_msg_write(&it, &h_ct);
				if (unlikely(r))
					goto err;
				continue;
			}
			break;
		case TFW_HTTP_HDR_COOKIE:
			if (!TFW_STR_DUP(field))
				break;
			r = write_merged_cookie_headers(
					&ht->tbl[TFW_HTTP_HDR_COOKIE], &it);
			if (unlikely(r))
				goto err;
			continue;
		default:
			break;
		}

		if (TFW_STR_EMPTY(field))
			continue;
		TFW_STR_FOR_EACH_DUP(dup, field, dup_end) {
			TfwStr *chunk, *chunk_end, hval = {};

			if (unlikely(TFW_STR_PLAIN(dup))) {
				r = -EINVAL;
				goto err;
			}

			hval.chunks = dup->chunks;
			TFW_STR_FOR_EACH_CHUNK(chunk, dup, chunk_end) {
				if (chunk->flags & TFW_STR_HDR_VALUE)
					break;
				hval.nchunks++;
				hval.len += chunk->len;
			}
			r = tfw_msg_write(&it, &hval);
			if (unlikely(r))
				goto err;
			r = tfw_msg_write(&it, &dlm);
			if (unlikely(r))
				goto err;

			hval.chunks += hval.nchunks;
			hval.nchunks = dup->nchunks - hval.nchunks;
			hval.len = dup->len - hval.len;

			r = tfw_msg_write(&it, &hval);
			if (unlikely(r))
				goto err;

			r = tfw_msg_write(&it, &crlf);
			if (unlikely(r))
				goto err;
		}
		if (unlikely(r))
			goto err;
	}

	r = tfw_msg_write(&it, &h_via);
	if (unlikely(r))
		goto err;

	if (need_cl) {
		h_cl = (TfwStr) {
			.chunks = (TfwStr []) {
				{ .data = "Content-Length", .len = SLEN("Content-Length") },
				{ .data = S_DLM, .len = SLEN(S_DLM) },
				{ .data = cl_data, .len = cl_data_len },
				{ .data = S_CRLF, .len = SLEN(S_CRLF) }
			},
			.len = cl_len,
			.nchunks = 4
		};
		r = tfw_msg_write(&it, &h_cl);
		if (unlikely(r))
			goto err;
	}
	/* Finally close headers. */
	r = tfw_msg_write(&it, &crlf);
	if (unlikely(r))
		goto err;

	T_DBG3("%s: req [%p] converted to http1.1\n", __func__, req);

	old_head = req->msg.skb_head;
	req->old_head = old_head;
	req->msg.skb_head = new_head;

	/* Http chains might add a mark for the message, keep it. */
	new_head->mark = old_head->mark;

	if (!TFW_STR_EMPTY(&req->body)) {
		/*
		 * Request has a body. we have to detach it from the old
		 * skb_head and append to a new one. There might be trailing
		 * headers after the body, but we're already copied them before
		 * body. This is not a problem, but we have to drop the trailer
		 * part after the body to avoid sending the same headers twice.
		 *
		 * Body travels in a separate DATA frame thus it's always in
		 * it's own skb.
		 */
		struct sk_buff *b_skbs = old_head, *trailer;
		size_t len = 0;

		do {
			b_skbs = b_skbs->next;
			if (WARN_ON_ONCE((b_skbs == old_head)))
				goto err;
		} while (b_skbs != req->body.skb);

		ss_skb_queue_split(old_head, b_skbs);
		trailer = b_skbs;
		do {
			len += trailer->len;
			trailer = trailer->next;

		} while ((trailer != b_skbs) && (len != req->body.len));
		ss_skb_queue_append(&req->msg.skb_head, b_skbs);
		if (trailer != b_skbs) {
			ss_skb_queue_split(req->msg.skb_head, trailer);
			ss_skb_queue_append(&old_head, trailer);
		}
	}

	return 0;

err:
	ss_skb_queue_purge(&new_head);
	T_DBG3("%s: req [%px] convertation to http1.1 has failed"
	       " with result (%d)\n", __func__, req, r);
	return r;
}

/*
 * Throw away a response body and set "Content-Length" to zero.
 */
static int
tfw_h1_purge_resp_clean(TfwHttpResp *resp)
{
	int ret;
	TfwStr replacement = {
		.chunks = (TfwStr []) {
			TFW_STR_STRING("Content-Length"),
			TFW_STR_STRING(": "),
			TFW_STR_STRING("0"),
		},
		.nchunks = 3,
	};
	TfwStr *c = replacement.chunks;

	if (!TFW_STR_EMPTY(&resp->body)) {
		ret = ss_skb_list_chop_head_tail(&resp->msg.skb_head,
				0, tfw_str_total_len(&resp->body));
		if (ret)
			return ret;
		TFW_STR_INIT(&resp->body);
	}

	replacement.len = c[0].len + c[1].len + c[2].len;
	return tfw_http_msg_hdr_xfrm_str((TfwHttpMsg *)resp, &replacement,
					 TFW_HTTP_HDR_CONTENT_LENGTH, false);
}

/**
 * Adjust the response before proxying it to real client.
 */
static int
tfw_http_adjust_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwHttpMsg *hm = (TfwHttpMsg *)resp;
	unsigned long conn_flg = 0;
	int r;

	/*
	 * If request violated backend rules, backend may respond with 4xx code
	 * and close connection to Tempesta. Don't encourage client to send
	 * more such requests and cause performance degradation, close the
	 * client connection.
	 */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, resp->flags)
	    && (resp->status / 100 == 4))
	{
		tfw_http_req_set_conn_close(req);
		conn_flg = BIT(TFW_HTTP_B_CONN_CLOSE);
	}
	else
	{
		if (unlikely(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)))
			conn_flg = BIT(TFW_HTTP_B_CONN_CLOSE);
		else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
			conn_flg = BIT(TFW_HTTP_B_CONN_KA);
	}

	if (test_bit(TFW_HTTP_B_REQ_HEAD_TO_GET, req->flags)
	    && !TFW_STR_EMPTY(&resp->body)) {
		r = ss_skb_list_chop_head_tail(&resp->msg.skb_head, 0,
					       tfw_str_total_len(&resp->body)
					       + resp->trailers_len);
		if (unlikely(r))
			return r;

		TFW_STR_INIT(&resp->body);
		if (resp->trailers_len > 0)
			tfw_http_msg_del_trailer_hdrs(hm);
	}

	if (test_bit(TFW_HTTP_B_PURGE_GET, req->flags)) {
		r = tfw_h1_purge_resp_clean(resp);
		if (r < 0)
			return r;
	}

	r = tfw_http_sess_resp_process(resp, false);
	if (r < 0)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
	if (r < 0)
		return r;

	r = tfw_http_set_hdr_upgrade(hm, true);
	if (r < 0)
		return r;

	r = tfw_http_set_hdr_keep_alive(hm, conn_flg);
	if (r < 0)
		return r;

	r = tfw_http_set_hdr_connection(hm, conn_flg);
	if (r < 0)
		return r;

	r = tfw_http_add_hdr_via(hm);
	if (r < 0)
		return r;

	r = tfw_h1_set_loc_hdrs(hm, true, false);
	if (r < 0)
		return r;

	if (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)) {
		r = tfw_http_set_hdr_date(hm);
		if (r < 0)
			return r;
	}

	return TFW_HTTP_MSG_HDR_XFRM(hm, "Server", TFW_NAME "/" TFW_VERSION,
				     TFW_HTTP_HDR_SERVER, 0);
}

/*
 * Forward responses in @ret_queue to the client in correct order.
 *
 * In case of error the client connection must be closed immediately.
 * Otherwise, the correct order of responses will be broken. Unsent
 * responses are taken care of by the caller.
 */
static void
__tfw_http_resp_fwd(TfwCliConn *cli_conn, struct list_head *ret_queue,
		    struct list_head *resp_del_queue)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, ret_queue, msg.seq_list) {
		bool send_cont;

		BUG_ON(!req->resp);
		send_cont = test_bit(TFW_HTTP_B_CONTINUE_RESP,
				     req->resp->flags);
		if (!send_cont)
			tfw_http_resp_init_ss_flags(req->resp);
		if (tfw_cli_conn_send(cli_conn, (TfwMsg *)req->resp)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			tfw_connection_close((TfwConn *)cli_conn, true);
			return;
		}
		TFW_INC_STAT_BH(serv.msgs_forwarded);
		tfw_inc_global_hm_stats(req->resp->status);
		list_del_init(&req->msg.seq_list);
		if (!send_cont)
			tfw_http_free_req_carefully(req, resp_del_queue);
		else
			tfw_http_msg_free(req->pair);
	}
}

static inline void
__tfw_http_ws_connection_put(TfwCliConn *cli_conn)
{
	if (unlikely(cli_conn->proto.type & TFW_FSM_WEBSOCKET))
		tfw_connection_put(cli_conn->pair);
}

/*
 * Mark @resp as ready to transmit. Then, starting with the first request
 * in @seq_queue, pick consecutive requests that have response ready to
 * transmit. Move those requests to the list of returned responses
 * @ret_queue. Sequentially send responses from @ret_queue to the client.
 */
void
tfw_http_resp_fwd(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
	struct list_head *seq_queue = &cli_conn->seq_queue;
	struct list_head *req_retent = NULL;
	LIST_HEAD(ret_queue);
	LIST_HEAD(resp_del_queue);

	T_DBG2("%s: req=[%p], resp=[%p]\n", __func__, req, resp);
	WARN_ON_ONCE(req->resp != resp);
	do_access_log(resp);

	/*
	 * If the list is empty, then it's either a bug, or the client
	 * connection had been closed. If it's a bug, then the correct
	 * order of responses to requests may be broken. The connection
	 * with the client must be closed immediately.
	 *
	 * Doing ss_close() on client connection's socket is safe
	 * as long as @req that holds a reference to the connection is
	 * not freed.
	 */
	spin_lock_bh(&cli_conn->seq_qlock);
	if (unlikely(list_empty(seq_queue))) {
		BUG_ON(!list_empty(&req->msg.seq_list));
		spin_unlock_bh(&cli_conn->seq_qlock);
		T_DBG2("%s: The client was disconnected, drop resp and req: "
		       "conn=[%p]\n",
			 __func__, cli_conn);
		/*
		 * Put the websocket server connection when client connection is
		 * lost after successful upgrade request.
		 */
		__tfw_http_ws_connection_put(cli_conn);
		tfw_connection_close(req->conn, true);
		tfw_http_free_req_carefully(req, &resp_del_queue);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		goto clear_del_queue;
	}
	BUG_ON(list_empty(&req->msg.seq_list));
	set_bit(TFW_HTTP_B_RESP_READY, resp->flags);
	/* Move consecutive requests with @req->resp to @ret_queue. */
	list_for_each_entry(req, seq_queue, msg.seq_list) {
		if (!req->resp
		    || !test_bit(TFW_HTTP_B_RESP_READY, req->resp->flags))
		{
			break;
		}
		req_retent = &req->msg.seq_list;
	}
	if (!req_retent) {
		spin_unlock_bh(&cli_conn->seq_qlock);
		return;
	}
	__list_cut_position(&ret_queue, seq_queue, req_retent);

	/*
	 * The function may be called concurrently on different CPUs,
	 * all going for the same client connection. In some threads
	 * a response is paired with a request, but the first response
	 * in the queue is not ready yet, so it can't be sent out. When
	 * there're responses to send, sending must be in correct order
	 * which is controlled by the lock. To avoid delays in progress
	 * of other threads during responses sending, unlock the seq_queue
	 * lock and use different lock @ret_qlock for sending.
	 *
	 * A client may close the connection at any time. A connection
	 * is destroyed when the last reference goes, so the argument
	 * to spin_unlock() may get invalid. Hold the connection until
	 * sending is done.
	 *
	 * TODO: There's a lock contention here as multiple threads/CPUs
	 * go for the same client connection's queue. Perhaps there's a
	 * better way of doing this that is more effective. Please see
	 * the TODO comment above and to the function tfw_http_popreq().
	 * Also, please see the issue #687.
	 *
	 * TODO #687: this is the only place where req_qlock is used. Instead
	 * of competing for the lock from different softirqs, just process
	 * the next available response, set a flag for current softirq
	 * processing ret_queue and make the current softirq retry from
	 * determination of req_retent.
	 */
	tfw_connection_get((TfwConn *)(cli_conn));
	spin_lock_bh(&cli_conn->ret_qlock);
	spin_unlock_bh(&cli_conn->seq_qlock);

	__tfw_http_resp_fwd(cli_conn, &ret_queue, &resp_del_queue);

	/* Zap request/responses that were not sent due to an error. */
	if (!list_empty(&ret_queue)) {
		TfwHttpReq *tmp;
		list_for_each_entry_safe(req, tmp, &ret_queue, msg.seq_list) {
			T_DBG2("%s: Forwarding error: conn=[%p] resp=[%p]\n",
			       __func__, cli_conn, req->resp);
			BUG_ON(!req->resp);
			list_del_init(&req->msg.seq_list);
			if (!test_bit(TFW_HTTP_B_CONTINUE_RESP,
				     req->resp->flags))
			{
				tfw_http_free_req_carefully(req,
							    &resp_del_queue);
			} else {
				tfw_http_msg_free(req->pair);
			}
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
	}

	spin_unlock_bh(&cli_conn->ret_qlock);
	tfw_connection_put((TfwConn *)(cli_conn));

clear_del_queue:
	tfw_http_clear_resp_del_queue(&resp_del_queue);
}

int
tfw_h2_hdr_map(TfwHttpResp *resp, const TfwStr *hdr, unsigned int id)
{
	TfwHdrIndex *index;
	TfwHttpHdrMap *map = resp->mit.map;

	if (id >= (1 << TFW_IDX_BITS) || hdr->nchunks > (1 << TFW_D_IDX_BITS)) {
		T_WARN("HTTP/2: too many headers (duplicates) in"
		       " HTTP/1.1-response (header id: %u, header dups: %u\n",
		       id, hdr->nchunks);
		return -EINVAL;
	}

	T_DBG3("%s: id=%u, hdr->nchunks=%u, map->size=%u, map->count=%u\n",
	       __func__, id, hdr->nchunks, map->size, map->count);

	if (unlikely(map->count == map->size)) {
		unsigned int new_size = map->size << 1;

		map = tfw_pool_realloc(resp->pool, map,
				       TFW_HDR_MAP_SZ(map->size),
				       TFW_HDR_MAP_SZ(new_size));
		if (!map) {
			T_WARN("HTTP/2: unable to reallocate memory for"
			       " response header map\n");
			return -ENOMEM;
		}

		map->size = new_size;
		resp->mit.map = map;

		BUG_ON(map->count >= map->size);
		T_DBG3("%s: expanded map, map->size=%u, map->count=%u\n",
		       __func__, map->size, map->count);
	}

	index = &map->index[map->count];
	index->idx = id;
	index->d_idx = TFW_STR_DUP(hdr) ? hdr->nchunks - 1 : 0;
	++map->count;

	return 0;
}

/*
 * Same as @tfw_http_add_hdr_via(), but intended for usage in HTTP/1.1=>HTTP/2
 * transformation.
 */
static int
tfw_h2_add_hdr_via(TfwHttpResp *resp)
{
	int r;
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	TfwStr via = {
		.chunks = (TfwStr []) {
			{ .data = S_VIA, .len = SLEN(S_VIA) },
			{ .data = S_VIA_H2_PROTO, .len = SLEN(S_VIA_H2_PROTO) },
			{ .data = *this_cpu_ptr(&g_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_VIA) + SLEN(S_VIA_H2_PROTO) + g_vhost->hdr_via_len,
		.nchunks = 3
	};

	memcpy_fast(__TFW_STR_CH(&via, 2)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);

	via.hpack_idx = 60;

	r = tfw_hpack_encode(resp, &via, true, true);
	if (unlikely(r))
		T_ERR("HTTP/2: unable to add 'via' header (resp=[%p])\n", resp);
	else
		T_DBG3("%s: added 'via' header, resp=[%p]\n", __func__, resp);
	return r;
}

/*
 * Same as @tfw_http_set_hdr_date(), but intended for usage in HTTP/1.1=>HTTP/2
 * transformation and for building response from cache.
 */
int
tfw_h2_add_hdr_date(TfwHttpResp *resp, bool cache)
{
	int r;
	char *s_date = *this_cpu_ptr(&g_buf);
	TfwStr hdr = {
		.chunks = (TfwStr []){
			{ .data = "date", .len = SLEN("date") },
			{ .data = s_date, .len = SLEN(S_V_DATE) },
		},
		.len = SLEN("date") + SLEN(S_V_DATE),
		.nchunks = 2
	};

	tfw_http_prep_date_from(s_date, resp->date);

	hdr.hpack_idx = 33;

	r = tfw_hpack_encode(resp, &hdr, !cache, !cache);
	if (unlikely(r))
		T_ERR("HTTP/2: unable to add 'date' header to response"
			" [%p]\n", resp);
	else
		T_DBG3("%s: added 'date' header, resp=[%p]\n", __func__, resp);

	return r;
}

/**
 * Add 'Content-Length:' header field to an HTTP message.
 */
static int
tfw_h2_add_hdr_clen(TfwHttpResp *resp)
{
	int r;
	char* buf = *this_cpu_ptr(&g_buf);
	unsigned long body_len = TFW_HTTP_RESP_CUT_BODY_SZ(resp);
	size_t cl_valsize = tfw_ultoa(body_len, buf,
				      TFW_ULTOA_BUF_SIZ);

	r = tfw_h2_msg_hdr_add(resp, "content-length",
			       SLEN("content-length"), buf,
			       cl_valsize, 28);

	if (unlikely(r))
		T_ERR("%s: unable to add 'content-length' header (resp=[%p])\n",
		      __func__, resp);
	else
		T_DBG3("%s: added 'content-length' header, resp=[%p]\n",
		       __func__, resp);
	return r;
}

/**
 * Add 'Content-Encoding:' header field to an HTTP message.
 *
 * @value - Value to add as field-value of Content-Encoding. Usually copied
 * from transfer encoding.
 */
static int
tfw_h2_add_hdr_cenc(TfwHttpResp *resp, TfwStr *value)
{
	int r;
	TfwStr name = { .data = "content-encoding",
			.len = SLEN("content-encoding")};
	TfwStr hdr = {
		.chunks = (TfwStr []) {
			{ .data = name.data, .len = name.len },
			{ .data = value->data, .len = value->len }
		},
		.len = name.len + value->len,
		.nchunks = 2,
		.hpack_idx = 26
	};

	r = tfw_hpack_encode(resp, &hdr, true, true);

	if (unlikely(r))
		goto err;

	T_DBG3("%s: added 'content-encoing' header, resp=[%p]\n", __func__,
	       resp);

	return r;
err:
	T_ERR("%s: unable to add 'content-encoding' header (resp=[%p])\n",
	      __func__, resp);
	return r;
}

/**
 * Copy values of multiple transfer-encoding headers to @dst.
 *
 * @max_len - Maximum length of the buffer the TE headers would be copied to.
 */
int
tfw_http_resp_copy_encodings(TfwHttpResp *resp, TfwStr* dst, size_t max_len)
{
	size_t len = 0;
	unsigned short sep = 0;
	char *buf = dst->data;
	TfwStr *chunk, *end, *dup, *dup_end;
	TfwStr *hdr = &resp->h_tbl->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING];

	BUG_ON(TFW_STR_EMPTY(hdr));
	BUG_ON(max_len == 0);

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		TFW_STR_FOR_EACH_CHUNK(chunk, dup, end) {
			if (!(chunk->flags & TFW_STR_NAME))
				continue;

			if (sep) {
				buf[len] = ',';
				len += 1;
				if (len > max_len)
					goto err;
			}

			while(chunk < end && chunk->flags & TFW_STR_NAME) {
				if (len + chunk->len > max_len)
					goto err;

				memcpy_fast(buf + len, chunk->data, chunk->len);
				len += chunk->len;
				chunk++;
			}

			sep = 1;
		}
	}

	dst->len = len;

	return 0;

err:
	T_WARN("Transfer-Encoding has too many encodings.\n");
	return -EINVAL;
}

/*
 * In case if response is stale, we should pass it with a warning.
 */
int
tfw_h2_set_stale_warn(TfwHttpResp *resp)
{
	TfwStr wh = {
		.chunks = (TfwStr []){
			{ .data = S_WARN, .len = SLEN(S_WARN) },
			{ .data = S_V_WARN, .len = SLEN(S_V_WARN) }
		},
		.len = SLEN(S_WARN) + SLEN(S_V_WARN),
		.nchunks = 2
	};

	return tfw_hpack_encode(resp, &wh, false, false);
}

/*
 * Split header into two parts: name and value, evicting ':' and OWS. Return
 * the resulting length of both parts.
 *
 * NOTE: this function is intended for response processing only (during
 * HTTP/1.1=>HTTP/2 transformation), since the response HTTP parser
 * supports splitting the header name, colon, LWS, value and RWS into
 * different chunks.
 *
 * When @spcolon is true header splits by colon between name and value.
 */
unsigned long
tfw_http_hdr_split(TfwStr *hdr, TfwStr *name_out, TfwStr *val_out, bool spcolon)
{
	unsigned long hdr_tail = 0;
	TfwStr *chunk, *end, *last_chunk = NULL;
	bool name_found = false, val_found = false;

	BUG_ON(!TFW_STR_EMPTY(name_out) || !TFW_STR_EMPTY(val_out));

	if (WARN_ON_ONCE(TFW_STR_PLAIN(hdr)))
		return 0;

	if (TFW_STR_EMPTY(hdr))
		return 0;

	if (!spcolon) {
		unsigned long off = 0;
		/*
		 * During headers addition (or message expansion) the source
		 * @hdr must have the following chunk structure (without the
		 * OWS):
		 *
		 *	{ name [S_DLM] value1 [value2 [value3 ...]] }.
		 *
		 */
		*name_out = *hdr->chunks;

		chunk = TFW_STR_CHUNK(hdr, 1);
		if (WARN_ON_ONCE(!chunk))
			return 0;

		if (chunk->len == SLEN(S_DLM)
		    && *(short *)chunk->data == *(short *)S_DLM)
		{
			off = SLEN(S_DLM);
			chunk = TFW_STR_CHUNK(hdr, 2);
			if (WARN_ON_ONCE(!chunk))
				return 0;
		}

		val_out->chunks = chunk;
		val_out->nchunks = hdr->chunks + hdr->nchunks - chunk;
		val_out->len = hdr->len - name_out->len - off;

		return hdr->len - off;
	}

	name_out->chunks = hdr->chunks;

	TFW_STR_FOR_EACH_CHUNK(chunk, hdr, end) {
		if (!chunk->len)
			continue;

		if (!name_found) {
			if (chunk->data[0] == ':') {
				name_found = true;
			} else {
				++name_out->nchunks;
				name_out->len += chunk->len;
			}
			continue;
		}

		/*
		 * LWS is always in the separate chunks between the name and
		 * value; thus, we can skip length of the entire (LWS) chunks.
		 */
		if (!val_found) {
			if (unlikely(chunk->flags & TFW_STR_OWS))
				continue;

			val_out->chunks = chunk;
			val_found = true;
		}

		val_out->len += chunk->len;

		/*
		 * Skip OWS after the header value (RWS) - they must be in
		 * separate chunks too.
		 */
		if (unlikely(chunk->flags & TFW_STR_OWS)) {
			hdr_tail += chunk->len;
		} else {
			last_chunk = chunk;
			hdr_tail = 0;
		}
	}

	/* The header value is empty. */
	if (unlikely(!val_found))
		return name_out->len;

	if (WARN_ON_ONCE(!last_chunk))
		return 0;

	T_DBG3("%s: hdr_tail=%lu, val_out->len=%lu, last_chunk->len=%lu,"
	       " last_chunk->data='%.*s'\n", __func__, hdr_tail, val_out->len,
	       last_chunk->len, (int)last_chunk->len, last_chunk->data);

	val_out->nchunks = last_chunk - val_out->chunks + 1;
	val_out->len -= hdr_tail;

	return name_out->len + val_out->len;
}

unsigned long
tfw_h2_hdr_size(unsigned long n_len, unsigned long v_len,
		unsigned short st_index)
{
	unsigned long size;

	if (st_index) {
		size = tfw_hpack_int_size(st_index, 0xF);
	} else {
		size = 1;
		size += tfw_hpack_int_size(n_len, 0x7F);
		size += n_len;
	}
	size += tfw_hpack_int_size(v_len, 0x7F);
	size += v_len;

	return size;
}

int
tfw_h2_resp_add_loc_hdrs(TfwHttpResp *resp, const TfwHdrMods *h_mods,
			 bool cache)
{
	unsigned int i;
	TfwHttpHdrTbl *ht = resp->h_tbl;

	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		const TfwHdrModsDesc *desc = &h_mods->hdrs[i];
		int r;
		unsigned short hid = desc->hid;

		if (TFW_STR_CHUNK(desc->hdr, 1) == NULL)
			continue;

		if (unlikely(desc->append && !TFW_STR_EMPTY(&ht->tbl[hid])
			     && (hid < TFW_HTTP_HDR_NONSINGULAR)))
		{
			T_WARN("Attempt to add already existed singular header '%.*s'\n",
			PR_TFW_STR(TFW_STR_CHUNK(desc->hdr, 0)));
			continue;
		}

		r = tfw_hpack_encode(resp, desc->hdr, !cache, !cache);
		if (unlikely(r))
			return r;
	}

	return 0;
}

static bool
tfw_h2_hdr_sub(unsigned short hid, const TfwStr *hdr, const TfwHdrMods *h_mods)
{
	unsigned int idx;
	const TfwHdrModsDesc *desc;

	if (!h_mods)
		return false;

	/* Fast path for special headers */
	if (hid >= TFW_HTTP_HDR_REGULAR && hid < TFW_HTTP_HDR_RAW) {
		desc = h_mods->spec_hdrs[hid];
		/* Skip only resp_hdr_set headers */
		return desc ? !desc->append : false;
	}

	if (hdr->hpack_idx > 0) {
		/* Don't touch pseudo-headers. */
		if (hdr->hpack_idx <= HPACK_STATIC_TABLE_REGULAR)
			return false;

		return test_bit(hdr->hpack_idx, h_mods->s_tbl);
	}

	for (idx = h_mods->spec_num; idx < h_mods->sz; ++idx) {
		desc = &h_mods->hdrs[idx];
		if (!desc->append && !__hdr_name_cmp(hdr, desc->hdr))
			return true;
	}

	return false;
}

static int
tfw_h2_hpack_encode_headers(TfwHttpResp *resp, const TfwHdrMods *h_mods)
{
	int r;
	unsigned int i;
	TfwHttpTransIter *mit = &resp->mit;
	TfwHttpHdrMap *map = mit->map;
	TfwHttpHdrTbl *ht = resp->h_tbl;

	for (i = 0; i < map->count; ++i) {
		unsigned short hid = map->index[i].idx;
		unsigned short d_num = map->index[i].d_idx;
		TfwStr *tgt = &ht->tbl[hid];

		if (TFW_STR_DUP(tgt))
			tgt = TFW_STR_CHUNK(tgt, d_num);

		if (WARN_ON_ONCE(!tgt
				 || TFW_STR_EMPTY(tgt)
				 || TFW_STR_DUP(tgt)))
			return -EINVAL;

		T_DBG3("%s: hid=%hu, d_num=%hu, nchunks=%u, h_mods->sz=%u\n",
		       __func__, hid, d_num, ht->tbl[hid].nchunks,
		       h_mods ? h_mods->sz : 0);

		/* Don't encode header if it must be substituted from config */
		if (tfw_h2_hdr_sub(hid, tgt, h_mods))
			continue;

		/*
		 * Remove 'Connection', 'Keep-Alive' headers and all hop-by-hop
		 * headers from the HTTP/2 response.
		 */
		if (hid == TFW_HTTP_HDR_KEEP_ALIVE
		    || hid == TFW_HTTP_HDR_CONNECTION
		    || tgt->flags & TFW_STR_HBH_HDR)
			continue;

		/*
		 * 'Server' header must be replaced; thus, remove the original
		 * header (and all its duplicates) skipping it here; the new
		 * header will be written later, during new headers' addition
		 * stage.
		 */
		if (hid == TFW_HTTP_HDR_SERVER)
			continue;

		r = tfw_hpack_transform(resp, tgt);
		if (unlikely(r))
			return r;
	}

	return 0;
}

/**
 * Split response body stored locally. Allocate a new skb and put body there
 * by fragments. Every skb fragment has size of single page and has frame
 * header at the beginning. Just like body constructed in
 * @tfw_cache_build_resp_body().
 *
 * The function is designed for @body preallocated during configuration
 * processing thus no chunked body allowed, only plain TfwStr is accepted there.
 */
static int
tfw_h2_append_predefined_body(TfwHttpResp *resp, const TfwStr *body)
{
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *it = &mit->iter;
	size_t len, max_copy = PAGE_SIZE;
	char *data;
	int r;

	if (!body || !body->data)
		return 0;
	if (!TFW_STR_PLAIN(body))
		return -EINVAL;
	len = body->len;

	if (!(it->skb = ss_skb_peek_tail(&it->skb_head)))
		return -EINVAL;
	it->frag = skb_shinfo(it->skb)->nr_frags - 1;

	if (it->frag + 1 >= MAX_SKB_FRAGS) {
		if ((r = tfw_msg_iter_append_skb(it)))
			return r;
	}

	data = body->data;
	while (len) {
		struct page *page;
		char *p;
		size_t copy = min(len, max_copy);

		len -= copy;

		if (!(page = alloc_page(GFP_ATOMIC))) {
			return -ENOMEM;
		}
		p = page_address(page);
		memcpy_fast(p, data, copy);
		data += copy;

		++it->frag;
		skb_fill_page_desc(it->skb, it->frag, page, 0, copy);
		ss_skb_adjust_data_len(it->skb, copy);

		if (it->frag + 1 == MAX_SKB_FRAGS
		    && (r = tfw_msg_iter_append_skb(it)))
		{
			return r;
		}
	}

	return 0;
}
ALLOW_ERROR_INJECTION(tfw_h2_append_predefined_body, ERRNO);

int
tfw_http_on_send_resp(void *conn, struct sk_buff **skb_head)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);
	struct tfw_skb_cb *tfw_cb = TFW_SKB_CB(*skb_head);
	TfwStream *stream;

	stream = tfw_h2_find_not_closed_stream(ctx, tfw_cb->stream_id, false);
	/*
	 * Very unlikely case. We check that stream is active, before
	 * calling ss_send, but there is a very small chance, that
	 * stream was canceled by RST STREAM from the client
	 * before ss_do_send was called.
	 */
	if (unlikely(!stream))
		return -EPIPE;

	BUG_ON(stream->xmit.skb_head);
	stream->xmit.resp = (TfwHttpResp *)tfw_cb->opaque_data;
	if (test_bit(TFW_HTTP_B_CLOSE_ERROR_RESPONSE, stream->xmit.resp->flags))
		ctx->error = stream;
	swap(stream->xmit.skb_head, *skb_head);
	sock_set_flag(((TfwConn *)conn)->sk, SOCK_TEMPESTA_HAS_DATA);
	if (!stream->xmit.is_blocked)
		tfw_h2_sched_activate_stream(&ctx->sched, stream);

	return 0;
}

/**
 * Frame response generated locally.
 */
int
tfw_h2_frame_local_resp(TfwHttpResp *resp, unsigned long h_len,
			const TfwStr *body)
{
	unsigned long b_len = body ? body->len : 0;
	int r;

	r = tfw_h2_append_predefined_body(resp, body);
	if (unlikely(r))
		return r;

	return tfw_h2_stream_init_for_xmit(resp, HTTP2_RELEASE_RESPONSE,
					   h_len, b_len);
}

static void
tfw_h1_resp_adjust_fwd(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	/*
	 * A client can disconnect at any time after the request was
	 * forwarded to backend. In this case the response will never be sent
	 * to the client. Keep the response until it's saved in the cache,
	 * so other clients can served from cache. After response is saved to
	 * cache it can be dropped.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_REQ_DROP, req->flags))) {
		T_DBG2("%s: resp=[%p] dropped: client disconnected\n",
		       __func__, resp);
		/*
		 * Put the websocket server connection when client connection is
		 * lost after successful upgrade request.
		 */
		__tfw_http_ws_connection_put((TfwCliConn *)req->conn);
		tfw_http_resp_pair_free(req);

		return;
	}
	/*
	 * Typically we're at a node far from the node where @resp was
	 * received, so we do an inter-node transfer. However, this is
	 * the final place where the response will be stored. Upcoming
	 * requests will get responded to by the current node without
	 * inter-node data transfers. (see tfw_http_req_cache_cb())
	 */
	if (tfw_http_adjust_resp(resp)) {
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_send_err_resp(req, 500,
				   "response dropped: processing error");
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return;
	}

	T_DBG4("[%d] %s: req %pK resp %pK: \n", smp_processor_id(), __func__,
	       req, resp);
	SS_SKB_QUEUE_DUMP(&resp->msg.skb_head);

	tfw_http_resp_fwd(resp);
}

static void
tfw_http_conn_error_log(TfwConn *conn, const char *msg)
{
	if (!(tfw_blk_flags & TFW_BLK_ERR_NOLOG))
		T_WARN_ADDR(msg, &conn->peer->addr, TFW_NO_PORT);
}

static inline int
tfw_h2_choose_close_type(ErrorType type, bool reply)
{
	if (!reply)
		return T_BLOCK_WITH_RST;
	else if (type == TFW_ERROR_TYPE_ATTACK)
		return T_BLOCK_WITH_FIN;
	else if (type == TFW_ERROR_TYPE_BAD)
		return T_BAD;
	return T_DROP;
}

static void
tfw_http_req_filter_block_ip(TfwHttpReq *req)
{
	TfwVhost *dflt_vh = tfw_vhost_lookup_default();
	TfwClient *cli;

	if (WARN_ON_ONCE(!dflt_vh))
		return;

	cli = req->peer ? : (TfwClient *)(req->conn ? req->conn->peer : NULL);
	if (!cli)
		goto out;

	if (dflt_vh->frang_gconf->ip_block)
		tfw_filter_block_ip(cli);

out:
	tfw_vhost_put(dflt_vh);
}

static int
tfw_h2_error_resp(TfwHttpReq *req, int status, bool reply, ErrorType type,
		  bool on_req_recv_event, TfwH2Err err_code)
{
	TfwStream *stream;
	TfwConn *conn = READ_ONCE(req->conn);
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(conn);
	bool close_after_send = (type == TFW_ERROR_TYPE_ATTACK ||
		type == TFW_ERROR_TYPE_BAD);

	/*
	 * block_action attack/error drop - Tempesta FW must block message
	 * silently (response won't be generated) and reset (with TCP RST)
	 * the client connection.
	 */
	if (!reply) {
		if (!on_req_recv_event)
			tfw_connection_abort(conn);
		tfw_h2_req_unlink_and_close_stream(req);
		if (type == TFW_ERROR_TYPE_ATTACK)
			tfw_http_req_filter_block_ip(req);
		goto free_req;
	}

	/*
	 * If stream is already unlinked and removed (due to particular stream
	 * closing from client side or the entire connection closing) we have
	 * nothing to do with that stream/request, and can go straight to the
	 * connection-specific logic.
	 */
	stream = req->stream;
	if (!stream)
		goto skip_stream;

	/*
	 * If reply should be sent and this is not the attack case - we
	 * can just send error response, leave the connection alive and
	 * drop request's corresponding stream; in this case stream either
	 * is already in locally closed state (switched in
	 * @tfw_h2_stream_id_send() during failed proxy/internal response
	 * creation) or will be switched into locally closed state in
	 * @tfw_h2_send_err_resp() (or in @tfw_h2_stream_id_send() if no error
	 * response is needed) below; remotely (i.e. on client side) stream
	 * will be closed - due to END_STREAM flag set in the last frame of
	 * error response; in case of attack we must close entire connection,
	 * and GOAWAY frame should be sent (RFC 7540 section 6.8) after
	 * error response.
	 */
	tfw_connection_get(conn);
	tfw_h2_send_err_resp(req, status, close_after_send);
	if (close_after_send) {
		tfw_h2_conn_terminate_close(ctx, err_code, !on_req_recv_event,
					    type == TFW_ERROR_TYPE_ATTACK);
	} else {
		TfwStreamState stream_state = tfw_h2_get_stream_state(stream);
		int r;

		/*
		 * Here we rely on the fact that we always drop connection
		 * (close_after_send is true) if request is not fully parsed.
		 * In this case we can not process RST_STREAM and can not
		 * change stream state here, because in this state we
		 * already don't expect to receive any frames other then
		 * PRIORITY or WINDOW_UPDATE.
		 * There is also a very small chance that stream is already
		 * in HTTP2_STREAM_CLOSED state here in case when error
		 * response was already sent. (This can occurs when we call
		 * this function during processing invalid response and error
		 * response is sent on other cpu).
		 */
		WARN_ON_ONCE(stream_state != HTTP2_STREAM_REM_HALF_CLOSED
			     && stream_state != HTTP2_STREAM_CLOSED);
		if ((r = tfw_h2_send_rst_stream(ctx, stream->id, err_code))) {
			tfw_connection_put(conn);
			return r;
		}
	}
	tfw_connection_put(conn);
	goto out;

skip_stream:
	if (close_after_send) {
		tfw_h2_conn_terminate_close(ctx, err_code, !on_req_recv_event,
					    type == TFW_ERROR_TYPE_ATTACK);
	}

free_req:
	do_access_log_req(req, status, 0);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
out:
	return tfw_h2_choose_close_type(type, reply);
}

static int
tfw_h1_error_resp(TfwHttpReq *req, int status, bool reply, ErrorType type,
		  bool on_req_recv_event)
{
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;

	/* The client connection is to be closed with the last resp sent. */
	reply &= !test_bit(TFW_HTTP_B_REQ_DROP, req->flags);
	/*
	 * block_action attack/error drop - Tempesta FW must block message
	 * silently (response won't be generated) and reset (with TCP RST)
	 * the client connection.
	 */
	if (!reply) {
		if (!on_req_recv_event)
			tfw_connection_abort(req->conn);
		if (type == TFW_ERROR_TYPE_ATTACK)
			tfw_http_req_filter_block_ip(req);
		do_access_log_req(req, status, 0);
		tfw_http_conn_req_clean(req);
		goto out;
	}

	if (on_req_recv_event) {
		WARN_ONCE(!list_empty_careful(&req->msg.seq_list),
			  "Request is already in seq_queue\n");
		tfw_stream_unlink_msg(req->stream);
		spin_lock(&cli_conn->seq_qlock);
		list_add_tail(&req->msg.seq_list, &cli_conn->seq_queue);
		spin_unlock(&cli_conn->seq_qlock);
	}

	if (type != TFW_ERROR_TYPE_DROP)
		tfw_http_req_set_conn_close(req);

	if (type == TFW_ERROR_TYPE_ATTACK)
		set_bit(TFW_HTTP_B_CONN_CLOSE_FORCE, req->flags);

	tfw_h1_send_err_resp(req, status);

out:
	return tfw_h2_choose_close_type(type, reply);
}

/**
 * Function define logging and response behaviour during detection of
 * malformed or malicious messages. Mark client connection in special
 * manner to delay its closing until transmission of error response
 * will be finished.
 *
 * @req			- malicious or malformed request;
 * @status		- response status code to use;
 * @msg			- message to be logged. Can be NULL if the caller does
 *			  logging on their side;
 * @type		- TFW_ERROR_TYPE_ATTACK if the request was sent
 *			  intentionally.
 *			  TFW_ERROR_TYPE_DROP if the request should be
 *			  dropped, but connection should be alive.
 *			  TFW_ERROR_TYPE_BAD if the request should be
 *			  dropped, but connection should be closed;
 *			  internal errors or misconfigurations;
 * @on_req_recv_event	- true if request is not fully parsed and the caller
 *			  handles the connection closing on its own.
 * @return		- T_BLOCK_WITH_RST if reply is not needed
 *			  T_BLOCK_WITH_FIN if it is an attack case and we need
 *			  to reply.
 * 			  T_BAD if it is not attack case and we need to reply
 *			  and shutdown gracefully.
 *			  T_DROP if it is error case and we need to reply.
 */
static int
tfw_http_cli_error_resp_and_log(TfwHttpReq *req, int status, const char *msg,
				ErrorType type, bool on_req_recv_event,
				TfwH2Err err_code)
{
	int r;
	bool reply;
	bool nolog;

	/*
	 * Error was happened and request should be dropped or blocked,
	 * but other modules (e.g. sticky cookie module) may have a response
	 * prepared for this request. A new error response is to be generated
	 * for the request, drop any previous response paired with the request.
	 */
	tfw_http_conn_msg_free(req->pair);

	if (type == TFW_ERROR_TYPE_ATTACK) {
		reply = tfw_blk_flags & TFW_BLK_ATT_REPLY;
		nolog = tfw_blk_flags & TFW_BLK_ATT_NOLOG;
	}
	else {
		reply = tfw_blk_flags & TFW_BLK_ERR_REPLY;
		nolog = tfw_blk_flags & TFW_BLK_ERR_NOLOG;
	}

	/* Do not log client port as it doesn't provide useful information
	 * and could contain outdated cached data.
	 */
	if (!nolog && msg)
		T_WARN_ADDR(msg, &req->conn->peer->addr, TFW_NO_PORT);

	if (TFW_MSG_H2(req)) {
		r = tfw_h2_error_resp(req, status, reply, type,
				      on_req_recv_event,
				      err_code ? err_code : HTTP2_ECODE_PROTO);
	} else {
		r = tfw_h1_error_resp(req, status, reply, type,
				      on_req_recv_event);
	}

	return r;
}

/**
 * Unintentional error happen during request parsing, connection should
 * be alive.
 */
static inline int
tfw_http_req_parse_drop(TfwHttpReq *req, int status, const char *msg,
			TfwH2Err err_code)
{
	return tfw_http_cli_error_resp_and_log(req, status, msg,
					       TFW_ERROR_TYPE_DROP, true,
					       err_code);
}

/**
 * Unintentional error happen during request parsing, connection should
 * be closed.
 */
static inline int
tfw_http_req_parse_drop_with_fin(TfwHttpReq *req, int status, const char *msg,
				 TfwH2Err err_code)
{
	return tfw_http_cli_error_resp_and_log(req, status, msg,
					       TFW_ERROR_TYPE_BAD, true,
					       err_code);
}

/**
 * Attack is detected during request parsing.
 */
static inline int
tfw_http_req_parse_block(TfwHttpReq *req, int status, const char *msg,
			 TfwH2Err err_code)
{
	return tfw_http_cli_error_resp_and_log(req, status, msg,
					       TFW_ERROR_TYPE_ATTACK, true,
					       err_code);
}

/**
 * Unintentional error happen during request or response processing. Caller
 * function is not a part of ss_tcp_data_ready() function and manual connection
 * close will be performed.
 */
static inline int
tfw_http_req_drop(TfwHttpReq *req, int status, const char *msg,
		  TfwH2Err err_code)
{
	return tfw_http_cli_error_resp_and_log(req, status, msg,
					       TFW_ERROR_TYPE_DROP, false,
					       err_code);
}

/**
 * Attack is detected during request or response processing. Caller function is
 * not a part of ss_tcp_data_ready() function and manual connection close
 * will be performed.
 */
static inline int
tfw_http_req_block(TfwHttpReq *req, int status, const char *msg,
		   TfwH2Err err_code)
{
	return tfw_http_cli_error_resp_and_log(req, status, msg,
					       TFW_ERROR_TYPE_ATTACK, false,
					       err_code);
}

static void
__tfw_h2_resp_cleanup(TfwHttpRespCleanup *cleanup)
{
	int i;
	struct sk_buff *skb;

	while ((skb = ss_skb_dequeue(&cleanup->skb_head)))
		__kfree_skb(skb);

	for (i = 0; i < cleanup->pages_sz; i++)
		put_page(cleanup->pages[i]);
}

/*
 * TODO: RFC 7540 8.1.2
 *    However, header field names MUST be converted to lowercase prior to
 *    their encoding in HTTP/2. A request or response containing uppercase
 *    header field names MUST be treated as malformed (Section 8.1.2.6).
 *
 * Major browsers and curl ignore that RFC requirement an work well. But
 * that is definitely an RFC violation and implementation specific behaviour.
 */
int
tfw_h2_resp_encode_headers(TfwHttpResp *resp)
{
	int r;
	TfwHttpReq *req = resp->req;
	TfwHttpTransIter *mit = &resp->mit;
	TfwHttpRespCleanup cleanup = {};
	TfwStr codings = {};
	const TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location,
							  req->vhost,
							  TFW_VHOST_HDRMOD_RESP);

	/*
	 * Accordingly to RFC 9113 8.2.2 connection-specific headers can't
	 * be used in HTTP/2.
	 *
	 * The whole header can be removed. Don't remove it, only mark as
	 * hop-by-hop header: such headers are ignored while saved into cache
	 * and never forwarded to h2 clients. Just avoid extra fragmentation
	 * now.
	 */
	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags)
	    || test_bit(TFW_HTTP_B_TE_EXTRA, resp->flags)) {
		TfwStr *te_hdr, *dup, *end;

		te_hdr = &resp->h_tbl->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING];
		TFW_STR_FOR_EACH_DUP(dup, te_hdr, end)
			dup->flags |= TFW_STR_HBH_HDR;
	}

	if (test_bit(TFW_HTTP_B_TE_EXTRA, resp->flags)) {
		codings.data = tfw_pool_alloc(resp->pool, RESP_TE_BUF_LEN);
		if (unlikely(!codings.data)) {
			r = -ENOMEM;
			goto clean;
		}
		r = tfw_http_resp_copy_encodings(resp, &codings,
						 RESP_TE_BUF_LEN);
		if (unlikely(r))
			goto clean;
	}

	/*
	 * Transform HTTP/1.1 headers into HTTP/2 form, in parallel with
	 * adjusting of particular headers.
	 */
	WARN_ON_ONCE(mit->acc_len);
	tfw_h2_msg_transform_setup(mit, resp->msg.skb_head, true);

	r = tfw_h2_msg_cutoff_headers(resp, &cleanup);
	if (unlikely(r))
		goto clean;

	/*
	 * Alloc room for frame header. After this call resp->pool
	 * must be used only as skb paged data.
	 */
	r = tfw_http_msg_setup_transform_pool(mit, resp->pool);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_resp_status_write(resp, resp->status, true, false);
	 if (unlikely(r))
		goto clean;

	r = tfw_h2_hpack_encode_headers(resp, h_mods);
	if (unlikely(r))
		goto clean;

	/*
	 * Write additional headers in HTTP/2 format in the end of the
	 * headers block, including configured headers which haven't been
	 * processed above and which have non-empty value (i.e. configured
	 * not for deletion).
	 */
	r = tfw_http_sess_resp_process(resp, false);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_add_hdr_via(resp);
	if (unlikely(r))
		goto clean;

	if (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)) {
		r = tfw_h2_add_hdr_date(resp, false);
		if (unlikely(r))
			goto clean;
	}

	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags)) {
		if (unlikely(tfw_h2_add_hdr_clen(resp)))
			goto clean;
	}

	if (test_bit(TFW_HTTP_B_TE_EXTRA, resp->flags)) {
		r = tfw_h2_add_hdr_cenc(resp, &codings);
		if (unlikely(r))
			goto clean;

		TFW_STR_INIT(&codings);
	}

	r = TFW_H2_MSG_HDR_ADD(resp, "server", TFW_SERVER, 54);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_resp_add_loc_hdrs(resp, h_mods, false);
	if (unlikely(r))
		goto clean;

	T_DBG4("[%d] %s: req %pK resp %pK: \n", smp_processor_id(), __func__,
	       req, resp);
	SS_SKB_QUEUE_DUMP(&resp->msg.skb_head);

	__tfw_h2_resp_cleanup(&cleanup);
	return 0;

clean:
	__tfw_h2_resp_cleanup(&cleanup);
	return r;
}

static void
tfw_h2_resp_adjust_fwd(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	int r;

	/*
	 * This function can be failed only if stream is
	 * already closed and deleted.
	 */
	r = tfw_h2_stream_init_for_xmit(resp, HTTP2_ENCODE_HEADERS, 0, 0);
	if (unlikely(r)) {
		tfw_http_resp_pair_free(req);
	} else {
		tfw_h2_req_unlink_stream(req);
		tfw_h2_resp_fwd(resp);
	}
}

/**
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 500 or 502 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpMsg *msg)
{
	int r;
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn = NULL;
	LIST_HEAD(eq);

	T_DBG2("%s: req = %p, resp = %p\n", __func__, req, req->resp);

	if (req->resp) {
		tfw_http_req_cache_service(req->resp);
		return;
	}

	if (test_bit(TFW_HTTP_B_JS_NOT_SUPPORTED, req->flags)) {
		T_DBG("request dropped: non-challengeable resource"
		      " was not served from cache");
		tfw_http_send_err_resp_nolog(req, 403);
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return;
	}

	/*
	 * Dispatch request to an appropriate server. Schedulers should
	 * make a decision based on an unmodified request, so this must
	 * be done before any request mangling.
	 *
	 * The code below is usually called on a remote NUMA node. That's
	 * not good, but TDB lookup must be run on the node before it is
	 * executed, to avoid unnecessary work in SoftIRQ and to speed up
	 * the cache operation. At the same time, cache hits are expected
	 * to prevail over cache misses, so this is not a frequent path.
	 */
	if (!(srv_conn = tfw_http_get_srv_conn((TfwMsg *)req))) {
		T_DBG("Unable to find a backend server\n");
		goto send_502;
	}

	r = TFW_MSG_H2(req)
		? tfw_h2_adjust_req(req)
		: tfw_h1_adjust_req(req);
	if (r)
		goto send_500;

	/* Account current request in APM health monitoring statistics */
	tfw_http_hm_srv_update((TfwServer *)srv_conn->peer, req);

	/* Forward request to the server. */
	tfw_http_req_fwd_resched(srv_conn, req, &eq);
	tfw_http_req_zap_error(&eq);
	goto conn_put;

send_502:
	T_DBG("request dropped: processing error, status 502");
	tfw_http_send_err_resp_nolog(req, 502);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
	return;
send_500:
	T_DBG("request dropped: processing error, status 500");
	tfw_http_send_err_resp_nolog(req, 500);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
conn_put:
	/*
	 * Paired with tfw_srv_conn_get_if_live() via tfw_http_get_srv_conn() which
	 * increments the reference counter.
	 */
	tfw_srv_conn_put(srv_conn);
}

static void
tfw_http_req_mark_nip(TfwHttpReq *req)
{
	TfwVhost *vh_dflt;
	TfwLocation *loc, *loc_dflt;
	/* See RFC 7231 4.2.1 */
	static const unsigned int safe_methods =
		(1 << TFW_HTTP_METH_GET) | (1 << TFW_HTTP_METH_HEAD)
		| (1 << TFW_HTTP_METH_OPTIONS) | (1 << TFW_HTTP_METH_PROPFIND)
		| (1 << TFW_HTTP_METH_TRACE);

	BUILD_BUG_ON(sizeof(safe_methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	if (!req->vhost)
		return;
	/*
	 * Search in the current location of the current vhost. If there
	 * are no entries there, then search in the default location of
	 * the current vhost. If there are no entries there either, then
	 * search in the default location of the default vhost - that is,
	 * in the global policies.
	 *
	 * TODO #862: req->location must be the full set of options.
	 */
	loc = req->location;
	loc_dflt = req->vhost->loc_dflt;
	vh_dflt = req->vhost->vhost_dflt;
	if (loc && loc->nipdef_sz) {
		if (tfw_nipdef_match(loc, req->method, &req->uri_path))
			goto nip_match;
	} else if (loc_dflt && loc_dflt->nipdef_sz) {
		if (tfw_nipdef_match(loc_dflt, req->method, &req->uri_path))
			goto nip_match;
	} else if (vh_dflt && vh_dflt->loc_dflt->nipdef_sz) {
		if (tfw_nipdef_match(vh_dflt->loc_dflt, req->method,
				     &req->uri_path))
			goto nip_match;
	}

	if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags))
		goto nip_match;

	if (safe_methods & (1 << req->method))
		return;

nip_match:
	T_DBG2("non-idempotent: method=[%d] uri=[%.*s]\n",
	       req->method, (int)TFW_STR_CHUNK(&req->uri_path, 0)->len,
		 TFW_STR_CHUNK(&req->uri_path, 0)->data);
	__set_bit(TFW_HTTP_B_NON_IDEMP, req->flags);
	return;
}

/*
 * Set the flag if @req is non-idempotent. Add the request to the list
 * of the client connection to preserve the correct order of responses.
 * If the request follows a non-idempotent request in flight, then the
 * preceding request becomes idempotent. See @tfw_http_req_fwd comment
 */
static void
tfw_http_req_add_seq_queue(TfwHttpReq *req)
{
	TfwHttpReq *req_prev;
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
	struct list_head *seq_queue = &cli_conn->seq_queue;

	tfw_http_req_mark_nip(req);

	spin_lock(&cli_conn->seq_qlock);
	req_prev = list_empty(seq_queue) ?
		   NULL : list_last_entry(seq_queue, TfwHttpReq, msg.seq_list);
	if (req_prev && tfw_http_req_is_nip(req_prev))
		clear_bit(TFW_HTTP_B_NON_IDEMP, req_prev->flags);
	list_add_tail(&req->msg.seq_list, seq_queue);
	spin_unlock(&cli_conn->seq_qlock);
}

static inline bool
tfw_http_check_wildcard_status(const char c, int *out)
{
	switch (c) {
	case '1':
		*out = HTTP_STATUS_1XX;
		break;
	case '2':
		*out = HTTP_STATUS_2XX;
		break;
	case '3':
		*out = HTTP_STATUS_3XX;
		break;
	case '4':
		*out = HTTP_STATUS_4XX;
		break;
	case '5':
		*out = HTTP_STATUS_5XX;
		break;
	default:
		return false;
	}
	return true;
}

static inline void
tfw_http_hm_drop_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	tfw_stream_unlink_msg(resp->stream);
	tfw_http_conn_msg_free((TfwHttpMsg *)resp);
	tfw_http_msg_free((TfwHttpMsg *)req);
}

static TfwStr
tfw_http_get_ip_from_xff(TfwHttpReq *req)
{
	const TfwStr *s_xff, *c, *end;
	TfwStr s_ip;
	unsigned int nchunks;

	/*
	 * If a client works through a forward proxy, then a proxy can pass it's
	 * IP address by the first value in X-Forwarded-For
	 */
	s_xff = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
	/* Pick only end client address, ignore all proxies between it and us.  */
	if (TFW_STR_DUP(s_xff))
		s_xff = __TFW_STR_CH(s_xff, 0);
	s_ip = tfw_str_next_str_val(s_xff);
	nchunks = 0;
	TFW_STR_FOR_EACH_CHUNK(c, &s_ip, end) {
		if (!(c->flags & TFW_STR_VALUE))
			break;
		nchunks++;
	}
	s_ip.nchunks = nchunks;

	return s_ip;
}

static int
tfw_http_req_client_link(TfwConn *conn, TfwHttpReq *req)
{
#ifdef DISABLED_934
	TfwStr s_ip, s_user_agent, *ua;
	TfwAddr addr;
	TfwClient *cli, *conn_cli;
#else
	TfwStr s_ip;
	TfwAddr addr;
#endif

	s_ip = tfw_http_get_ip_from_xff(req);
	if (!TFW_STR_EMPTY(&s_ip)) {
		if (tfw_addr_pton(&s_ip, &addr) != 0)
			return -EINVAL;
/* @TODO: Disabled by issue #934. Code above need to validate XFF header. */
#ifdef DISABLED_934
		conn_cli = (TfwClient *)conn->peer;
		ua = &req->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT];
		tfw_http_msg_clnthdr_val(req, ua, TFW_HTTP_HDR_USER_AGENT,
					 &s_user_agent);
		cli = tfw_client_obtain(conn_cli->addr, &addr, &s_user_agent,
					NULL);
		if (cli) {
			if (cli != conn_cli)
				req->peer = cli;
			else
				tfw_client_put(cli);
		}
#endif
	}

	return 0;
}

static TfwHttpMsg *
tfw_h1_req_process(TfwStream *stream, struct sk_buff *skb)
{
	TfwHttpReq *req = (TfwHttpReq *)stream->msg;
	TfwHttpMsg *hmsib = NULL;

	/*
	 * In HTTP 1.0 the server always closes the connection
	 * after sending the response unless the client sent a
	 * a "Connection: keep-alive" request header, and the
	 * server sent a "Connection: keep-alive" response header.
	 *
	 * This behavior was added to existing HTTP 1.0 protocol.
	 * RFC 1945 section 1.3 says:
	 * "Except for experimental applications, current practice
	 * requires that the connection be established by the client
	 * prior to each request and closed by the server after
	 * sending the response."
	 *
	 * Make it work this way in Tempesta by setting the flag.
	 */
	if ((req->version == TFW_HTTP_VER_09)
	    || ((req->version == TFW_HTTP_VER_10)
		&& !test_bit(TFW_HTTP_B_CONN_KA, req->flags)))
	{
		__set_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
	}

	/*
	 * The request has been successfully parsed and processed.
	 * If the connection will be closed after the response to
	 * the request is sent to the client, then there's no need
	 * to process pipelined requests. Also, the request may be
	 * released when handled in general HTTP processing in caller
	 * function. So, reset sibling skb pointer (if it exists)
	 * to indicate for the following code that processing must be
	 * stopped, since corresponding flag may not be accessible later
	 * through @req->flags. If the connection must be closed, it
	 * also should be marked with @Conn_Stop flag - to left it alive
	 * for sending responses and, at the same time, to stop passing
	 * data for processing from the lower layer.
	 */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)) {
		TFW_CONN_TYPE(req->conn) |= Conn_Stop;
		if (unlikely(skb)) {
			__kfree_skb(skb);
			skb = NULL;
		}
	}

	/*
	 * Pipelined requests: create a new sibling message.
	 * If pipelined message can't be created, it still possible to
	 * process current one. But @skb must be freed then, since it's
	 * not owned by any message.
	 */
	if (skb) {
		hmsib = tfw_http_msg_create_sibling((TfwHttpMsg *)req, skb);
		if (unlikely(!hmsib)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			__set_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
			TFW_CONN_TYPE(req->conn) |= Conn_Stop;
			tfw_http_conn_error_log(req->conn, "Can't create"
						" pipelined request");
			__kfree_skb(skb);
		}
	}

	/*
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @stream as
	 * further handling of @stream depends on that. Future SKBs
	 * will be put in a new message.
	 * On an error the function returns from anywhere inside
	 * the loop. @stream->msg holds the reference to the message,
	 * which can be used to release it.
	 */
	tfw_stream_unlink_msg(stream);

	/*
	 * Add the request to the list of the client connection
	 * to preserve the correct order of responses to requests.
	 */
	tfw_http_req_add_seq_queue(req);

	return hmsib;
}

void
tfw_http_extract_request_authority(TfwHttpReq *req)
{
	int hid = 0;
	TfwStr *hdrs = req->h_tbl->tbl;

	if (TFW_MSG_H2(req)) {
		/*
		 * RFC 9113, sec-8.3.1:
		 * The recipient of an HTTP/2 request MUST NOT use
		 * the Host header field to determine the target
		 * URI if ":authority" is present.
		 */
		if (!TFW_STR_EMPTY(&hdrs[TFW_HTTP_HDR_H2_AUTHORITY]))
			hid = TFW_HTTP_HDR_H2_AUTHORITY;
		else
			hid = TFW_HTTP_HDR_HOST;
		__h2_msg_hdr_val(&hdrs[hid], &req->host);
	} else {
		/*
		 * req->host can be only filled by HTTP/1.x parser from
		 * absoluteURI, so we act as described by RFC 9112, sec-3.2.2
		 * (https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2):
		 * When an origin server receives a request with an
		 * absolute-form of request-target, the origin server
		 * MUST ignore the received Host header field (if any)
		 * and instead use the host information of the request-target.
		 */
		if (TFW_STR_EMPTY(&req->host))
			tfw_http_msg_clnthdr_val(req, &hdrs[TFW_HTTP_HDR_HOST],
						 TFW_HTTP_HDR_HOST,
						 &req->host);
	}
}

static bool
__check_authority_correctness(TfwHttpReq *req)
{
	switch (req->version) {
	case TFW_HTTP_VER_11:
		/* https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2
		 * A client MUST send a Host header field in an HTTP/1.1
		 * request even if the request-target is in the absolute-form
		 */
		if (test_bit(TFW_HTTP_B_ABSOLUTE_URI, req->flags) &&
		    TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST]))
			return false;
		fallthrough;
	case TFW_HTTP_VER_20:
		/* HTTP/1.1 and HTTP/2 requires authority information */
		return !TFW_STR_EMPTY(&req->host);
	}
	return true;
}

static bool
tfw_http_check_tfh_req_limit(TfwHttpReq *req)
{
	u64 limit = http_get_tf_recs_limit(req->tfh);
	u64 rate = tfh_get_records_rate(req->tfh);

	return rate > limit;
}

/*
 * Whether we should delete request with ready 100-continue response from
 * @seq_queue. Delete request when the body or its part received, but request
 * still in @seq_queue with ready 100-continue response that not sent to client.
 *
 * RFC 9110 10.1.1:
 * A server MAY omit sending a 100 (Continue) response if it has already
 * received some or all of the content for the corresponding request, or
 * if the framing indicates that there is no content.
 */
static bool
tfw_http_should_del_continuation_seq_queue(TfwHttpReq *req)
{
	return test_bit(TFW_HTTP_B_CONTINUE_QUEUED, req->flags);
}

/*
 * Remove request with ready 100-continue response from @seq_queue and free
 * the response.
 */
static void
tfw_http_del_continuation_seq_queue(TfwCliConn *cli_conn, TfwHttpReq *req)
{
	struct list_head *seq_queue = &cli_conn->seq_queue;
	TfwHttpReq *queued_req = NULL;

	clear_bit(TFW_HTTP_B_CONTINUE_QUEUED, req->flags);

	/* Remove request from @seq_queue only if we ensure that it's there.
	 * Otherwise request might be in @ret_queue, therefore we can't do
	 * that under @seq_qlock.
	 */
	spin_lock_bh(&cli_conn->seq_qlock);
	list_for_each_entry(queued_req, seq_queue, msg.seq_list) {
		if (queued_req != req)
			continue;

		list_del_init(&req->msg.seq_list);
		tfw_http_msg_free((TfwHttpMsg *)req->resp);
		spin_unlock_bh(&cli_conn->seq_qlock);
		return;
	}
	spin_unlock_bh(&cli_conn->seq_qlock);

	spin_lock_bh(&cli_conn->ret_qlock);
	/*
	 * Need this section to ensure that request sent or removed from
	 * @ret_queue due to error. We can't move forward if request still in
	 * @ret_queue. In this case we just spin until @ret_queue drained.
	 */
	BUG_ON(!list_empty(&req->msg.seq_list));
	spin_unlock_bh(&cli_conn->ret_qlock);
}

/**
 * Send 100-continue response to the client.
 *
 * When request is the first in the sequence (no pipelined requests), then
 * immediately send 100-continue response to the client, otherwise place
 * request into @seq_queue, the response will be sent later when one of
 * the queued responses will be forwarded by @tfw_http_resp_fwd.
 */
static int
tfw_http_send_continuation(TfwCliConn *cli_conn, TfwHttpReq *req)
{
	TfwHttpResp *resp;
	struct list_head *seq_queue = &cli_conn->seq_queue;
	TfwStr msg = MAX_PREDEF_RESP;

	tfw_http_prep_err_resp(req, 100, &msg);

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		goto err;

	if (tfw_h1_write_resp(resp, 100, &msg)) {
		tfw_http_msg_free((TfwHttpMsg *)resp);
		goto err;
	}

	spin_lock_bh(&cli_conn->seq_qlock);
	if (list_empty(seq_queue)) {
		/*
		 * A queue is empty, don't hold a lock. Next request can be
		 * added to the queue only on the current CPU when this
		 * request will be processed.
		 */
		spin_unlock_bh(&cli_conn->seq_qlock);
		tfw_connection_get((TfwConn *)(cli_conn));
		if (tfw_cli_conn_send(cli_conn, (TfwMsg *)resp)) {
			tfw_http_msg_free((TfwHttpMsg *)resp);
			tfw_connection_put((TfwConn *)(cli_conn));
			goto err;
		}
		tfw_inc_global_hm_stats(resp->status);
		tfw_http_msg_free((TfwHttpMsg *)resp);
		tfw_connection_put((TfwConn *)(cli_conn));
	} else {
		set_bit(TFW_HTTP_B_CONTINUE_QUEUED, req->flags);
		set_bit(TFW_HTTP_B_CONTINUE_RESP, resp->flags);
		set_bit(TFW_HTTP_B_RESP_READY, resp->flags);
		list_add_tail(&req->msg.seq_list, seq_queue);
		spin_unlock_bh(&cli_conn->seq_qlock);
	}

	return 0;

err:
	TFW_INC_STAT_BH(serv.msgs_otherr);
	return T_BAD;
}

/**
 * Whether we should send 100-continue response.
 *
 * Circumstances in which Tempesta must respond with 100-continue code:
 * 1. Headers are fully parsed.
 * 2. "Expect" header is present in request.
 * 3. Vesrion is HTTP/1.1.
 *
 * RFC 9110 10.1.1:
 * - A server that receives a 100-continue expectation in an HTTP/1.0 request
 * MUST ignore that expectation.
 * - A server MAY omit sending a 100 (Continue) response if it has already
 * received some or all of the content for the corresponding request, or if the
 * framing indicates that there is no content.
 */
static bool
tfw_http_should_handle_expect(TfwHttpReq *req)
{
	return test_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags) &&
	       test_bit(TFW_HTTP_B_EXPECT_CONTINUE, req->flags) &&
	       req->version == TFW_HTTP_VER_11;
}

/*
 * Handle `Expect: 100-continue` in the request.
 */
static int
tfw_http_handle_expect_request(TfwCliConn *conn, TfwHttpReq *req)
{
	if (!req->body.len)
		return tfw_http_send_continuation(conn, req);
	else if (tfw_http_should_del_continuation_seq_queue(req))
		/**
		 * Part of the body received, but 100-continue didn't send,
		 * however handled. It implies it was queued, try to remove it
		 * from queue.
		 */
		tfw_http_del_continuation_seq_queue(conn, req);

	return T_OK;
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_req_process(TfwConn *conn, TfwStream *stream, struct sk_buff *skb,
		     struct sk_buff **split)
{
	ss_skb_actor_t *actor;
	unsigned int parsed;
	TfwHttpReq *req;
	TfwHttpMsg *hmsib;
	TfwFsmData data_up;
	int r;
	TfwHttpActionResult res;

	BUG_ON(!stream->msg);

	T_DBG2("Received %u client data bytes on conn=%p msg=%p\n",
	       skb->len, conn, stream->msg);

	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
next_msg:
	parsed = 0;
	hmsib = NULL;
	req = (TfwHttpReq *)stream->msg;
	if (TFW_MSG_H2(req)) {
		actor = tfw_h2_parse_req;
		req->tfh.version = TFW_HTTP_TFH_HTTP2_REQ;
	} else {
		actor = tfw_http_parse_req;
		req->tfh.version = TFW_HTTP_TFH_HTTP_REQ;
	}

	r = ss_skb_process(skb, actor, req, &req->chunk_cnt, &parsed);
	req->msg.len += parsed;
	TFW_ADD_STAT_BH(parsed, clnt.rx_bytes);

	T_DBG2("Request parsed: len=%u next=%pK parsed=%d msg_len=%lu"
	       " ver=%d res=%d\n",
		 skb->len, skb->next, parsed, req->msg.len, req->version, r);

	/*
	 * We have to keep @skb the same to pass it as is to FSMs
	 * registered with lower priorities after us, but we must
	 * feed the new data version to FSMs registered on our states.
	 */
	data_up.skb = skb;
	data_up.req = (TfwMsg *)req;
	data_up.resp = NULL;

	switch (r) {
	case T_DROP:
	default:
		/*
		 * System errors, memory allocation, invalid arguments
		 * and so on.
		 */
	case T_COMPRESSION:
		fallthrough;
	case T_BAD:
		T_DBG2("Drop invalid HTTP request\n");
		TFW_INC_STAT_BH(clnt.msgs_parserr);
		return tfw_http_req_parse_drop_with_fin(req, 400, NULL,
							r == T_COMPRESSION
							? HTTP2_ECODE_COMPRESSION
							: HTTP2_ECODE_PROTO);
	case T_BLOCK:
		T_DBG2("Block invalid HTTP request\n");
		TFW_INC_STAT_BH(clnt.msgs_parserr);
		return tfw_http_req_parse_block(req, 403, NULL,
						HTTP2_ECODE_PROTO);
	case T_POSTPONE:
		if (WARN_ON_ONCE(parsed != data_up.skb->len)) {
			/*
			 * The parser should only return T_POSTPONE if it ate
			 * all available data, but that weren't enough.
			 */
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return tfw_http_req_parse_block(req, 500,
					"Request parsing inconsistency",
					HTTP2_ECODE_PROTO);
		}
		if (TFW_MSG_H2(req)) {
			TfwH2Ctx *ctx = tfw_h2_context_unsafe(conn);

			/* Do not check the request validity until
			 * it has been fully parsed.
			 */
			if (unlikely(ctx->to_read))
				return T_OK;

			/* If the parser met END_HEADERS flag we can be sure
			 * that we get and processed all headers.
			 * We will be at this point even if the parser met
			 * END_STREAM and END_HEADERS flags at once.
			 *
			 * We should see END_HEADERS in the following cases:
			 * - single HEADERS/PUSH_PROMISE w/ END_HEADERS set
			 * - HEADERS/PUSH_PROMISE w/o END_HEADERS flag +
			 *   one or more CONTINUATION, where the last
			 *   CONTINUATION has END_HEADERS set
			 * - trailer HEADERS frame might contain END_HEADERS as well
			 */
			if (ctx->hdr.flags & HTTP2_F_END_HEADERS) {
				if (unlikely(tfw_http_parse_check_bodyless_meth(req))) {
					return tfw_http_req_parse_drop_with_fin(req, 400,
							"Request contains Content-Length"
							" or Content-Type field"
							" for bodyless method",
							HTTP2_ECODE_PROTO);
				}

				__set_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags);
				tfw_http_extract_request_authority(req);
			}

			if (tfw_h2_strm_req_is_compl(req->stream)) {
				if (likely(!tfw_h2_parse_req_finish(req)))
					break;
				TFW_INC_STAT_BH(clnt.msgs_otherr);
				return	tfw_http_req_parse_drop_with_fin(req, 400,
						"Request parsing inconsistency",
						HTTP2_ECODE_PROTO);
			}
		}

		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_CHUNK, &data_up);
		T_DBG3("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
		if (r == T_BLOCK) {
			TFW_INC_STAT_BH(clnt.msgs_filtout);
			return tfw_http_req_parse_block(req, 403,
					"postponed request has been filtered out",
					HTTP2_ECODE_PROTO);
		}

		if (tfw_http_should_handle_expect(req)) {
			r = tfw_http_handle_expect_request((TfwCliConn *)conn,
							   req);
			if (unlikely(r))
				return r;
		}

		/*
		 * T_POSTPONE status means that parsing succeeded
		 * but more data is needed to complete it. Lower layers
		 * just supply data for parsing. They only want to know
		 * if processing of a message should continue or not.
		 */
		return T_OK;

	case T_OK:
		/*
		 * The request is fully parsed, fall through and process it.
		 */
		if (WARN_ON_ONCE(!test_bit(TFW_HTTP_B_CHUNKED, req->flags)
				 && (req->content_length != req->body.len))) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return tfw_http_req_parse_drop_with_fin(req, 500,
				"Request parsing inconsistency",
				HTTP2_ECODE_PROTO);
		}
	}

	/* The body received, remove 100-continue from queue. */
	if (unlikely(tfw_http_should_del_continuation_seq_queue(req)))
		tfw_http_del_continuation_seq_queue((TfwCliConn *)conn, req);

	req->tfh.method = req->method;

	if (tfw_http_check_tfh_req_limit(req)) {
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		return tfw_http_req_parse_block(req, 403,
				"parsed request exceeded tfh limit",
				HTTP2_ECODE_PROTO);
	}


	/*
	 * The message is fully parsed, the rest of the data in the
	 * stream may represent another request or its part.
	 * If skb splitting has failed, the request can't be forwarded
	 * to backend server or request-response sequence can be broken.
	 * @skb is replaced with pointer to a new SKB.
	 */
	if (parsed < skb->len) {
		WARN_ON_ONCE(TFW_MSG_H2(req));
		/* Don't pipeline anything after UPGRADE request. */
		if (test_bit(TFW_HTTP_B_CONN_UPGRADE, req->flags)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return tfw_http_req_parse_block(req, 400,
					"Request dropped: "
					"Pipelined request received "
					"after UPGRADE request",
					HTTP2_ECODE_PROTO);
		}
		skb = ss_skb_split(skb, parsed);
		if (unlikely(!skb)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return tfw_http_req_parse_drop(req, 500,
					"Can't split pipelined requests",
					HTTP2_ECODE_PROTO);
		}
		*split = skb;
	} else {
		skb = NULL;
	}

	/*
	 * XXX __check_authority_correctness() is called after parsing a whole
	 * request, including body. For example: if we have a request with
	 * invalid host/authority it will be dropped only after full parsing
	 * while it's enough to parse only headers.
	 */
	if (!__check_authority_correctness(req)) {
		return tfw_http_req_parse_drop(req, 400, "Invalid authority",
					       HTTP2_ECODE_PROTO);
	}

	if ((r = tfw_http_req_client_link(conn, req))) {
		return tfw_http_req_parse_drop(req, 400, "request dropped: "
				"incorrect X-Forwarded-For header",
				HTTP2_ECODE_PROTO);
	}

	/*
	 * Assign a target virtual host for the current request before further
	 * processing.
	 *
	 * There are multiple ways to get a target vhost:
	 * - search in HTTP chains (defined in the configuration by an admin),
	 * can be slow on big configurations, since chains are tested
	 * one-by-one;
	 * - get vhost from the HTTP session information (by Sticky cookie);
	 * - get Vhost according to TLS SNI header parsing.
	 *
	 * There is a possibility, that each method will give a very different
	 * result. It absolutely depends on configuration provided by
	 * an administrator and application behaviour. Some differences are
	 * expected anyway, e.g. if tls client doesn't send an SNI identifier
	 * it will be matched to 'default' vhost while http_chains can identify
	 * target vhost. We also can't just skip http_chains and fully rely
	 * on sticky module, since http_chains also contains non-terminating
	 * rules, such as `mark` rule. Even if http_chains is the
	 * slowest method we have, we can't simply skip it.
	 */
	if (unlikely(r = tfw_http_tbl_action((TfwMsg *)req, &res))) {
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		return tfw_http_req_parse_block(req, 403,
				"request has been filtered out via http table",
				HTTP2_ECODE_PROTO);
	}
	if (res.type == TFW_HTTP_RES_VHOST) {
		req->vhost = res.vhost;
	}
	if (req->vhost)
		req->location = tfw_location_match(req->vhost, &req->uri_path);
	/*
	 * If vhost is not found the request will be dropped, but it will still
	 * go through some processing stages since some subsystems need to track
	 * all incoming requests.
	 */
	/*
	 * The time the request was received is used for age
	 * calculations in cache, and for eviction purposes.
	 */
	req->cache_ctl.timestamp = tfw_current_timestamp();
	/*
	 * Bypass cache if corresponding binary flag in request set.
	 * We need separate from cache_ctl binary flag in request
	 * due to multiple rules may one after one set and clear
	 * the flag before it evaluated to CC_NO_CACHE here.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_CHAIN_NO_CACHE, req->flags)))
		req->cache_ctl.flags |= TFW_HTTP_CC_NO_CACHE;

	/*
	 * Run frang checks first before any processing happen. Can't start
	 * the checks earlier, since vhost and specific client is required
	 * for frang checks.
	 *
	 * If a request was received in a single skb, the only frang check
	 * happens here. At the first sight it seems like http tables are not
	 * protected with anti-DDoS limits and attackers may stress http tables
	 * as long as they want till they get 403 responses from us. But
	 * Tempesta closes connection every time it faces `block` action
	 * in HTTP table, this causes attackers to open a new connection
	 * for every new request. Connection rates limits usually much more
	 * strict than request rates, so this attack path is closed by usual
	 * frang configuration.
	 *
	 * TODO #1490: block the request if Frang didn't finish its job.
	 */
	r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_MSG, &data_up);
	T_DBG3("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
	/* Don't accept any following requests from the peer. */
	if (r == T_BLOCK) {
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		return tfw_http_req_parse_block(req, 403,
				"parsed request has been filtered out",
				HTTP2_ECODE_PROTO);
	}

	if (res.type == TFW_HTTP_RES_REDIR) {
		tfw_http_req_redir(req, res.redir.resp_code, &res.redir);
		return T_OK;
	}

	if (unlikely(req->method == TFW_HTTP_METH_PURGE)) {
		/* Override shouldn't be combined with PURGE, that'd
		 * probably break things */
		req->method_override = _TFW_HTTP_METH_NONE;
	} else {
		__clear_bit(TFW_HTTP_B_PURGE_GET, req->flags);
	}

	/*
	 * Method override masks real request properties, non-idempotent methods
	 * can hide behind idempotent, method is used as a key in cache
	 * subsystem to store and look up cached responses. Thus hiding real
	 * method can spoil responses for other clients. Use the real method
	 * for accurate processing.
	 *
	 * We don't rewrite the method string and don't remove override header
	 * since there can be additional intermediates between TempestaFW and
	 * backend.
	 *
	 * While non-idempotent method can be hidden behind idempotent, it is
	 * reasonable to expect that non-safe method can not be hidden behind
	 * safe method.
	 */
	if (unlikely(req->method_override)) {
		if (TFW_HTTP_IS_METH_SAFE(req->method)
			&& !TFW_HTTP_IS_METH_SAFE(req->method_override))
		{
			return tfw_http_req_parse_block(req, 400,
					"request dropped: unsafe"
					" method override",
					HTTP2_ECODE_PROTO);
		}
		req->method = req->method_override;
	}

	/*
	 * Sticky cookie module must be used before request can reach cache.
	 * Unauthorised clients mustn't be able to get any resource on protected
	 * service. If client requested non-challengeable resource, we try to
	 * service such request from cache. The module is also the quickest way
	 * to obtain target VHost and target backend server connection since it
	 * allows to avoid expensive tables lookups.
	 *
	 * We should obtain session after set method according method override.
	 * When client sends HEAD or POST request and set X-HTTP-Method-Override
	 * to GET. We should send js challenge to the client because the real
	 * method, expected by the client is GET.
	 */
	switch (tfw_http_sess_obtain(req)) {
	case TFW_HTTP_SESS_SUCCESS:
		break;

	case TFW_HTTP_SESS_REDIRECT_NEED:
		/* Response is built and stored in @req->resp. */
		break;

	case TFW_HTTP_SESS_VIOLATE:
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		return tfw_http_req_parse_block(req, 403, NULL,
						HTTP2_ECODE_PROTO);

	case TFW_HTTP_SESS_JS_NOT_SUPPORTED:
		/*
		 * Requested resource can't be challenged, try service it
		 * from cache.
		 */
		T_DBG("Can't send JS challenge for request since a "
		      "non-challengeable resource (e.g. image) was requested");
		__set_bit(TFW_HTTP_B_JS_NOT_SUPPORTED, req->flags);
		break;

	case TFW_HTTP_SESS_FAILURE:
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return tfw_http_req_parse_drop_with_fin(req, 500,
				"request dropped: internal error"
				" in Sticky module",
				HTTP2_ECODE_PROTO);
	default:
		BUG();
	}

	*split = NULL;
	if (TFW_MSG_H2(req))
		/*
		 * Just marks request as non-idempotent if required.
		 */
		tfw_http_req_mark_nip(req);
	else
		hmsib = tfw_h1_req_process(stream, skb);

	/*
	 * Response is already prepared for the client by sticky module.
	 */
	if (unlikely(req->resp)) {
		if (TFW_MSG_H2(req))
			tfw_h2_resp_fwd(req->resp);
		else
			tfw_http_resp_fwd(req->resp);
	}
	/*
	 * If no virtual host has been found for current request, there
	 * is no sense for its further processing, so we drop it, send
	 * error response to client and move on to the next request.
	 */
	else if (unlikely(!req->vhost)) {
		tfw_http_send_err_resp(req, 403, "request dropped:"
				       " cannot find appropriate virtual host");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
	/*
	 * Look up a cache entry for this request. If there's one, a response
	 * will be linked to this request. Then our callback will either return
	 * a cached response, or forward the request to an upstream.
	 */
	else if (tfw_cache_process((TfwHttpMsg *)req, tfw_http_req_cache_cb)) {
		/*
		 * The request should either be stored or released.
		 * Otherwise we lose the reference to it and get a leak.
		 */
		tfw_http_send_err_resp(req, 500, "request dropped:"
				       " processing error");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}	
	/*
	 * According to RFC 7230 6.3.2, connection with a client
	 * must be dropped after a response is sent to that client,
	 * if the client sends "Connection: close" header field in
	 * the request (@tfw_h1_req_process() return NULL for @hmsib
	 * in this case). Subsequent requests from the client coming
	 * over the same connection are ignored.
	 *
	 * Note: This connection's @conn must not be dereferenced
	 * from this point on.
	 */
	if (hmsib) {
		/*
		 * No sibling messages should appear in processing
		 * of HTTP/2 protocol.
		 */
		WARN_ON_ONCE(TFW_MSG_H2(hmsib));
		/*
		 * Switch connection to the new sibling message.
		 * Data processing will continue with the new SKB.
		 */
		stream->msg = (TfwMsg *)hmsib;
		goto next_msg;
	}

	return r;
}

/**
 * Process the cached response from tfw_cache_process() or the original
 * response from a backend if it wasn't cached due to certain circumstances
 * or conditions.
 *
 * This is the second half of tfw_http_resp_process().
 * tfw_http_resp_process() runs in SoftIRQ whereas tfw_http_resp_cache_cb()
 * runs in cache thread that is scheduled at an appropriate TDB node.
 *
 * HTTP requests are usually much smaller than HTTP responses, so it's
 * better to transfer requests to a TDB node to make any adjustments.
 * The other benefit of the scheme is that less work is done in SoftIRQ.
 */
static void
tfw_http_resp_cache_cb(TfwHttpMsg *msg)
{
	TfwHttpResp *resp = (TfwHttpResp *)msg;

	T_DBG2("%s: req = %p, resp = %p\n", __func__, resp->req, resp);

	tfw_http_sess_learn(resp);

	if (TFW_MSG_H2(resp->req))
		tfw_h2_resp_adjust_fwd(resp);
	else
		tfw_h1_resp_adjust_fwd(resp);
}

/**
 * Just received response is parsed and processed. The corresponding
 * request is the first one in the connection forwarding
 * queue, and srv_conn->last_msg_sent points to it or to one of the next
 * requests. @fwd_unsent is set to true if progress inside connection is
 * possible. The forwarding queue state is fully consistent after the call.
 *
 * If processing of the response is successful then it's possible to forward
 * all unsent requests.
 *
 * Upstreams don't normally send invalid responses. The processing error will
 * happen once again if the request will be re-sent or forwarded to another
 * server. Delist the request to prevent future errors. The server connection
 * is about to be closed and there is no sense in forwarding unsent requests.
 *
 * TODO: When a response is received and a paired request is found,
 * pending (unsent) requests in the connection are forwarded to the
 * server right away. In current design, @fwd_queue is locked until
 * after a request is submitted to SS for sending. It shouldn't be
 * necessary to lock @fwd_queue for that. Please see a similar TODO
 * comment to tfw_http_req_fwd(). Also, please see the issue #687.
 */
static void
tfw_http_popreq(TfwHttpMsg *hmresp, bool fwd_unsent)
{
	int err = 0;
	TfwHttpReq *req = hmresp->req;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmresp->conn;
	LIST_HEAD(reschq);
	LIST_HEAD(eq);

	spin_lock(&srv_conn->fwd_qlock);
	if ((TfwMsg *)req == srv_conn->last_msg_sent)
		srv_conn->last_msg_sent = NULL;
	if ((TfwMsg *)req == srv_conn->curr_msg_sent)
		srv_conn->curr_msg_sent = NULL;
	tfw_http_req_delist(srv_conn, req);
	tfw_http_conn_nip_adjust(srv_conn);

	if (unlikely(!fwd_unsent)) {
		spin_unlock(&srv_conn->fwd_qlock);
		return;
	}
	/*
	 * Run special processing if the connection is in repair
	 * mode. Otherwise, forward pending requests to the server.
	 *
	 * @hmresp is holding a reference to the server connection
	 * while forwarding is done, so there's no need to take an
	 * additional reference.
	 */
	if (unlikely(tfw_srv_conn_restricted(srv_conn)))
		err = tfw_http_conn_fwd_repair(srv_conn, &eq);
	else if (tfw_http_conn_need_fwd(srv_conn))
		err = tfw_http_conn_fwd_unsent(srv_conn, &eq);
	if (!err) {
		spin_unlock(&srv_conn->fwd_qlock);
		goto out;
	}
	/*
	 * If error occurred during repairing or forwarding procedures
	 * (-EBUSY and @last_msg_sent is NULL) the rescheduling is started;
	 * Since @last_msg_sent is definitely NULL here, there must not be
	 * pending sibling responses attached to requests, so it is
	 * safe to cut all remaining requests from @fwd_queue for
	 * rescheduling.
	 */
	WARN_ON(srv_conn->curr_msg_sent || srv_conn->last_msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	tfw_srv_set_busy_delay(srv_conn);
	tfw_http_fwdq_reset(srv_conn, &reschq);
	spin_unlock(&srv_conn->fwd_qlock);

	tfw_http_fwdq_resched(srv_conn, &reschq, &eq);
out:
	tfw_http_req_zap_error(&eq);
}

/*
 * Post-process the response. Pass it to modules registered with GFSM
 * for further processing. Finish the request/response exchange properly
 * in case of an error.
 */
static int
tfw_http_resp_gfsm(TfwHttpMsg *hmresp, TfwFsmData *data)
{
	int r;
	TfwHttpReq *req = hmresp->req;

	BUG_ON(!hmresp->conn);

	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG, data);
	T_DBG3("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
	if (r == T_BLOCK)
		goto error;

	BUG_ON(r != T_OK);

	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_LOCAL_RESP_FILTER,
			  data);
	T_DBG3("TFW_HTTP_FSM_LOCAL_RESP_FILTER return code %d\n", r);
	if (r == T_OK)
		return T_OK;

	BUG_ON(r != T_BLOCK);

error:
	tfw_http_popreq(hmresp, false);
	TFW_INC_STAT_BH(serv.msgs_filtout);
	/* The response is freed by tfw_http_req_block(). */
	return tfw_http_req_block(req, 403, "response blocked: filtered out",
				  HTTP2_ECODE_PROTO);
}

/*
 * Set up the response @hmresp with data needed down the road,
 * get the paired request, and then pass the response to cache
 * for further processing.
 */
static int
tfw_http_resp_cache(TfwHttpMsg *hmresp)
{
	int r;
	TfwHttpResp *resp = (TfwHttpResp *)hmresp;
	TfwHttpReq *req = hmresp->req;
	TfwFsmData data;
	long timestamp = tfw_current_timestamp();
	unsigned long jrtime;

	/*
	 * The time the response was received is used in cache
	 * for age calculations, and for APM and Load Balancing.
	 */
	hmresp->cache_ctl.timestamp = timestamp;
	/*
	 * If 'Date:' header is missing in the response, then
	 * set the date to the time the response was received.
	 */
	if (!test_bit(TFW_HTTP_B_HDR_DATE, hmresp->flags))
		((TfwHttpResp *)hmresp)->date = timestamp;
	/*
	 * Response is fully received, delist corresponding request from
	 * fwd_queue.
	 */
	tfw_http_popreq(hmresp, true);
	/*
	 * TODO: Currently APM holds the pure roundtrip time (RTT) from
	 * the time a request is forwarded to the time a response to it
	 * is received and parsed. Perhaps it makes sense to penalize
	 * server connections which get broken too often. What would be
	 * a fast and simple algorithm for that? Keep in mind, that the
	 * value of RTT has an upper boundary in the APM.
	 */
	jrtime = resp->jrxtstamp - req->jtxtstamp;
	tfw_apm_update(((TfwServer *)resp->conn->peer)->apmref,
		       resp->jrxtstamp, jrtime);
	tfw_apm_update_global(resp->jrxtstamp, jrtime);
	/*
	 * Health monitor request means that its response need not to
	 * send anywhere.
	 */
	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		tfw_http_hm_drop_resp((TfwHttpResp *)hmresp);
		return T_OK;
	}
	/*
	 * This hook isn't in tfw_http_resp_fwd() because responses from the
	 * cache shouldn't be accounted.
	 */
	data.skb = NULL;
	data.req = (TfwMsg *)req;
	data.resp = (TfwMsg *)hmresp;
	if (tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG_FWD,
			  &data)) {
		TFW_INC_STAT_BH(serv.msgs_filtout);
		/* The response is freed by tfw_http_req_block(). */
		return tfw_http_req_block(req, 403, "response blocked: filtered out",
					  HTTP2_ECODE_PROTO);
	}

	/*
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @stream as
	 * further handling of @conn depends on that. Future SKBs
	 * will be put in a new message.
	 */
	tfw_stream_unlink_msg(hmresp->stream);
	if ((r = tfw_cache_process(hmresp, tfw_http_resp_cache_cb)))
	{
		tfw_http_conn_msg_free(hmresp);
		tfw_http_send_err_resp(req, 500, "response dropped:"
				   " processing error");
		TFW_INC_STAT_BH(serv.msgs_otherr);
		/* Proceed with processing of the next response. */
		return r;
	}

	return T_OK;
}

/*
 * Finish a response that is terminated by closing the connection.
 *
 * Http/1 response is terminated by connection close and lacks of framing
 * information. H2 connections have their own framing happening just before
 * forwarding message to network, but h1 connections still require explicit
 * framing.
 */
static void
tfw_http_resp_terminate(TfwHttpMsg *hm)
{
	TfwFsmData data;

	/*
	 * Response to HTTP2 client which has flag TFW_HTTP_B_CHUNKED_APPLIED
	 * blocks during response parsing.
	 */
	WARN_ON_ONCE(TFW_MSG_H2(hm->req)
		     && test_bit(TFW_HTTP_B_CHUNKED_APPLIED, hm->flags));

	if (test_bit(TFW_HTTP_B_CHUNKED_APPLIED, hm->flags))
		set_bit(TFW_HTTP_B_CONN_CLOSE, hm->req->flags);

	if (!TFW_MSG_H2(hm->req)) {
		int r;

		r = tfw_http_add_hdr_clen(hm);
		if (r) {
			TfwHttpReq *req = hm->req;

			tfw_http_popreq(hm, false);
			/* The response is freed by tfw_http_req_block(). */
			tfw_http_req_block(req, 502, "response blocked: filtered out",
					HTTP2_ECODE_PROTO);
			TFW_INC_STAT_BH(serv.msgs_filtout);
			return;
		}
	}

	/*
	 * Note that in this case we don't have data to process.
	 * All data has been processed already. The response needs
	 * to go through Tempesta's post-processing, and then be
	 * sent to the client. The full skb->len is used as the
	 * offset to mark this case in the post-processing phase.
	 */
	data.skb = ss_skb_peek_tail(&hm->msg.skb_head);
	BUG_ON(!data.skb);
	data.req = NULL;
	data.resp = (TfwMsg *)hm;

	if (tfw_http_resp_gfsm(hm, &data) != T_OK)
		return;

	tfw_http_resp_cache(hm);
}

static int
tfw_http_resp_fwd_stale(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req = hmresp->req;
	TfwFsmData data;

	/*
	 * Response is fully received, delist corresponding request from
	 * fwd_queue.
	 */
	tfw_http_popreq(hmresp, true);

	tfw_apm_update(((TfwServer *)hmresp->conn->peer)->apmref,
		       jiffies, jiffies - req->jtxtstamp);

	BUG_ON(test_bit(TFW_HTTP_B_HMONITOR, req->flags));

	/*
	 * Let frang do all necessery checks for the response, before
	 * responding with a stale response.
	 */
	data.skb = NULL;
	data.req = (TfwMsg *)req;
	data.resp = (TfwMsg *)hmresp;
	if (tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG_FWD,
			  &data)) {
		TFW_INC_STAT_BH(serv.msgs_filtout);
		/* The response is freed by tfw_http_req_block(). */
		return tfw_http_req_block(req, 403, "response blocked: filtered out",
					  HTTP2_ECODE_PROTO);
	}

	if (!__tfw_http_resp_fwd_stale(hmresp)) {
		tfw_http_req_drop(req, 502,
				  "response dropped: processing error",
				  HTTP2_ECODE_PROTO);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return T_BAD;
	}

	return T_OK;
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_resp_process(TfwConn *conn, TfwStream *stream, struct sk_buff *skb,
		      struct sk_buff **split)
{
	int r;
	unsigned int chunks_unused, parsed;
	TfwHttpReq *bad_req;
	TfwHttpMsg *hmresp, *hmsib;
	TfwCliConn *cli_conn;
	TfwFsmData data_up;
	bool conn_stop, filtout = false, websocket = false;

	BUG_ON(!stream->msg);
	/*
	 * #769: There is no client side TLS, so we don't read HTTP responses
	 * through TLS connection, so trail and off should be zero.
	 * However, TCP overlapping segments still may produce non-zero offset
	 * in ss_tcp_process_skb().
	 */

	T_DBG2("Received %u server data bytes on conn=%p msg=%p\n",
	       skb->len, conn, stream->msg);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
next_msg:
	conn_stop = false;
	parsed = 0;
	hmsib = NULL;
	hmresp = (TfwHttpMsg *)stream->msg;
	cli_conn = (TfwCliConn *)hmresp->req->conn;

	r = ss_skb_process(skb, tfw_http_parse_resp, hmresp, &chunks_unused,
			   &parsed);
	hmresp->msg.len += parsed;
	TFW_ADD_STAT_BH(parsed, serv.rx_bytes);

	T_DBG2("Response parsed: len=%u parsed=%d msg_len=%lu ver=%d res=%d\n",
	       skb->len, parsed, hmresp->msg.len, hmresp->version, r);

	/*
	 * We have to keep @skb the same to pass it as is to FSMs
	 * registered with lower priorities after us, but we must
	 * feed the new data version to FSMs registered on our states.
	 */
	data_up.skb = skb;
	data_up.req = NULL;
	data_up.resp = (TfwMsg *)hmresp;

	switch (r) {
	case T_DROP:
	default:
		/*
		 * System errors, memory allocation, invalid arguments
		 * and so on.
		 */
	case T_BAD:
		T_DBG2("Drop invalid HTTP response\n");
		TFW_INC_STAT_BH(serv.msgs_parserr);
		goto bad_msg;
	case T_BLOCK:
		/*
		 * The response has not been fully parsed. There's no
		 * choice but report a critical error. The lower layer
		 * will close the connection and release the response
		 * message, and well as all request messages that went
		 * out on this connection and are waiting for paired
		 * response messages.
		 */
		T_DBG2("Block invalid HTTP response\n");
		TFW_INC_STAT_BH(serv.msgs_parserr);
		filtout = true;
		goto bad_msg;
	case T_POSTPONE:
		if (WARN_ON_ONCE(parsed != data_up.skb->len)) {
			/*
			 * The parser should only return T_POSTPONE if it ate
			 * all available data, but that weren't enough.
			 */
			TFW_INC_STAT_BH(serv.msgs_otherr);
			goto bad_msg;
		}
		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_RESP_CHUNK,
				  &data_up);
		T_DBG3("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
		if (r == T_BLOCK) {
			TFW_INC_STAT_BH(serv.msgs_filtout);
			filtout = true;
			goto bad_msg;
		}

		/*
		 * T_POSTPONE status means that parsing succeeded
		 * but more data is needed to complete it. Lower layers
		 * just supply data for parsing. They only want to know
		 * if processing of a message should continue or not.
		 */
		return T_OK;
	case T_OK:
		/*
		 * The response is fully parsed, fall through and
		 * process it. If the response has broken length, then
		 * block it (the server connection will be dropped).
		 */
		if (!(test_bit(TFW_HTTP_B_CHUNKED, hmresp->flags)
		      || test_bit(TFW_HTTP_B_VOID_BODY, hmresp->flags))
		    && (hmresp->content_length != hmresp->body.len))
		{
			goto bad_msg;
		}
	}

	/*
	 * The message is fully parsed, the rest of the data in the
	 * stream may represent another response or its part.
	 * If skb splitting has failed, the response cant be forwarded
	 * to client or request-response sequence on client side can be
	 * broken and client may receive sensitive data from other
	 * clients can be also sent there.
	 * @skb is replaced with pointer to a new SKB.
	 */
	if (parsed < skb->len) {
		skb = ss_skb_split(skb, parsed);
		if (unlikely(!skb)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			goto bad_msg;
		}
		*split = skb;
	}
	else {
		skb = NULL;
	}

	/*
	 * Verify response in context of http health monitor,
	 * and mark server as disabled/enabled.
	 *
	 * TODO (TBD) Probably we should close server connection here to
	 * make all queued request be rescheduled to other servers.
	 * Also it's a common practice to reset and reestablish
	 * connections with buggy applications. Now we stop scheduling
	 * new requests to the server and forward all, probably error
	 * responses, for queued requests to clients.
	 */
	tfw_http_hm_control((TfwHttpResp *)hmresp);

	/*
	 * Pass the response to GFSM for further processing.
	 * Drop server connection in case of serious error or security
	 * event.
	 */
	r = tfw_http_resp_gfsm(hmresp, &data_up);
	if (unlikely(r))
		return r;

	/*
	 * We need to know if connection will be upgraded after response
	 * forwarding here before sibling processing because after upgrade
	 * http semantics for pipelined responses no longer apply.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_CONN_UPGRADE, hmresp->flags)
		     && test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, hmresp->flags)
		     && ((TfwHttpResp *)hmresp)->status == 101))
	{
		websocket = true;
	}

	/*
	 * If @skb's data has not been processed in full, then
	 * we have pipelined responses. Create a sibling message.
	 * @skb is replaced with a pointer to a new SKB.
	 *
	 * RFC6455#section-5.5.2:
	 * If the server finishes ... without aborting the WebSocket
	 * handshake, the server considers the WebSocket connection to be
	 * established and that the WebSocket connection is in the OPEN state.
	 * At this point, the server may begin sending (and receiving) data.
	 *
	 * This means that can be no http sibling messages on successfully
	 * opened (upgraded) websocket connection. Further data is websocket
	 * protocol data.
	 */
	if (skb && !websocket) {
		*split = NULL;
		hmsib = tfw_http_msg_create_sibling(hmresp, skb);
		/*
		 * In case of an error there's no recourse. The
		 * caller expects that data is processed in full,
		 * and can't deal with partially processed data.
		 */
		if (unlikely(!hmsib)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			tfw_http_conn_error_log(conn, "Can't create pipelined"
						      " response");
			__kfree_skb(skb);
			skb = NULL;
			conn_stop = true;
		}
	}

	/*
	 * Do upgrade if correct websocket upgrade response detected earlier.
	 * We have to do this before going to the cache, since the cache calls
	 * the message forwarding on a callback, which may free both the request
	 * and response leading to zero reference counter on the client
	 * connection and its corresponding freeing.
	 */
	if (websocket) {
		r = tfw_http_websocket_upgrade((TfwSrvConn *)conn, cli_conn);
		if (unlikely(r != T_OK))
			return r;
	}

	/* Respond with stale cached response. */
	if (tfw_http_resp_should_fwd_stale(hmresp->req,
					   ((TfwHttpResp *)hmresp)->status))
		r = tfw_http_resp_fwd_stale(hmresp);
	else
		/*
		 * Pass the response to cache for further processing.
		 * In the end, the response is sent on to the client.
		 * @hmsib is not attached to the connection yet.
		 */
		r = tfw_http_resp_cache(hmresp);

	if (unlikely(r != T_OK)) {
		if (hmsib)
			tfw_http_conn_msg_free(hmsib);
		return r;
	}

	*split = NULL;
	if (skb && websocket)
		return tfw_ws_msg_process(cli_conn->pair, skb);
	if (hmsib) {
		/*
		 * Switch the connection to the sibling message.
		 * Data processing will continue with the new SKB.
		 */
		stream->msg = (TfwMsg *)hmsib;
		goto next_msg;
	}
	else if (unlikely(conn_stop)) {
		/*
		 * Creation of sibling response has failed, close
		 * the connection to recover.
		 */
		return T_BAD;
	}

	return T_OK;
bad_msg:
	/*
	 * Response can't be parsed or processed. This is abnormal situation,
	 * upstream server usually sends valid responses or closes the
	 * connection when it refuses to serve the request. But this exact
	 * request makes server to send invalid response. Most likely that the
	 * situation will happen once again if the request will be re-sent.
	 * Send error or drop the request.
	 */
	bad_req = hmresp->req;
	tfw_http_popreq(hmresp, false);

	/*
	 * Special case: malformed response to a Health Monitor request.
	 * There's no client involved, so just log-n-drop the response now
	 * without further processing.
	 */
	if(unlikely(test_bit(TFW_HTTP_B_HMONITOR, bad_req->flags))) {
		T_WARN("Health Monitor response malformed");
		tfw_http_resp_pair_free(bad_req);
		return T_OK;
	}

	if (!filtout && tfw_http_resp_should_fwd_stale(bad_req, 502)) {
		if (!__tfw_http_resp_fwd_stale(hmresp)) {
			tfw_http_req_drop(bad_req, 502,
					  "response dropped: processing error",
					  HTTP2_ECODE_PROTO);
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
		/*
		 * Mark server connection as Conn_Stop to prevent multiple
		 * calls of @tfw_http_resp_process() when original response
		 * is freed and connection ready for closing. It may happens
		 * when error occurred in the middle of the message that has
		 * sent in multiple SKBs. In this case we close connection,
		 * but still continue to process rest of SKBs and parse data,
		 * that is dangerous.
		 */
		TFW_CONN_TYPE(conn) |= Conn_Stop;
		/*
		 * Close connection with backend immediately
		 * and try to re-establish it later.
		 */
		r = T_BAD;
	} else {
		/* The response is freed by tfw_http_req_block/drop(). */
		if (filtout) {
			r = tfw_http_req_block(bad_req, 502,
					       "response blocked: filtered out",
					       HTTP2_ECODE_PROTO);
		} else {
			tfw_http_req_drop(bad_req, 502,
					  "response dropped: processing error",
					  HTTP2_ECODE_PROTO);
			/*
			 * Close connection with backend immediately
			 * and try to re-establish it later.
			 */
			r = T_BAD;
		}
	}

	return r;
}

static inline int
__tfw_upgrade_in_queue(TfwCliConn *cli_conn)
{
	TfwHttpReq *req_prev;
	struct list_head *seq_queue = &cli_conn->seq_queue;

	req_prev = list_empty(seq_queue) ? NULL :
		list_last_entry(seq_queue, TfwHttpReq, msg.seq_list);
	if (req_prev && test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
				 req_prev->flags))
	{
		T_WARN_ADDR("Request dropped: Pipelined request received after "
			    "UPGRADE request", &cli_conn->peer->addr,
			    TFW_NO_PORT);
		return T_BAD;
	}

	return T_OK;
}

/**
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process_generic(TfwConn *conn, TfwStream *stream,
			     struct sk_buff *skb, struct sk_buff **next)
{
	int r = T_BAD;
	TfwHttpMsg *req;
	bool websocket;

	if (WARN_ON_ONCE(!stream))
		goto err;
	if (unlikely(!stream->msg)) {
		if (TFW_CONN_TYPE(conn) & Conn_Clnt
		    && (r = __tfw_upgrade_in_queue((TfwCliConn *)conn))) {
			goto err;
		}
		stream->msg = tfw_http_conn_msg_alloc(conn, stream);
		if (!stream->msg) {
			r = -ENOMEM;
			goto err;
		}
		T_DBG2("Link new msg %p with connection %p\n",
		       stream->msg, conn);
	}

	T_DBG2("Add skb %pK to message %pK\n", skb, stream->msg);
	ss_skb_queue_tail(&stream->msg->skb_head, skb);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt)
		return tfw_http_req_process(conn, stream, skb, next);

	/* That is paired request, it may be freed after resp processing,
	 * so we cannot move it iside `if` clause. */
	req = ((TfwHttpMsg *)stream->msg)->pair;
	websocket = test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags);
	if ((r = tfw_http_resp_process(conn, stream, skb, next))) {
		TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
		/*
		 * We must clear TFW_CONN_B_UNSCHED to make server connection
		 * available for request scheduling further if websocket upgrade
		 * request failed.
		 */
		if (websocket)
			clear_bit(TFW_CONN_B_UNSCHED, &srv_conn->flags);
	}

	return r;

err:
	__kfree_skb(skb);
	return r;
}

/**
 * TLS can send us list of decrypted skbs, it doesn't care about the list any
 * more. Meantime, HTTP uses it's own skb lists, so here we process the list
 * and pretend that we have each skb separately.
 *
 * We responsible for freeing all consumed skbs, including the skb which
 * returned an error code on. The rest of skbs are freed by us.
 */
int
tfw_http_msg_process(TfwConn *conn, struct sk_buff *skb,
		     struct sk_buff **next)
{
	TfwStream *stream = &conn->stream;

	WARN_ON_ONCE(TFW_CONN_TLS(conn) && tfw_tls_context(conn)->alpn_chosen
		     && tfw_tls_context(conn)->alpn_chosen->id
			== TTLS_ALPN_ID_HTTP2
		     && TFW_FSM_TYPE(conn->proto.type) != TFW_FSM_H2);

	if (TFW_FSM_TYPE(conn->proto.type) == TFW_FSM_H2)
		return tfw_h2_frame_process(conn, skb, next);
	return tfw_http_msg_process_generic(conn, stream, skb, next);
}

/**
 * Send monitoring request to backend server to check its state (alive or
 * suspended) in the sense of HTTP accessibility.
 */
void
tfw_http_hm_srv_send(TfwServer *srv, char *data, unsigned long len)
{
	TfwMsgIter it;
	TfwHttpReq *req;
	TfwHttpMsg *hmreq;
	TfwSrvConn *srv_conn;
	TfwStr msg = {
		.data = data,
		.len = len,
	};
	LIST_HEAD(equeue);
	TfwHttpActionResult res;
	int r;

	if (!(req = tfw_http_msg_alloc_req_light()))
		return;
	hmreq = (TfwHttpMsg *)req;
	if (tfw_http_msg_setup(hmreq, &it, msg.len, 0))
		goto cleanup;
	if (tfw_msg_write(&it, &msg))
		goto cleanup;

	__set_bit(TFW_HTTP_B_HMONITOR, req->flags);
	req->jrxtstamp = jiffies;

	/*
	 * Vhost and location store policies definitions that can be
	 * required on various stages of request-response processing.
	 * E.g. response to HM request still needs to be processed by frang,
	 * and vhost keeps the frang configuration.
	 *
	 * The request is created using lightweight function, req->uri_path
	 * is not set, thus default location is used.
	 *
	 * TBD: it's more natural to configure HM not in server group section,
	 * but in vhost: instead of table lookups target vhost could be chosen
	 * directly.
	 */
	if (unlikely(r = tfw_http_tbl_action((TfwMsg *)req, &res))) {
		T_WARN_ADDR("Unable to assign vhost for health monitoring "
			    "request of backend server", &srv->addr,
			    TFW_WITH_PORT);
		goto cleanup;
	}
	if (res.type == TFW_HTTP_RES_REDIR) {
		goto cleanup;
	} else if (res.type == TFW_HTTP_RES_VHOST) {
		req->vhost = res.vhost;
	} else {
		BUG();
	}

	if (likely(req->vhost))
		req->location = req->vhost->loc_dflt;

	srv_conn = srv->sg->sched->sched_srv_conn((TfwMsg *)req, srv);
	if (!srv_conn) {
		T_WARN_ADDR("Unable to find connection for health monitoring "
			    "of backend server", &srv->addr, TFW_WITH_PORT);
		goto cleanup;
	}

	tfw_http_req_fwd(srv_conn, req, &equeue, false);
	tfw_http_req_zap_error(&equeue);

	/*
	 * Paired with tfw_srv_conn_get_if_live() via sched_srv_conn callback which
	 * increments the reference counter.
	 */
	tfw_srv_conn_put(srv_conn);

	return;

cleanup:
	tfw_http_msg_free(hmreq);
}

/**
 * Calculate the key of an HTTP request by hashing URI and Host header values.
 */
unsigned long
tfw_http_req_key_calc(TfwHttpReq *req)
{
	if (req->hash)
		return req->hash;

	req->hash = tfw_hash_str(&req->uri_path);

	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags))
		return req->hash;

	if (!TFW_STR_EMPTY(&req->host))
		req->hash ^= tfw_hash_str(&req->host);

	return req->hash;
}

static TfwConnHooks http_conn_hooks = {
	.conn_init	= tfw_http_conn_init,
	.conn_repair	= tfw_http_conn_repair,
	.conn_close	= tfw_http_conn_close,
	.conn_abort	= tfw_http_conn_abort,
	.conn_drop	= tfw_http_conn_drop,
	.conn_release	= tfw_http_conn_release,
	.conn_send	= tfw_http_conn_send,
};

static int
tfw_http_start(void)
{
	TfwVhost *dflt_vh = tfw_vhost_lookup_default();
	bool misconfiguration;
	u64 storage_size = http_get_tf_storage_size();

	if (WARN_ON_ONCE(!dflt_vh))
		return -1;

        misconfiguration = (tfw_blk_flags & TFW_BLK_ATT_REPLY)
                           && dflt_vh->frang_gconf->ip_block;
	tfw_vhost_put(dflt_vh);

	if (misconfiguration) {
		T_WARN_NL("Directive 'block action' can't be set to"
			  " 'attack reply' if 'ip_block' from 'frang_limits'"
			  " group is 'on'. This is misconfiguration, look in"
			  " the wiki).\n");
		return -1;
	}

	if (storage_size && !tfh_init_filter(storage_size))
		return -ENOMEM;

	return 0;
}

static void
tfw_http_stop(void)
{
	tfh_close_filter();
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

static int
tfw_cfgop_define_block_action(const char *action, unsigned short mask,
			      unsigned short *flags)
{
	if (!strcasecmp(action, "reply")) {
		*flags |= mask;
	} else if (!strcasecmp(action, "drop")) {
		*flags &= ~mask;
	} else {
		T_ERR_NL("Unsupported argument: '%s'\n", action);
		return -EINVAL;
	}
	return 0;
}

static int
tfw_cfgop_define_block_nolog(TfwCfgEntry *ce, unsigned short mask,
			     unsigned short *flags)
{
	if (ce->val_n == 3) {
		if (!strcasecmp(ce->vals[2], "nolog"))
			*flags |= mask;
		else {
			T_ERR_NL("Unsupported argument: '%s'\n", ce->vals[2]);
			return -EINVAL;
		}
	} else {
		*flags &= ~mask;
	}
	return 0;
}

static int
tfw_cfgop_block_action(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->val_n < 2 || ce->val_n > 3) {
		T_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (!strcasecmp(ce->vals[0], "error")) {
		if (tfw_cfgop_define_block_action(ce->vals[1],
						  TFW_BLK_ERR_REPLY,
						  &tfw_blk_flags) ||
		    tfw_cfgop_define_block_nolog(ce,
						 TFW_BLK_ERR_NOLOG,
						 &tfw_blk_flags))
			return -EINVAL;
	} else if (!strcasecmp(ce->vals[0], "attack")) {
		if (tfw_cfgop_define_block_action(ce->vals[1],
						  TFW_BLK_ATT_REPLY,
						  &tfw_blk_flags) ||
		    tfw_cfgop_define_block_nolog(ce,
						 TFW_BLK_ATT_NOLOG,
						 &tfw_blk_flags))
			return -EINVAL;
	} else {
		T_ERR_NL("Unsupported argument: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_cfgop_cleanup_block_action(TfwCfgSpec *cs)
{
	tfw_blk_flags = TFW_CFG_BLK_DEF;
}

/* Macros specific to *_set_body() functions. */
#define __TFW_STR_SET_BODY()						\
	msg->len += l_size - clen_str->len + b_size - body_str->len;	\
	body_str->data = new_body;					\
	body_str->len = b_size;						\
	clen_str->data = new_length;					\
	clen_str->len = l_size;

static void
tfw_http_set_body(resp_code_t code, char *new_length, size_t l_size,
		  char *new_body, size_t b_size)
{
	unsigned long prev_len;
	TfwStr *msg = &http_predef_resps[code];
	TfwStr *clen_str = TFW_STR_CLEN_CH(msg);
	TfwStr *body_str = TFW_STR_BODY_CH(msg);
	void *prev_body_ptr = body_str->data;
	void *prev_clen_ptr = NULL;

	if (prev_body_ptr) {
		prev_clen_ptr = clen_str->data;
		prev_len = clen_str->len + body_str->len;
	}

	__TFW_STR_SET_BODY();

	if (!prev_body_ptr)
		return;

	BUG_ON(!prev_clen_ptr);
	if (prev_body_ptr != __TFW_STR_CH(&http_4xx_resp_body, 1)->data &&
	    prev_body_ptr != __TFW_STR_CH(&http_5xx_resp_body, 1)->data)
	{
		free_pages((unsigned long)prev_clen_ptr, get_order(prev_len));
	}
}

static int
tfw_http_set_common_body(int status_code, char *new_length, size_t l_size,
			 char *new_body, size_t b_size)
{
	TfwStr *msg;
	resp_code_t i, begin, end;
	TfwStr *clen_str;
	TfwStr *body_str;
	unsigned long prev_len;
	void *prev_clen_ptr = NULL;
	void *prev_body_ptr = NULL;

	switch(status_code) {
	case HTTP_STATUS_4XX:
		begin = RESP_4XX_BEGIN;
		end = RESP_4XX_END;
		msg = &http_4xx_resp_body;
		break;
	case HTTP_STATUS_5XX:
		begin = RESP_5XX_BEGIN;
		end = RESP_5XX_END;
		msg = &http_5xx_resp_body;
		break;
	default:
		T_ERR_NL("undefined HTTP status group: [%d]\n", status_code);
		return -EINVAL;
	}

	clen_str = __TFW_STR_CH(msg, 0);
	body_str = __TFW_STR_CH(msg, 1);
	prev_body_ptr = body_str->data;

	if (prev_body_ptr) {
		prev_clen_ptr = clen_str->data;
		prev_len = clen_str->len + body_str->len;
	}

	__TFW_STR_SET_BODY();

	for (i = begin; i < end; ++i) {
		TfwStr *msg = &http_predef_resps[i];
		TfwStr *body_str = TFW_STR_BODY_CH(msg);
		if (!body_str->data ||
		    body_str->data == prev_body_ptr)
		{
			TfwStr *clen_str = TFW_STR_CLEN_CH(msg);
			__TFW_STR_SET_BODY();
		}
	}

	if (!prev_body_ptr) {
		BUG_ON(prev_clen_ptr);
		return 0;
	}

	BUG_ON(!prev_clen_ptr);
	free_pages((unsigned long)prev_clen_ptr, get_order(prev_len));

	return 0;
}

/**
 * Allocate memory to store `Content-length' header and body located in file
 * @filename. Memory is allocated via __get_free_pages(), thus free_pages()
 * must be used on cleanup;
 * @c_len	- Content-Length header value. Meaning that content-length value
 * 		  must be saved at that string.
 * @len		- total length of body data including headers.
 * @body_offset	- the body offset in result;
 */
static char *
__tfw_http_msg_body_dup(const char *filename, TfwStr *c_len, size_t *len,
			size_t *body_offset)
{
	char *body, *b_start, *res = NULL;
	size_t b_sz, t_sz = 0;
	char buff[TFW_ULTOA_BUF_SIZ] = {0};

	if (!(body = tfw_cfg_read_file(filename, &b_sz))) {
		*len = *body_offset = 0;
		return NULL;
	}
	b_sz--;
	if (c_len) {
		c_len->data = buff;
		c_len->len = tfw_ultoa(b_sz, c_len->data, TFW_ULTOA_BUF_SIZ);
		if (unlikely(!c_len->len)) {
			T_ERR_NL("Can't copy file %s: too big\n", filename);
			goto err;
		}

		t_sz += c_len->len;
	}

	t_sz += b_sz;
	b_start = res = (char *)__get_free_pages(GFP_KERNEL, get_order(t_sz));
	if (!res) {
		T_ERR_NL("Can't allocate memory storing file %s as response "
			 "body\n", filename);
		goto err_2;
	}

	if (c_len) {
		tfw_str_to_cstr(c_len, res, t_sz);
		b_start += c_len->len;
	}
	memcpy(b_start, body, b_sz);

	*len = t_sz;
	*body_offset = b_start - res;
err_2:
	if (c_len)
		c_len->len = 0;
err:
	kfree(body);

	return res;
}

/**
 * Copy @filename content to allocated memory. Memory is allocated
 * via __get_free_pages(), thus free_pages() must be used on cleanup.
 * Unlike in @__tfw_http_msg_body_dup() content-length header is not added
 * to the body.
 * @len		- total length of body data including headers.
 */
char *
tfw_http_msg_body_dup(const char *filename, size_t *len)
{
	size_t b_off;

	return __tfw_http_msg_body_dup(filename, NULL, len, &b_off);
}

/**
 * Set message body for predefined response with corresponding code.
 */
static int
tfw_http_config_resp_body(int status_code, const char *filename)
{
	resp_code_t code;
	size_t cl_sz, b_sz, sz, b_off;
	char *cl, *body;
	TfwStr c_len_hdr = { .data = NULL, .len = 0 };

	if (!(cl = __tfw_http_msg_body_dup(filename, &c_len_hdr, &sz, &b_off)))
		return -EINVAL;

	cl_sz = b_off;
	body = cl + b_off;
	b_sz = sz - b_off;

	if (status_code == HTTP_STATUS_4XX || status_code == HTTP_STATUS_5XX) {
		tfw_http_set_common_body(status_code, cl, cl_sz, body, b_sz);
		return 0;
	}

	code = tfw_http_enum_resp_code(status_code);
	if (code == RESP_NUM) {
		T_ERR_NL("Unexpected status code: [%d]\n", status_code);
		return -EINVAL;
	}

	tfw_http_set_body(code, cl, cl_sz, body, b_sz);

	return 0;
}

/**
 * Delete all dynamically allocated message bodies for predefined
 * responses (for the cleanup case during shutdown).
 */
static void
tfw_cfgop_cleanup_resp_body(TfwCfgSpec *cs)
{
	TfwStr *clen_str_4xx = __TFW_STR_CH(&http_4xx_resp_body, 0);
	TfwStr *body_str_4xx = __TFW_STR_CH(&http_4xx_resp_body, 1);
	TfwStr *clen_str_5xx = __TFW_STR_CH(&http_5xx_resp_body, 0);
	TfwStr *body_str_5xx = __TFW_STR_CH(&http_5xx_resp_body, 1);
	resp_code_t i;

	for (i = 0; i < RESP_NUM; ++i) {
		TfwStr *clen_str;
		TfwStr *body_str = TFW_STR_BODY_CH(&http_predef_resps[i]);
		if (!body_str->data)
			continue;

		if (body_str->data == body_str_4xx->data ||
		    body_str->data == body_str_5xx->data)
			continue;

		clen_str = TFW_STR_CLEN_CH(&http_predef_resps[i]);
		free_pages((unsigned long)clen_str->data,
			   get_order(clen_str->len + body_str->len));
		TFW_STR_INIT(body_str);
		clen_str->data = "0";
		clen_str->len = SLEN("0");
	}

	if (body_str_4xx->data) {
		BUG_ON(!clen_str_4xx->data);
		free_pages((unsigned long)clen_str_4xx->data,
			   get_order(clen_str_4xx->len + body_str_4xx->len));
		TFW_STR_INIT(body_str_4xx);
		TFW_STR_INIT(clen_str_4xx);
	}
	if (body_str_5xx->data) {
		BUG_ON(!clen_str_5xx->data);
		free_pages((unsigned long)clen_str_5xx->data,
			   get_order(clen_str_5xx->len + body_str_5xx->len));
		TFW_STR_INIT(body_str_5xx);
		TFW_STR_INIT(clen_str_5xx);
	}
}

int
tfw_cfgop_parse_http_status(const char *status, int *out)
{
	int i;
	for (i = 0; status[i]; ++i) {
		if (isdigit(status[i]))
			continue;

		if (i == 1 && status[i] == '*' && !status[i+1]) {
			/*
			 * For status groups only two-character
			 * sequences with first digit are
			 * acceptable (e.g. 4* or 5*).
			 */
			if (tfw_http_check_wildcard_status(status[0], out))
				return 0;
		}
		return -EINVAL;
	}
	/*
	 * For simple HTTP status value only
	 * three-digit numbers are acceptable
	 * currently.
	 */
	if (i != 3 || kstrtoint(status, 10, out))
		return -EINVAL;

	return tfw_cfg_check_range(*out, HTTP_CODE_MIN, HTTP_CODE_MAX);
}

static int
tfw_cfgop_resp_body(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int code;

	TFW_CFG_CHECK_VAL_N(==, 2, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (tfw_cfgop_parse_http_status(ce->vals[0], &code)) {
		T_ERR_NL("Unable to parse HTTP code value in '%s' directive: "
			 "'%s'\n", cs->name, ce->vals[0]);
		return -EINVAL;
	}

	return tfw_http_config_resp_body(code, ce->vals[1]);
}

static int
tfw_cfgop_whitelist_mark(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int i;
	const char *val;

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	tfw_wl_marks.sz = ce->val_n;
	if (!(tfw_wl_marks.mrks = kmalloc(ce->val_n * sizeof(unsigned int),
					  GFP_KERNEL)))
		return -ENOMEM;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfg_parse_int(val, &tfw_wl_marks.mrks[i])) {
			T_ERR_NL("Unable to parse whitelist mark value: '%s'\n",
				 val);
			kfree(tfw_wl_marks.mrks);
			return -EINVAL;
		}
	}

	sort(tfw_wl_marks.mrks, tfw_wl_marks.sz, sizeof(tfw_wl_marks.mrks[0]),
	     tfw_http_marks_cmp, NULL);

	return 0;
}

static void
tfw_cfgop_cleanup_whitelist_mark(TfwCfgSpec *cs)
{
	kfree(tfw_wl_marks.mrks);
	memset(&tfw_wl_marks, 0, sizeof(tfw_wl_marks));
}

static int
__cfgop_brange_hndl(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned char *a)
{
	unsigned int i;
	const char *val;

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		unsigned long i0 = 0, i1 = 0;

		if (tfw_cfg_parse_intvl(val, &i0, &i1)) {
			T_ERR_NL("Cannot parse %s interval: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
		if (i0 > 255 || i1 > 255) {
			T_ERR_NL("Too large interval bounds in %s: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}

		a[i0++] = 1;
		while (i0 <= i1)
			a[i0++] = 1;
	}

	return 0;
}

static int
__cfgop_brange_parse_disallowed(char *str, unsigned char *a)
{
	char *start = str, *end = str;

	do {
		char* val;
		unsigned long i0, i1;

		if (*end != ' ' && *end != '\0')
			continue;

		val = start;
		i0 = 0, i1 = 0;
		*end = '\0';

		if (tfw_cfg_parse_intvl(val, &i0, &i1)) {
			T_ERR_NL("Cannot parse interval: '%s'\n", val);
			return -EINVAL;
		}
		if (i0 > 255 || i1 > 255) {
			T_ERR_NL("Too large interval bounds: '%s'\n", val);
			return -EINVAL;
		}

		a[i0++] = 1;
		while (i0 <= i1)
			a[i0++] = 1;

		start = end + 1;
	} while (*end++ != '\0');

	return 0;
}

#define TFW_HTTP_CFG_CUSTOM_BRANGE(name, disallowed)			\
static int								\
tfw_cfgop_brange_##name(TfwCfgSpec *cs, TfwCfgEntry *ce)		\
{									\
	int r, i;							\
	unsigned char a[256] = {};					\
	unsigned char d[256] = {};					\
	char dd[] = disallowed;					        \
	T_DBG3("custom brange: %s: disallow chars: %s\n",		\
		#name, disallowed);					\
									\
	if ((r = __cfgop_brange_hndl(cs, ce, a)))			\
		return r;						\
	if ((r = __cfgop_brange_parse_disallowed(dd, d)))		\
		return r;						\
	for (i = 0; i < 256; i++)					\
		if (d[i] && a[i]) {					\
			T_ERR_NL("disallowed char: '0x%02x'\n", i);	\
			return -EINVAL;					\
		}							\
	tfw_init_custom_##name(a);					\
									\
	return 0;							\
}									\
									\
static void								\
tfw_cfgop_cleanup_brange_##name(TfwCfgSpec *cs)				\
{									\
	tfw_init_custom_##name(NULL);					\
}

TFW_HTTP_CFG_CUSTOM_BRANGE(uri, "0x00-0x20");
TFW_HTTP_CFG_CUSTOM_BRANGE(token, "0x00-0x20 0x2c 0x3b");
TFW_HTTP_CFG_CUSTOM_BRANGE(qetoken, "0x00-0x08 0x0a-0x1f 0x22 0x5c 0x7f");
TFW_HTTP_CFG_CUSTOM_BRANGE(nctl, "0x00-0x1f");
TFW_HTTP_CFG_CUSTOM_BRANGE(ctext_vchar, "0x00-0x1f");
TFW_HTTP_CFG_CUSTOM_BRANGE(xff, "0x00-0x20 0x2c");
TFW_HTTP_CFG_CUSTOM_BRANGE(cookie, "0x00-0x20 0x3b 0x3d");
TFW_HTTP_CFG_CUSTOM_BRANGE(etag, "0x00-0x20 0x22");

#undef TFW_HTTP_CFG_CUSTOM_BRANGE

static int
tfw_cfgop_max_header_list_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	if (tfw_cfg_check_val_n(ce, 1))
		return -EINVAL;
	if (ce->attr_n) {
		T_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	r = tfw_cfg_parse_uint(ce->vals[0], &max_header_list_size);
	if (unlikely(r)) {
		T_ERR_NL("Unable to parse 'max_header_list_size' value: '%s'\n",
			 ce->vals[0]);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_cfgop_cleanup_max_header_list_size(TfwCfgSpec *cs)
{
	max_header_list_size = 0;
}

static void
tfw_cfgop_cleanup_allow_empty_body_content_type(TfwCfgSpec *cs)
{
	allow_empty_body_content_type = false;
}

static void
tfw_cfgop_cleanup_frame_limit(TfwCfgSpec *cs)
{
	ctrl_frame_rate_mul = 1;
	wnd_update_frame_rate_mul = 1;
}

static TfwCfgSpec tfw_http_specs[] = {
	{
		.name = "block_action",
		.deflt = NULL,
		.handler = tfw_cfgop_block_action,
		.allow_repeat = true,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_block_action,
	},
	{
		.name = "response_body",
		.deflt = NULL,
		.handler = tfw_cfgop_resp_body,
		.allow_repeat = true,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_resp_body,
	},
	{
		.name = "whitelist_mark",
		.deflt = NULL,
		.handler = tfw_cfgop_whitelist_mark,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_whitelist_mark,
	},
	{
		.name = "http_uri_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_uri,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_uri,
	},
	{
		.name = "http_token_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_token,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_token,
	},
	{
		.name = "http_qetoken_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_qetoken,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_qetoken,
	},
	{
		.name = "http_nctl_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_nctl,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_nctl,
	},
	{
		.name = "http_ctext_vchar_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_ctext_vchar,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_ctext_vchar,
	},
	{
		.name = "http_xff_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_xff,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_xff,
	},
	{
		.name = "http_cookie_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_cookie,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_cookie,
	},
	{
		.name = "http_etag_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_etag,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_etag,
	},
	{
		.name = "http_max_header_list_size",
		.deflt = "16384",
		.handler = tfw_cfgop_max_header_list_size,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_max_header_list_size,
	},
	{
		.name = "http_allow_empty_body_content_type",
		.deflt = "false",
		.handler = tfw_cfg_set_bool,
		.dest = &allow_empty_body_content_type,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_allow_empty_body_content_type,
	},
	{
		.name = "tfh",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = http_tf_cfgop_cleanup,
		.dest = tf_hash_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tf_cfgop_begin,
			.finish_hook = http_tf_cfgop_finish
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "ctrl_frame_rate_multiplier",
		.deflt = "1",
		.handler = tfw_cfg_set_int,
		.dest = &ctrl_frame_rate_mul,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 1, 65536 },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
		.cleanup  = tfw_cfgop_cleanup_frame_limit,
	},
	{
		.name = "window_update_frame_rate_multiplier",
		.deflt = "1",
		.handler = tfw_cfg_set_int,
		.dest = &wnd_update_frame_rate_mul,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 1, 65536 },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
		.cleanup  = tfw_cfgop_cleanup_frame_limit,
	},
	{ 0 }
};

TfwMod tfw_http_mod  = {
	.name	= "http",
	.start = tfw_http_start,
	.stop = tfw_http_stop,
	.specs	= tfw_http_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_http_init(void)
{
	tfw_connection_hooks_register(&http_conn_hooks, TFW_FSM_HTTP);

	tfw_mod_register(&tfw_http_mod);

	return 0;
}

void
tfw_http_exit(void)
{
	tfw_mod_unregister(&tfw_http_mod);
	tfw_connection_hooks_unregister(TFW_FSM_HTTP);
}
