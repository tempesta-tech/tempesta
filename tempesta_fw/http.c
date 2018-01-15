/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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

#include "cache.h"
#include "classifier.h"
#include "client.h"
#include "hash.h"
#include "http_msg.h"
#include "http_sess.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "tls.h"
#include "apm.h"

#include "sync_socket.h"

#define RESP_BUF_LEN			128
static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_buf);
int ghprio; /* GFSM hook priority. */

unsigned short tfw_blk_flags = TFW_BLK_ERR_REPLY;

#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"

#define S_200			"HTTP/1.1 200 OK"
#define S_302			"HTTP/1.1 302 Found"
#define S_304			"HTTP/1.1 304 Not Modified"
#define S_403			"HTTP/1.1 403 Forbidden"
#define S_404			"HTTP/1.1 404 Not Found"
#define S_412			"HTTP/1.1 412 Precondition Failed"
#define S_500			"HTTP/1.1 500 Internal Server Error"
#define S_502			"HTTP/1.1 502 Bad Gateway"
#define S_504			"HTTP/1.1 504 Gateway Timeout"

#define S_F_HOST		"Host: "
#define S_F_DATE		"Date: "
#define S_F_CONTENT_LENGTH	"Content-Length: "
#define S_F_LOCATION		"Location: "
#define S_F_CONNECTION		"Connection: "
#define S_F_ETAG		"ETag: "

#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"
#define S_V_CONN_CLOSE		"close"
#define S_V_CONN_KA		"keep-alive"

#define S_H_CONN_KA		S_F_CONNECTION S_V_CONN_KA S_CRLFCRLF
#define S_H_CONN_CLOSE		S_F_CONNECTION S_V_CONN_CLOSE S_CRLFCRLF

#define S_200_PART_01		S_200 S_CRLF S_F_DATE
#define S_200_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_403_PART_01		S_403 S_CRLF S_F_DATE
#define S_403_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_404_PART_01		S_404 S_CRLF S_F_DATE
#define S_404_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_412_PART_01		S_412 S_CRLF S_F_DATE
#define S_412_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_500_PART_01		S_500 S_CRLF S_F_DATE
#define S_500_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_502_PART_01		S_502 S_CRLF S_F_DATE
#define S_502_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_504_PART_01		S_504 S_CRLF S_F_DATE
#define S_504_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF

/*
 * Array with predefined response data
 */
static TfwStr http_predef_resps[RESP_NUM] = {
	[RESP_200] = {
		.ptr = (TfwStr []){
			{ .ptr = S_200_PART_01, .len = SLEN(S_200_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_200_PART_02, .len = SLEN(S_200_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_200_PART_01 S_V_DATE S_200_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	},
	[RESP_403] = {
		.ptr = (TfwStr []){
			{ .ptr = S_403_PART_01, .len = SLEN(S_403_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_403_PART_02, .len = SLEN(S_403_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_403_PART_01 S_V_DATE S_403_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	},
	[RESP_404] = {
		.ptr = (TfwStr []){
			{ .ptr = S_404_PART_01, .len = SLEN(S_404_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_404_PART_02, .len = SLEN(S_404_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_404_PART_01 S_V_DATE S_404_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	},
	[RESP_412] = {
		.ptr = (TfwStr []){
			{ .ptr = S_412_PART_01, .len = SLEN(S_412_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_412_PART_02, .len = SLEN(S_412_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_412_PART_01 S_V_DATE S_412_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	},
	[RESP_500] = {
		.ptr = (TfwStr []){
			{ .ptr = S_500_PART_01, .len = SLEN(S_500_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_500_PART_02, .len = SLEN(S_500_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_500_PART_01 S_V_DATE S_500_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	},
	[RESP_502] = {
		.ptr = (TfwStr []){
			{ .ptr = S_502_PART_01, .len = SLEN(S_502_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_502_PART_02, .len = SLEN(S_502_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_502_PART_01 S_V_DATE S_502_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	},
	[RESP_504] = {
		.ptr = (TfwStr []){
			{ .ptr = S_504_PART_01, .len = SLEN(S_504_PART_01) },
			{ .ptr = NULL, .len = SLEN(S_V_DATE) },
			{ .ptr = S_504_PART_02, .len = SLEN(S_504_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
			{ .ptr = NULL, .len = 0 },
		},
		.len = SLEN(S_504_PART_01 S_V_DATE S_504_PART_02 S_CRLF),
		.flags = 5 << TFW_STR_CN_SHIFT
	}
};

/*
 * Chunks for various message parts in @http_predef_resps array
 * have predefined positions:
 * 1: Start line,
 * 2: Date,
 * 3: Content-Length header,
 * 4: CRLF,
 * 5: Message body.
 * Some position-dependent macros specific to @http_predef_resps
 * are defined below.
 */
#define TFW_STR_START_CH(msg)	__TFW_STR_CH(msg, 0)
#define TFW_STR_DATE_CH(msg)	__TFW_STR_CH(msg, 1)
#define TFW_STR_CLEN_CH(msg)	__TFW_STR_CH(msg, 2)
#define TFW_STR_CRLF_CH(msg)	__TFW_STR_CH(msg, 3)
#define TFW_STR_BODY_CH(msg)	__TFW_STR_CH(msg, 4)

/*
 * Two static TfwStr structures are needed due to have the opportunity
 * to set separately one page body, e.g. for 500 answer, and another
 * page body - for the remaining 5xx answers.
 */
static TfwStr http_4xx_resp_body = {
	.ptr = (TfwStr []){
		{ .ptr = NULL, .len = 0 },
		{ .ptr = NULL, .len = 0 },
	},
	.len = 0,
};
static TfwStr http_5xx_resp_body = {
	.ptr = (TfwStr []){
		{ .ptr = NULL, .len = 0 },
		{ .ptr = NULL, .len = 0 },
	},
	.len = 0,
};

/*
 * Prepare current date in the format required for HTTP "Date:"
 * header field. See RFC 2616 section 3.3.
 */
static void
tfw_http_prep_date_from(char *buf, time_t date)
{
	struct tm tm;
	char *ptr = buf;

	static const char * const wday[] =
		{ "Sun, ", "Mon, ", "Tue, ",
		  "Wed, ", "Thu, ", "Fri, ", "Sat, " };
	static const char * const month[] =
		{ " Jan ", " Feb ", " Mar ", " Apr ", " May ", " Jun ",
		  " Jul ", " Aug ", " Sep ", " Oct ", " Nov ", " Dec " };

#define PRINT_2DIGIT(p, n)			\
	*p++ = (n <= 9) ? '0' : '0' + n / 10;	\
	*p++ = '0' + n % 10;

	time_to_tm(date, 0, &tm);

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

unsigned long tfw_hash_str(const TfwStr *str);

#define S_302_PART_01	S_302 S_CRLF S_F_DATE
#define S_302_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF S_F_LOCATION
#define S_302_PART_03	S_CRLF S_F_SET_COOKIE
#define S_302_FIXLEN	SLEN(S_302_PART_01 S_V_DATE S_302_PART_02 S_302_PART_03)
#define S_302_KEEP	S_CRLF S_H_CONN_KA
#define S_302_CLOSE	S_CRLF S_H_CONN_CLOSE
/*
 * HTTP 302 response.
 * The response redirects the client to the same URI as the original request,
 * but it includes 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 */
int
tfw_http_prep_302(TfwHttpMsg *resp, TfwHttpReq *req, TfwStr *cookie)
{
	size_t data_len = S_302_FIXLEN;
	int conn_flag = req->flags & __TFW_HTTP_CONN_MASK, ret = 0;
	TfwMsgIter it;
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_302_PART_01, .len = SLEN(S_302_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_302_PART_02, .len = SLEN(S_302_PART_02) }
		},
		.len = SLEN(S_302_PART_01 S_V_DATE S_302_PART_02),
		.flags = 3 << TFW_STR_CN_SHIFT
	};
	static TfwStr part03 = {
		.ptr = S_302_PART_03, .len = SLEN(S_302_PART_03) };
	static TfwStr crlfcrlf = {
		.ptr = S_CRLFCRLF, .len = SLEN(S_CRLFCRLF) };
	static TfwStr crlf_keep = {
		.ptr = S_302_KEEP, .len = SLEN(S_302_KEEP) };
	static TfwStr crlf_close = {
		.ptr = S_302_CLOSE, .len = SLEN(S_302_CLOSE) };
	TfwStr host, *crlf = &crlfcrlf;

	tfw_http_msg_clnthdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
				 TFW_HTTP_HDR_HOST, &host);
	if (TFW_STR_EMPTY(&host))
		host = req->host;

	/* Set "Connection:" header field if needed. */
	if (conn_flag == TFW_HTTP_CONN_CLOSE)
		crlf = &crlf_close;
	else if (conn_flag == TFW_HTTP_CONN_KA)
		crlf = &crlf_keep;

	/* Add variable part of data length to get the total */
	data_len += host.len ? host.len + SLEN(S_HTTP) : 0;
	data_len += req->uri_path.len + cookie->len;
	data_len += crlf->len;

	if (tfw_http_msg_setup(resp, &it, data_len))
		return TFW_BLOCK;

	tfw_http_prep_date(__TFW_STR_CH(&rh, 1)->ptr);
	ret = tfw_http_msg_write(&it, resp, &rh);
	/*
	 * HTTP/1.0 may have no host part, so we create relative URI.
	 * See RFC 1945 9.3 and RFC 7231 7.1.2.
	 */
	if (host.len) {
		static TfwStr proto = { .ptr = S_HTTP, .len = SLEN(S_HTTP) };
		ret |= tfw_http_msg_write(&it, resp, &proto);
		ret |= tfw_http_msg_write(&it, resp, &host);
	}
	ret |= tfw_http_msg_write(&it, resp, &req->uri_path);
	ret |= tfw_http_msg_write(&it, resp, &part03);
	ret |= tfw_http_msg_write(&it, resp, cookie);
	ret |= tfw_http_msg_write(&it, resp, crlf);

	return ret ? TFW_BLOCK : TFW_PASS;
}

#define S_304_PART_01	S_304 S_CRLF
#define S_304_KEEP	S_F_CONNECTION S_V_CONN_KA S_CRLF
#define S_304_CLOSE	S_F_CONNECTION S_V_CONN_CLOSE S_CRLF
/*
 * HTTP 304 response: Not Modified.
 */
int
tfw_http_prep_304(TfwHttpMsg *resp, TfwHttpReq *req, void *msg_it,
		  size_t hdrs_size)
{
	size_t data_len = SLEN(S_304_PART_01);
	TfwMsgIter *it = (TfwMsgIter *)msg_it;
	int conn_flag = req->flags & __TFW_HTTP_CONN_MASK, ret = 0;
	static TfwStr rh = {
		.ptr = S_304_PART_01, .len = SLEN(S_304_PART_01) };
	static TfwStr crlf_keep = {
		.ptr = S_304_KEEP, .len = SLEN(S_304_KEEP) };
	static TfwStr crlf_close = {
		.ptr = S_304_CLOSE, .len = SLEN(S_304_CLOSE) };
	TfwStr *end = NULL;

	/* Set "Connection:" header field if needed. */
	if (conn_flag == TFW_HTTP_CONN_CLOSE)
		end = &crlf_close;
	else if (conn_flag == TFW_HTTP_CONN_KA)
		end = &crlf_keep;

	/* Add variable part of data length to get the total */
	data_len += hdrs_size;
	if (end)
		data_len += end->len;

	if (tfw_http_msg_setup(resp, it, data_len))
		return TFW_BLOCK;

	ret = tfw_http_msg_write(it, resp, &rh);
	if (end)
		ret |= tfw_http_msg_write(it, resp, end);

	TFW_DBG("Send HTTP 304 response\n");

	return ret ? TFW_BLOCK : TFW_PASS;
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
static void
tfw_http_conn_msg_free(TfwHttpMsg *hm)
{
	if (unlikely(!hm))
		return;

	if (hm->conn) {
		/*
		 * Unlink the connection while there is at least one
		 * reference. Use atomic exchange to avoid races with
		 * new messages arriving on the connection.
		 */
		__cmpxchg((unsigned long *)&hm->conn->msg, (unsigned long)hm,
			  0UL, sizeof(long));
		tfw_connection_put(hm->conn);
	}

	tfw_http_msg_free(hm);
}

/*
 * Free request after removing it from seq_queue. This function is
 * needed in cases when response is not sent to client for some reasons.
 */
static inline void
tfw_http_conn_req_clean(TfwHttpReq *req)
{
	spin_lock(&((TfwCliConn *)req->conn)->seq_qlock);
	if (likely(!list_empty(&req->msg.seq_list)))
		list_del_init(&req->msg.seq_list);
	spin_unlock(&((TfwCliConn *)req->conn)->seq_qlock);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
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
	ss_close_sync(req->conn->sk, true);
	tfw_http_conn_req_clean(req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
}

/*
 * Perform operations common to sending an error response to a client.
 * Set current date in the header of an HTTP error response, and set
 * the "Connection:" header field if it was present in the request.
 * If memory allocation error or message setup errors occurred, then
 * client connection should be closed, because response-request
 * pairing for pipelined requests is violated.
 *
 * NOTE: This function expects the predefined order of chunks in @msg:
 * the fourth chunk must be CRLF.
 */
void
tfw_http_send_resp(TfwHttpReq *req, resp_code_t code)
{
	TfwMsgIter it;
	TfwHttpMsg *hmresp;
	TfwStr *date, *crlf, *body;
	int conn_flag = req->flags & __TFW_HTTP_CONN_MASK;
	TfwStr msg = {
		.ptr = (TfwStr []){ {}, {}, {}, {}, {} },
		.len = 0,
		.flags = 5 << TFW_STR_CN_SHIFT
	};

	if (tfw_strcpy_desc(&msg, &http_predef_resps[code]))
		return;

	crlf = TFW_STR_CRLF_CH(&msg);
	if (conn_flag) {
		unsigned long crlf_len = crlf->len;
		if (conn_flag == TFW_HTTP_CONN_KA) {
			crlf->ptr = S_H_CONN_KA;
			crlf->len = SLEN(S_H_CONN_KA);
		} else {
			crlf->ptr = S_H_CONN_CLOSE;
			crlf->len = SLEN(S_H_CONN_CLOSE);
		}
		msg.len += crlf->len - crlf_len;
	}

	if (!(hmresp = tfw_http_msg_alloc_err_resp()))
		goto err_create;
	if (tfw_http_msg_setup(hmresp, &it, msg.len))
		goto err_setup;

	body = TFW_STR_BODY_CH(&msg);
	date = TFW_STR_DATE_CH(&msg);
	date->ptr = *this_cpu_ptr(&g_buf);
	tfw_http_prep_date(date->ptr);
	if (!body->ptr)
		__TFW_STR_CHUNKN_SET(&msg, 4);

	if (tfw_http_msg_write(&it, hmresp, &msg))
		goto err_setup;

	tfw_http_resp_fwd(req, (TfwHttpResp *)hmresp);

	return;
err_setup:
	TFW_DBG2("%s: Response message allocation error: conn=[%p]\n",
		 __func__, req->conn);
	tfw_http_msg_free(hmresp);
err_create:
	tfw_http_resp_build_error(req);
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
 * make a copy of requests's SKBs in SS layer.
 *
 * TODO: Making a copy of each SKB _IS BAD_. See issues #391 and #488.
 *
 */
static inline void
tfw_http_req_init_ss_flags(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	((TfwMsg *)req)->ss_flags |= SS_F_KEEP_SKB;
}

static inline void
tfw_http_resp_init_ss_flags(TfwHttpResp *resp, const TfwHttpReq *req)
{
	if (req->flags & (TFW_HTTP_CONN_CLOSE | TFW_HTTP_SUSPECTED))
		((TfwMsg *)resp)->ss_flags |= SS_F_CONN_CLOSE;
}

/*
 * Check if a request is non-idempotent.
 */
static inline bool
tfw_http_req_is_nip(TfwHttpReq *req)
{
	return (req->flags & TFW_HTTP_NON_IDEMP);
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
 * It's on hold it the request that was sent last was non-idempotent.
 */
static inline bool
tfw_http_conn_on_hold(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));
	return (req_sent && tfw_http_req_is_nip(req_sent));
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
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

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
 * Get the request that is previous to @srv_conn->msg_sent.
 */
static inline TfwMsg *
__tfw_http_conn_msg_sent_prev(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	BUG_ON(!req_sent);
	/*
	 * There is list_is_last() function in the Linux kernel,
	 * but there is no list_is_first(). The condition below
	 * is an implementation of list_is_first().
	 */
	return (srv_conn->fwd_queue.next == &req_sent->fwd_list) ?
		NULL : (TfwMsg *)list_prev_entry(req_sent, fwd_list);
}

/*
 * Remove @req from the server connection's forwarding queue.
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
 * in @equeue. The error code and the reason for an error response are
 * saved as well.
 */
static inline void
__tfw_http_req_error(TfwHttpReq *req, struct list_head *equeue,
		     unsigned short status, const char *reason)
{
	list_add_tail(&req->fwd_list, equeue);
	req->httperr.status = status;
	req->httperr.reason = reason;
}

static inline void
tfw_http_req_error(TfwSrvConn *srv_conn, TfwHttpReq *req,
		   struct list_head *equeue, unsigned short status,
		   const char *reason)
{
	tfw_http_req_delist(srv_conn, req);
	__tfw_http_req_error(req, equeue, status, reason);
}

static inline resp_code_t
tfw_http_enum_resp_code(int status)
{
	switch(status) {
	case 200:
		return RESP_200;
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
	case 504:
		return RESP_504;
	default:
		return RESP_NUM;
	}
}

static inline void
tfw_http_error_resp_switch(TfwHttpReq *req, int status, const char *reason)
{
	resp_code_t code = tfw_http_enum_resp_code(status);
	if (code == RESP_NUM) {
		TFW_WARN("Unexpected response error code: [%d]\n", status);
		tfw_http_send_resp(req, RESP_500);
		return;
	}

	tfw_http_send_resp(req, code);
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
tfw_http_req_zap_error(struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;

	TFW_DBG2("%s: queue is %sempty\n",
		 __func__, list_empty(equeue) ? "" : "NOT ");
	if (list_empty(equeue))
		return;

	list_for_each_entry_safe(req, tmp, equeue, fwd_list) {
		list_del_init(&req->fwd_list);
		tfw_http_error_resp_switch(req, req->httperr.status,
					   req->httperr.reason);
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
}

/*
 * If @req has timed out (has not been forwarded for too long), then
 * move it to the error queue @equeue for sending an error response later.
 */
static inline bool
tfw_http_req_evict_timeout(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *equeue)
{
	unsigned long jqage = jiffies - req->jrxtstamp;

	if (unlikely(time_after(jqage, srv->sg->max_jqage))) {
		TFW_DBG2("%s: Eviction: req=[%p] overdue=[%dms]\n",
			 __func__, req,
			 jiffies_to_msecs(jqage - srv->sg->max_jqage));
		tfw_http_req_error(srv_conn, req, equeue, 504,
				   "request evicted: timed out");
		return true;
	}
	return false;
}

/*
 * If the number of re-forwarding attempts for @req is exceeded, then
 * move it to the error queue @equeue for sending an error response later.
 */
static inline bool
tfw_http_req_evict_retries(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *equeue)
{
	if (unlikely(req->retries++ >= srv->sg->max_refwd)) {
		TFW_DBG2("%s: Eviction: req=[%p] retries=[%d]\n",
			 __func__, req, req->retries);
		tfw_http_req_error(srv_conn, req, equeue, 504,
				   "request evicted: the number"
				   " of retries exceeded");
		return true;
	}
	return false;
}

/*
 * If forwarding of @req to server @srv_conn is not successful, then
 * move it to the error queue @equeue for sending an error response later.
 *
 * TODO: Perhaps, there's a small optimization. Ultimately, the thread
 * ends up in ss_send(). In some cases a connection is still active when
 * it's obtained, but not active by the time the thread is in ss_send().
 * In that case -EBADF is returned, and nothing destructive happens to
 * the request. So, perhaps, instead of sending an error in that case
 * these unlucky requests can be re-sent when the connection is restored.
 */
static inline bool
tfw_http_req_fwd_send(TfwSrvConn *srv_conn, TfwServer *srv,
		      TfwHttpReq *req, struct list_head *equeue)
{
	req->jtxtstamp = jiffies;
	tfw_http_req_init_ss_flags(srv_conn, req);

	if (tfw_connection_send((TfwConn *)srv_conn, (TfwMsg *)req)) {
		TFW_DBG2("%s: Forwarding error: conn=[%p] req=[%p]\n",
			 __func__, srv_conn, req);
		tfw_http_req_error(srv_conn, req, equeue, 500,
				   "request dropped: forwarding error");
		return false;
	}
	return true;
}

/*
 * Forward one request @req to server connection @srv_conn.
 * Return false if forwarding must be stopped, or true otherwise.
 */
static inline bool
tfw_http_req_fwd_single(TfwSrvConn *srv_conn, TfwServer *srv,
			TfwHttpReq *req, struct list_head *equeue)
{
	if (tfw_http_req_evict_timeout(srv_conn, srv, req, equeue))
		return false;
	if (!tfw_http_req_fwd_send(srv_conn, srv, req, equeue))
		return false;
	srv_conn->msg_sent = (TfwMsg *)req;
	TFW_INC_STAT_BH(clnt.msgs_forwarded);
	return true;
}

/*
 * Forward unsent requests in server connection @srv_conn. The requests
 * are forwarded until a non-idempotent request is found in the queue.
 * It's assumed that the forwarding queue in @srv_conn is locked and
 * NOT drained.
 */
static void
tfw_http_conn_fwd_unsent(TfwSrvConn *srv_conn, struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(tfw_http_conn_drained(srv_conn));

	req = srv_conn->msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->msg_sent, fwd_list)
	    : list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwd_queue, fwd_list) {
		if (!tfw_http_req_fwd_single(srv_conn, srv, req, equeue))
			continue;
		/* Stop forwarding if the request is non-idempotent. */
		if (tfw_http_req_is_nip(req))
			break;
		/* See if the idempotent request was non-idempotent. */
		tfw_http_req_nip_delist(srv_conn, req);
	}
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
 * pipelining. See RFC 7230 6.3.2.
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
static void
tfw_http_req_fwd(TfwSrvConn *srv_conn,
		 TfwHttpReq *req, struct list_head *equeue)
{
	TFW_DBG2("%s: srv_conn=[%p], req=[%p]\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock(&srv_conn->fwd_qlock);
	list_add_tail(&req->fwd_list, &srv_conn->fwd_queue);
	srv_conn->qsize++;
	if (tfw_http_req_is_nip(req))
		tfw_http_req_nip_enlist(srv_conn, req);
	if (tfw_http_conn_on_hold(srv_conn)) {
		spin_unlock(&srv_conn->fwd_qlock);
		return;
	}
	tfw_http_conn_fwd_unsent(srv_conn, equeue);
	spin_unlock(&srv_conn->fwd_qlock);
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
 * that's @srv_conn->msg_sent.
 *
 * Note: @srv_conn->msg_sent may change in result.
 */
static inline void
tfw_http_conn_treatnip(TfwSrvConn *srv_conn, struct list_head *equeue)
{
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	if (tfw_http_conn_on_hold(srv_conn)
	    && likely(!(srv->sg->flags & TFW_SRV_RETRY_NIP)))
	{
		BUG_ON(list_empty(&req_sent->nip_list));
		srv_conn->msg_sent = __tfw_http_conn_msg_sent_prev(srv_conn);
		tfw_http_req_error(srv_conn, req_sent, equeue, 504,
				   "request dropped: non-idempotent requests"
				   " are not re-forwarded or re-scheduled");
	}
}

/*
 * Re-forward requests in a server connection. Requests that exceed
 * the set limits are evicted.
 */
static TfwMsg *
tfw_http_conn_resend(TfwSrvConn *srv_conn, bool first, struct list_head *equeue)
{
	TfwHttpReq *req, *tmp, *req_resent = NULL;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwd_queue = &srv_conn->fwd_queue;

	TFW_DBG2("%s: conn=[%p] first=[%s]\n",
		 __func__, srv_conn, first ? "true" : "false");
	BUG_ON(!srv_conn->msg_sent);
	BUG_ON(list_empty(&((TfwHttpReq *)srv_conn->msg_sent)->fwd_list));

	req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);
	end = ((TfwHttpReq *)srv_conn->msg_sent)->fwd_list.next;

	/* Similar to list_for_each_entry_safe_from() */
	for (tmp = list_next_entry(req, fwd_list);
	     &req->fwd_list != end;
	     req = tmp, tmp = list_next_entry(tmp, fwd_list))
	{
		if (tfw_http_req_evict_timeout(srv_conn, srv, req, equeue))
			continue;
		if (tfw_http_req_evict_retries(srv_conn, srv, req, equeue))
			continue;
		if (!tfw_http_req_fwd_send(srv_conn, srv, req, equeue))
			continue;
		req_resent = req;
		if (unlikely(first))
			break;
	}

	return (TfwMsg *)req_resent;
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
	BUG_ON(srv_conn->msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	return true;
}

/*
 * Handle the complete re-forwarding of requests in a server connection
 * that is being repaired, after the first request had been re-forwarded.
 * The connection is not scheduled until all requests in it are re-sent.
 */
static void
tfw_http_conn_fwd_repair(TfwSrvConn *srv_conn, struct list_head *equeue)
{
	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(!tfw_srv_conn_restricted(srv_conn));

	if (tfw_srv_conn_reenable_if_done(srv_conn))
		return;
	if (test_bit(TFW_CONN_B_QFORWD, &srv_conn->flags)) {
		if (tfw_http_conn_need_fwd(srv_conn))
			tfw_http_conn_fwd_unsent(srv_conn, equeue);
	} else {
		/*
		 * Resend all previously forwarded requests. After that
		 * @srv_conn->msg_sent will be either NULL or the last
		 * request that was re-sent successfully. If re-sending
		 * of non-idempotent requests is allowed, then that last
		 * request may be non-idempotent. Continue with sending
		 * requests that were never forwarded only if the last
		 * request that was re-sent was NOT non-idempotent.
		 */
		if (srv_conn->msg_sent)
			srv_conn->msg_sent =
				tfw_http_conn_resend(srv_conn, false, equeue);
		set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		if (tfw_http_conn_need_fwd(srv_conn))
			tfw_http_conn_fwd_unsent(srv_conn, equeue);
	}
	tfw_srv_conn_reenable_if_done(srv_conn);
}

/*
 * Snip @fwd_queue (and @nip_queue) and move its contents to @out_queue.
 *
 * This is run under a lock, so spend minimum time under the lock and
 * do it fast while maintaining consistency. First destroy @nip_queue,
 * most often it has just one entry. Then snip @fwd_queue, move it to
 * @out_queue, and zero @qsize and @msg_sent.
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
	srv_conn->msg_sent = NULL;
}

/*
 * Collect requests in a dead server connection's queue that are suited
 * for re-scheduling. Idempotent requests are always rescheduled.
 * Non-idempotent requests may be rescheduled depending on the option
 * in configuration.
 */
static void
tfw_http_conn_collect(TfwSrvConn *srv_conn, struct list_head *sch_queue,
		      struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	/* Treat a non-idempotent request if any. */
	tfw_http_conn_treatnip(srv_conn, equeue);

	/*
	 * The assumption is that the forwarding queue is processed
	 * in one pass. There's no need to maintain the correct value
	 * of @srv_conn->msg_sent in each loop iteration.
	 *
	 * Note: The limit on re-forward attempts is checked against
	 * the maximum value for the current server group. Later the
	 * request is placed in another connection in the same group.
	 * It's essential that all servers in a group have the same
	 * limit. Otherwise, it will be necessary to check requests
	 * for eviction _after_ a new connection is found.
	 */
	/*
	 * Evict requests with depleted number of re-send attempts. Do it
	 * for requests that were sent before. Don't touch unsent requests.
	 */
	if (srv_conn->msg_sent) {
		struct list_head *end =
			((TfwHttpReq *)srv_conn->msg_sent)->fwd_list.next;
		req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

		/* Similar to list_for_each_entry_safe_from() */
		for (tmp = list_next_entry(req, fwd_list);
		     &req->fwd_list != end;
		     req = tmp, tmp = list_next_entry(tmp, fwd_list))
		{
			tfw_http_req_evict_retries(srv_conn, srv, req, equeue);
		}
	}

	/*
	 * Move the remaining requests to @sch_queue. These requests
	 * will be re-scheduled to other servers and/or connections.
	 */
	tfw_http_conn_snip_fwd_queue(srv_conn, sch_queue);
}

/*
 * Re-schedule requests collected from a dead server connection's
 * queue to a live server connection.
 *
 * Note: re-scheduled requests are put at the tail of a new server's
 * connection queue, and NOT according to their original timestamps.
 * That's the intended behaviour. These requests are unlucky already.
 * They were delayed by waiting in their original server connections,
 * and then by the time spent on multiple attempts to reconnect. Now
 * they have much greater chance to be evicted when it's their turn
 * to be forwarded. The main effort is put into servicing requests
 * that are on time. Unlucky requests are just given another chance
 * with minimal effort.
 */
static void
tfw_http_conn_resched(struct list_head *sch_queue, struct list_head *equeue)
{
	TfwSrvConn *sch_conn;
	TfwHttpReq *req, *tmp;

	/*
	 * Process the complete queue and re-schedule all requests
	 * to other servers/connections.
	 */
	list_for_each_entry_safe(req, tmp, sch_queue, fwd_list) {
		if (!(sch_conn = tfw_sched_get_srv_conn((TfwMsg *)req))) {
			TFW_DBG("Unable to find a backend server\n");
			__tfw_http_req_error(req, equeue, 502,
					     "request dropped: unable to find"
					     " an available back end server");
			continue;
		}
		tfw_http_req_fwd(sch_conn, req, equeue);
		tfw_srv_conn_put(sch_conn);
	}
}

/*
 * Process complete forwarding queue and evict requests that timed out.
 *
 * - First, process unanswered requests that were forwarded to the server,
 *   NOT including the request that was sent last.
 * - Secondly, process that request that was sent last, and then reassign
 *   @srv_conn->msg_sent in case it is evicted.
 * - Finally, process the rest of the queue. Those are the requests that
 *   were never forwarded yet.
 */
static inline void
tfw_http_conn_evict_timeout(TfwSrvConn *srv_conn, struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	if (srv_conn->msg_sent) {
		TfwMsg *msg_sent_prev;
		struct list_head *end =
			&((TfwHttpReq *)srv_conn->msg_sent)->fwd_list;
		req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

		/* Similar to list_for_each_entry_safe_from() */
		for (tmp = list_next_entry(req, fwd_list);
		     &req->fwd_list != end;
		     req = tmp, tmp = list_next_entry(tmp, fwd_list))
		{
			tfw_http_req_evict_timeout(srv_conn, srv, req, equeue);
		}
		/*
		 * Process the request that was forwarded last.
		 * @req is now the same as @srv_conn->msg_sent.
		 */
		msg_sent_prev = __tfw_http_conn_msg_sent_prev(srv_conn);
		if (tfw_http_req_evict_timeout(srv_conn, srv, req, equeue))
			srv_conn->msg_sent = msg_sent_prev;
	}

	/* Process the rest of the forwarding queue. */
	req = srv_conn->msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->msg_sent, fwd_list)
	    : list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwd_queue, fwd_list)
		tfw_http_req_evict_timeout(srv_conn, srv, req, equeue);
}

static void
tfw_http_conn_release_closed(TfwSrvConn *srv_conn, bool resched)
{
	LIST_HEAD(equeue);
	LIST_HEAD(sch_queue);

	tfw_http_conn_evict_timeout(srv_conn, &equeue);
	if (unlikely(resched))
		tfw_http_conn_collect(srv_conn, &sch_queue, &equeue);
	spin_unlock(&srv_conn->fwd_qlock);

	if (!list_empty(&sch_queue))
		tfw_http_conn_resched(&sch_queue, &equeue);

	tfw_http_req_zap_error(&equeue);
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
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	LIST_HEAD(equeue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock(&srv_conn->fwd_qlock);

	if (list_empty(&srv_conn->fwd_queue)) {
		spin_unlock(&srv_conn->fwd_qlock);
		return;
	}

	/* See if requests need to be rescheduled. */
	if (unlikely(!tfw_srv_conn_live(srv_conn))) {
		bool resched = tfw_srv_conn_need_resched(srv_conn);
		return tfw_http_conn_release_closed(srv_conn, resched);
	}

	/* Treat a non-idempotent request if any. */
	tfw_http_conn_treatnip(srv_conn, &equeue);
	/* Re-send only the first unanswered request. */
	if (srv_conn->msg_sent)
		if (unlikely(!tfw_http_conn_resend(srv_conn, true, &equeue)))
			srv_conn->msg_sent = NULL;
	/* If none re-sent, then send the remaining unsent requests. */
	if (!srv_conn->msg_sent) {
		if (!list_empty(&srv_conn->fwd_queue)) {
			set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
			tfw_http_conn_fwd_unsent(srv_conn, &equeue);
		}
		tfw_srv_conn_reenable_if_done(srv_conn);
	}

	spin_unlock(&srv_conn->fwd_qlock);

	tfw_http_req_zap_error(&equeue);
}

/*
 * Destructor for a request message.
 */
void
tfw_http_req_destruct(void *msg)
{
	TfwHttpReq *req = msg;

	BUG_ON(!list_empty(&req->msg.seq_list));
	BUG_ON(!list_empty(&req->fwd_list));
	BUG_ON(!list_empty(&req->nip_list));

	if (req->sess)
		tfw_http_sess_put(req->sess);
}

/*
 * Allocate a new HTTP message structure and link it with the connection
 * instance. Increment the number of users of the instance. Initialize
 * GFSM for the message.
 */
static TfwMsg *
tfw_http_conn_msg_alloc(TfwConn *conn)
{
	TfwHttpMsg *hm = tfw_http_msg_alloc(TFW_CONN_TYPE(conn));
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_connection_get(conn);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		TFW_INC_STAT_BH(clnt.rx_messages);
	} else {
		TfwHttpReq *req;
		TfwSrvConn *srv_conn = (TfwSrvConn *)conn;

		spin_lock(&srv_conn->fwd_qlock);
		req = list_first_entry_or_null(&srv_conn->fwd_queue,
					       TfwHttpReq, fwd_list);
		spin_unlock(&srv_conn->fwd_qlock);
		if (req && (req->method == TFW_HTTP_METH_HEAD))
			hm->flags |= TFW_HTTP_VOID_BODY;
		TFW_INC_STAT_BH(serv.rx_messages);
	}

	return (TfwMsg *)hm;
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
	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Srv) {
		TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
		if (!list_empty(&srv_conn->fwd_queue)) {
			set_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
			TFW_INC_STAT_BH(serv.conn_restricted);
		}
	}
	tfw_gfsm_state_init(&conn->state, conn, TFW_HTTP_FSM_INIT);
	return 0;
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
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	TfwHttpReq *req, *tmp;
	LIST_HEAD(zap_queue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	if (likely(ss_active())) {
		/*
		 * Server is removed from configuration and won't be available
		 * any more, reschedule it's forward queue.
		 */
		if (unlikely(test_bit(TFW_CONN_B_DEL, &srv_conn->flags)))
			tfw_http_conn_release_closed(srv_conn, true);
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
		if (unlikely(!list_empty_careful(&req->msg.seq_list))) {
			spin_lock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
			if (unlikely(!list_empty(&req->msg.seq_list)))
				list_del_init(&req->msg.seq_list);
			spin_unlock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
		}
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
	}
}

/*
 * Dequeue the request from @seq_queue and free the request
 * and the paired response.
 */
static inline void
__tfw_http_resp_pair_free(TfwHttpReq *req)
{
	list_del_init(&req->msg.seq_list);
	tfw_http_conn_msg_free(req->resp);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

/*
 * Drop client connection's resources.
 *
 * Desintegrate the client connection's @seq_list. Requests that have
 * a paired response can be freed. Move those to @zap_queue for doing
 * that without the lock. Requests without a paired response have not
 * been answered yet. They are held in the lists of server connections
 * until responses come. Don't free those requests.
 *
 * If a response comes after @seq_list is desintegrated, then both the
 * request and the response are dropped at the sight of an empty list.
 *
 * Locking is necessary as @seq_list is constantly probed from server
 * connection threads.
 */
static void
tfw_http_conn_cli_drop(TfwCliConn *cli_conn)
{
	TfwHttpReq *req, *tmp;
	struct list_head *seq_queue = &cli_conn->seq_queue;
	LIST_HEAD(zap_queue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, cli_conn);
	BUG_ON(!(TFW_CONN_TYPE(cli_conn) & Conn_Clnt));

	if (list_empty_careful(seq_queue))
		return;

	/*
	 * Desintegration of the list must be done under the lock.
	 * The list can't be just detached from seq_queue, and then
	 * be desintegrated without the lock. That would open a race
	 * condition with freeing of a request in tfw_http_resp_fwd().
	 */
	spin_lock(&cli_conn->seq_qlock);
	list_for_each_entry_safe(req, tmp, seq_queue, msg.seq_list) {
		if (req->resp)
			list_move_tail(&req->msg.seq_list, &zap_queue);
		else
			list_del_init(&req->msg.seq_list);
	}
	spin_unlock(&cli_conn->seq_qlock);

	list_for_each_entry_safe(req, tmp, &zap_queue, msg.seq_list) {
		BUG_ON(!list_empty_careful(&req->fwd_list));
		BUG_ON(!list_empty_careful(&req->nip_list));
		__tfw_http_resp_pair_free(req);
	}
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
	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		tfw_http_conn_cli_drop((TfwCliConn *)conn);
	} else if (conn->msg) {		/* Conn_Srv */
		if (tfw_http_parse_terminate((TfwHttpMsg *)conn->msg))
			tfw_http_resp_terminate((TfwHttpMsg *)conn->msg);
	}
	tfw_http_conn_msg_free((TfwHttpMsg *)conn->msg);
}

/*
 * Send a message through the connection.
 *
 * Called when the connection is used to send a message through.
 */
static int
tfw_http_conn_send(TfwConn *conn, TfwMsg *msg)
{
	return ss_send(conn->sk, &msg->skb_list, msg->ss_flags);
}

/**
 * Create a sibling for @msg message.
 * Siblings in HTTP are pipelined HTTP messages that share the same SKB.
 */
static TfwHttpMsg *
tfw_http_msg_create_sibling(TfwHttpMsg *hm, struct sk_buff **skb,
			    unsigned int split_offset, int type)
{
	TfwHttpMsg *shm;
	struct sk_buff *nskb;

	TFW_DBG2("Create sibling message: conn %p, skb %p\n", hm->conn, skb);

	/* The sibling message belongs to the same connection. */
	shm = (TfwHttpMsg *)tfw_http_conn_msg_alloc(hm->conn);
	if (unlikely(!shm))
		return NULL;

	/*
	 * The sibling message is set up to start with a new SKB.
	 * The new SKB is split off from the original SKB and has
	 * the first part of the new message. The original SKB is
	 * shrunk to have just data from the original message.
	 */
	nskb = ss_skb_split(*skb, split_offset);
	if (!nskb) {
		tfw_http_conn_msg_free(shm);
		return NULL;
	}
	ss_skb_queue_tail(&shm->msg.skb_list, nskb);
	*skb = nskb;

	return shm;
}

/*
 * Add 'Date:' header field to an HTTP message.
 */
static int
tfw_http_set_hdr_date(TfwHttpMsg *hm)
{
	int r;
	char *s_date = *this_cpu_ptr(&g_buf);

	tfw_http_prep_date_from(s_date, ((TfwHttpResp *)hm)->date);
	r = tfw_http_msg_hdr_xfrm(hm, "Date", sizeof("Date") - 1,
				  s_date, SLEN(S_V_DATE),
				  TFW_HTTP_HDR_RAW, 0);
	if (r)
		TFW_ERR("Unable to add Date: header to msg [%p]\n", hm);
	else
		TFW_DBG2("Added Date: header to msg [%p]\n", hm);
	return r;
}

/**
 * Remove Connection header from HTTP message @msg if @conn_flg is zero,
 * and replace or set a new header value otherwise.
 *
 * SKBs may be shared by several HTTP messages. A shared SKB is not copied
 * but safely modified. Thus, a shared SKB is still owned by one CPU.
 */
static int
tfw_http_set_hdr_connection(TfwHttpMsg *hm, int conn_flg)
{
	if (((hm->flags & __TFW_HTTP_CONN_MASK) == conn_flg)
	    && (!TFW_STR_EMPTY(&hm->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION]))
	    && !(hm->flags & TFW_HTTP_CONN_EXTRA))
		return 0;

	switch (conn_flg) {
	case TFW_HTTP_CONN_CLOSE:
		return TFW_HTTP_MSG_HDR_XFRM(hm, "Connection", "close",
					     TFW_HTTP_HDR_CONNECTION, 0);
	case TFW_HTTP_CONN_KA:
		return TFW_HTTP_MSG_HDR_XFRM(hm, "Connection", "keep-alive",
					     TFW_HTTP_HDR_CONNECTION, 0);
	default:
		return TFW_HTTP_MSG_HDR_DEL(hm, "Connection",
					    TFW_HTTP_HDR_CONNECTION);
	}
}

/**
 * Add/Replace/Remove Keep-Alive header field to/from HTTP message.
 */
static int
tfw_http_set_hdr_keep_alive(TfwHttpMsg *hm, int conn_flg)
{
	int r;

	if ((hm->flags & __TFW_HTTP_CONN_MASK) == conn_flg)
		return 0;

	switch (conn_flg) {
	case TFW_HTTP_CONN_CLOSE:
		r = TFW_HTTP_MSG_HDR_DEL(hm, "Keep-Alive", TFW_HTTP_HDR_KEEP_ALIVE);
		if (unlikely(r && r != -ENOENT)) {
			TFW_WARN("Cannot delete Keep-Alive header (%d)\n", r);
			return r;
		}
		return 0;
	case TFW_HTTP_CONN_KA:
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
		 * as well. TFW_HTTP_CONN_KA flag will force the addition of
		 * "Connection: keep-alive" header to HTTP message.
		 */
		return 0;
	}
}

static int
tfw_http_add_hdr_via(TfwHttpMsg *hm)
{
	int r;
	static const char * const s_http_version[] = {
		[0 ... _TFW_HTTP_VER_COUNT] = NULL,
		[TFW_HTTP_VER_09] = "0.9 ",
		[TFW_HTTP_VER_10] = "1.0 ",
		[TFW_HTTP_VER_11] = "1.1 ",
		[TFW_HTTP_VER_20] = "2.0 ",
	};
	TfwVhost *vhost = tfw_vhost_get_default();
	const TfwStr rh = {
#define S_VIA	"Via: "
		.ptr = (TfwStr []) {
			{ .ptr = S_VIA, .len = SLEN(S_VIA) },
			{ .ptr = (void *)s_http_version[hm->version],
			  .len = 4 },
			{ .ptr = *this_cpu_ptr(&g_buf),
			  .len = vhost->hdr_via_len },
		},
		.len = SLEN(S_VIA) + 4 + vhost->hdr_via_len,
		.eolen = 2,
		.flags = 3 << TFW_STR_CN_SHIFT
#undef S_VIA
	};

	memcpy(__TFW_STR_CH(&rh, 2)->ptr, vhost->hdr_via, vhost->hdr_via_len);

	r = tfw_http_msg_hdr_add(hm, &rh);
	if (r)
		TFW_ERR("Unable to add Via: header to msg [%p]\n", hm);
	else
		TFW_DBG2("Added Via: header to msg [%p]\n", hm);
	return r;
}

static int
tfw_http_add_x_forwarded_for(TfwHttpMsg *hm)
{
	int r;
	char *p, *buf = *this_cpu_ptr(&g_buf);

	p = ss_skb_fmt_src_addr(hm->msg.skb_list.first, buf);

	r = tfw_http_msg_hdr_xfrm(hm, "X-Forwarded-For",
				  sizeof("X-Forwarded-For") - 1, buf, p - buf,
				  TFW_HTTP_HDR_X_FORWARDED_FOR, true);
	if (r)
		TFW_ERR("can't add X-Forwarded-For header for %.*s to msg %p",
			(int)(p - buf), buf, hm);
	else
		TFW_DBG2("added X-Forwarded-For header for %*s\n",
			 (int)(p - buf), buf);
	return r;
}

static int
tfw_http_set_loc_hdrs(TfwHttpMsg *hm, TfwHttpReq *req)
{
	int r;
	size_t i;
	int msg_type = (hm == (TfwHttpMsg *)req) ? TFW_HTTP_MSG_REQ
						 : TFW_HTTP_MSG_RESP;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods((TfwMsg *)req, msg_type);

	for (i = 0; i < h_mods->sz; ++i) {
		TfwHdrModsDesc *d = &h_mods->hdrs[i];
		r = tfw_http_msg_hdr_xfrm_str(hm, d->hdr, d->hid, d->append);
		if (r) {
			TFW_ERR("can't update location-specific header in msg %p\n",
				hm);
			return r;
		}
		TFW_DBG2("updated location-specific header in msg %p\n", hm);
	}

	return 0;
}

/**
 * Adjust the request before proxying it to real server.
 */
static int
tfw_http_adjust_req(TfwHttpReq *req)
{
	int r;
	TfwHttpMsg *hm = (TfwHttpMsg *)req;

	r = tfw_http_add_x_forwarded_for(hm);
	if (r)
		return r;

	r = tfw_http_add_hdr_via(hm);
	if (r)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
	if (r < 0)
		return r;

	r = tfw_http_set_loc_hdrs(hm, req);
	if (r < 0)
		return r;

	return tfw_http_set_hdr_connection(hm, TFW_HTTP_CONN_KA);
}

/**
 * Adjust the response before proxying it to real client.
 */
static int
tfw_http_adjust_resp(TfwHttpResp *resp, TfwHttpReq *req)
{
	int r, conn_flg = req->flags & __TFW_HTTP_CONN_MASK;
	TfwHttpMsg *hm = (TfwHttpMsg *)resp;

	r = tfw_http_sess_resp_process(resp, req);
	if (r < 0)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
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

	r = tfw_http_set_loc_hdrs(hm, req);
	if (r < 0)
		return r;

	if (resp->flags & TFW_HTTP_RESP_STALE) {
#define S_WARN_110 "Warning: 110 - Response is stale"
		/* TODO: ajust for #215 */
		TfwStr wh = {
			.ptr	= S_WARN_110,
			.len	= SLEN(S_WARN_110),
			.eolen	= 2
		};
		r = tfw_http_msg_hdr_add(hm, &wh);
		if (r)
			return r;
#undef S_WARN_110
	}

	if (!(resp->flags & TFW_HTTP_HAS_HDR_DATE)) {
		r =  tfw_http_set_hdr_date(hm);
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
__tfw_http_resp_fwd(TfwCliConn *cli_conn, struct list_head *ret_queue)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, ret_queue, msg.seq_list) {
		BUG_ON(!req->resp);
		tfw_http_resp_init_ss_flags((TfwHttpResp *)req->resp, req);
		if (tfw_cli_conn_send(cli_conn, (TfwMsg *)req->resp)) {
			ss_close_sync(cli_conn->sk, true);
			return;
		}
		__tfw_http_resp_pair_free(req);
		TFW_INC_STAT_BH(serv.msgs_forwarded);
	}
}

/*
 * Pair response @resp with request @req in @seq_queue. Then, starting
 * with the first request in @seq_queue, pick consecutive requests that
 * have a paired response. Move those requests to the list of returned
 * responses @ret_queue. Sequentially send responses from @ret_queue to
 * the client.
 */
void
tfw_http_resp_fwd(TfwHttpReq *req, TfwHttpResp *resp)
{
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
	struct list_head *seq_queue = &cli_conn->seq_queue;
	struct list_head *req_retent = NULL;
	LIST_HEAD(ret_queue);

	TFW_DBG2("%s: req=[%p], resp=[%p]\n", __func__, req, resp);

	/*
	 * If the list is empty, then it's either a bug, or the client
	 * connection had been closed. If it's a bug, then the correct
	 * order of responses to requests may be broken. The connection
	 * with the client must to be closed immediately.
	 *
	 * Doing ss_close_sync() on client connection's socket is safe
	 * as long as @req that holds a reference to the connection is
	 * not freed.
	 */
	spin_lock(&cli_conn->seq_qlock);
	if (unlikely(list_empty(seq_queue))) {
		BUG_ON(!list_empty(&req->msg.seq_list));
		spin_unlock(&cli_conn->seq_qlock);
		TFW_DBG2("%s: The client's request missing: conn=[%p]\n",
			 __func__, cli_conn);
		ss_close_sync(cli_conn->sk, true);
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return;
	}
	BUG_ON(list_empty(&req->msg.seq_list));
	req->resp = (TfwHttpMsg *)resp;
	/* Move consecutive requests with @req->resp to @ret_queue. */
	list_for_each_entry(req, seq_queue, msg.seq_list) {
		if (req->resp == NULL)
			break;
		req_retent = &req->msg.seq_list;
	}
	if (!req_retent) {
		spin_unlock(&cli_conn->seq_qlock);
		return;
	}
	__list_cut_position(&ret_queue, seq_queue, req_retent);

	/*
	 * The function may be called concurrently on different CPUs,
	 * all going for the same client connection. In some threads
	 * a response is paired with a request, but the first response
	 * in the queue is not ready yet, so it can't be sent out. When
	 * there're responses to send, sending must be in correct order
	 * which is controlled by the lock. To allow other threads pair
	 * requests with responses, unlock the seq_queue lock and use
	 * different lock @ret_qlock for sending.
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
	 */
	tfw_cli_conn_get(cli_conn);
	spin_lock(&cli_conn->ret_qlock);
	spin_unlock(&cli_conn->seq_qlock);

	__tfw_http_resp_fwd(cli_conn, &ret_queue);

	spin_unlock(&cli_conn->ret_qlock);
	tfw_cli_conn_put(cli_conn);

	/* Zap request/responses that were not sent due to an error. */
	if (!list_empty(&ret_queue)) {
		TfwHttpReq *tmp;
		list_for_each_entry_safe(req, tmp, &ret_queue, msg.seq_list) {
			TFW_DBG2("%s: Forwarding error: conn=[%p] resp=[%p]\n",
				 __func__, cli_conn, req->resp);
			BUG_ON(!req->resp);
			__tfw_http_resp_pair_free(req);
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
	}
}

/**
 * The request is serviced from cache.
 * Send the response as is and unrefer its data.
 */
static void
tfw_http_req_cache_service(TfwHttpReq *req, TfwHttpResp *resp)
{
	if (tfw_http_adjust_resp(resp, req)) {
		HTTP_SEND_RESP(req, 500, "response dropped: processing error");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		return;
	}
	tfw_http_resp_fwd(req, resp);
	TFW_INC_STAT_BH(clnt.msgs_fromcache);
	return;
}

/**
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 500 or 502 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpReq *req, TfwHttpResp *resp)
{
	int r;
	TfwSrvConn *srv_conn = NULL;
	LIST_HEAD(equeue);

	TFW_DBG2("%s: req = %p, resp = %p\n", __func__, req, resp);

	/*
	 * Sticky cookie module used for HTTP session identification may send
	 * a response to the client when sticky cookie presence is enforced
	 * and the cookie is missing from the request.
	 *
	 * HTTP session may be required for request scheduling, so obtain it
	 * first. However, req->sess still may be NULL if sticky cookies are
	 * not enabled.
	 */
	r = tfw_http_sess_obtain(req);
	if (r < 0)
		goto send_500;
	if (r > 0)	/* Response sent, nothing to do. */
		return;

	if (resp) {
		tfw_http_req_cache_service(req, resp);
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
	if (!(srv_conn = tfw_sched_get_srv_conn((TfwMsg *)req))) {
		TFW_DBG("Unable to find a backend server\n");
		goto send_502;
	}

	if (tfw_http_adjust_req(req))
		goto send_500;

	/* Forward request to the server. */
	tfw_http_req_fwd(srv_conn, req, &equeue);
	tfw_http_req_zap_error(&equeue);
	goto conn_put;

send_502:
	HTTP_SEND_RESP(req, 502, "request dropped: processing error");
	TFW_INC_STAT_BH(clnt.msgs_otherr);
	return;
send_500:
	HTTP_SEND_RESP(req, 500, "request dropped: processing error");
	TFW_INC_STAT_BH(clnt.msgs_otherr);
conn_put:
	tfw_srv_conn_put(srv_conn);
}

static void
tfw_http_req_mark_nip(TfwHttpReq *req)
{
	/* See RFC 7231 4.2.1 */
	static const unsigned int safe_methods =
		(1 << TFW_HTTP_METH_GET) | (1 << TFW_HTTP_METH_HEAD)
		| (1 << TFW_HTTP_METH_OPTIONS) | (1 << TFW_HTTP_METH_PROPFIND)
		| (1 << TFW_HTTP_METH_TRACE);
	TfwLocation *loc = req->location;
	TfwLocation *loc_dflt = req->vhost->loc_dflt;
	TfwLocation *base_loc = (tfw_vhost_get_default())->loc_dflt;

	BUILD_BUG_ON(sizeof(safe_methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	/*
	 * Search in the current location of the current vhost. If there
	 * are no entries there, then search in the default location of
	 * the current vhost. If there are no entries there either, then
	 * search in the default location of the default vhost - that is,
	 * in the global policies.
	 *
	 * TODO #862: req->location must be the full set of options.
	 */
	if (loc && loc->nipdef_sz) {
		if (tfw_nipdef_match(loc, req->method, &req->uri_path))
			goto nip_match;
	} else if (loc_dflt && loc_dflt->nipdef_sz) {
		if (tfw_nipdef_match(loc_dflt, req->method, &req->uri_path))
			goto nip_match;
	} else if ((base_loc != loc_dflt) && base_loc && base_loc->nipdef_sz) {
		if (tfw_nipdef_match(base_loc, req->method, &req->uri_path))
			goto nip_match;
	}

	if (safe_methods & (1 << req->method))
		return;

nip_match:
	TFW_DBG2("non-idempotent: method=[%d] uri=[%.*s]\n",
		 req->method, (int)TFW_STR_CHUNK(&req->uri_path, 0)->len,
		 (char *)TFW_STR_CHUNK(&req->uri_path, 0)->ptr);
	req->flags |= TFW_HTTP_NON_IDEMP;
	return;
}

/*
 * Set the flag if @req is non-idempotent. Add the request to the list
 * of the client connection to preserve the correct order of responses.
 * If the request follows a non-idempotent request in flight, then the
 * preceding request becomes idempotent.
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
		req_prev->flags &= ~TFW_HTTP_NON_IDEMP;
	list_add_tail(&req->msg.seq_list, seq_queue);
	spin_unlock(&cli_conn->seq_qlock);
}

static int
tfw_http_req_set_context(TfwHttpReq *req)
{
	req->vhost = tfw_vhost_match(&req->uri_path);
	req->location = tfw_location_match(req->vhost, &req->uri_path);

	return !req->vhost;
}

static inline void
tfw_http_req_mark_error(TfwHttpReq *req, int status, const char *msg)
{
	TFW_CONN_TYPE(req->conn) |= Conn_Stop;
	req->flags |= TFW_HTTP_SUSPECTED;
	tfw_http_error_resp_switch(req, status, msg);
}

/**
 * Functions define logging and response behaviour during detection of
 * malformed or malicious messages. Mark client connection in special
 * manner to delay its closing until transmission of error response
 * will be finished.
 */
static void
tfw_http_cli_error_resp_and_log(bool reply, bool nolog, TfwHttpReq *req,
				int status, const char *msg)
{
	if (reply) {
		TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
		tfw_connection_unlink_msg(req->conn);
		spin_lock(&cli_conn->seq_qlock);
		list_add_tail(&req->msg.seq_list, &cli_conn->seq_queue);
		spin_unlock(&cli_conn->seq_qlock);
		tfw_http_req_mark_error(req, status, msg);
	}
	else
		tfw_http_conn_req_clean(req);

	if (!nolog)
		TFW_WARN_ADDR(msg, &req->conn->peer->addr);
}

static void
tfw_http_srv_error_resp_and_log(bool reply, bool nolog, TfwHttpReq *req,
				int status, const char *msg)
{
	if (reply)
		tfw_http_req_mark_error(req, status, msg);
	else
		tfw_http_conn_req_clean(req);

	if (!nolog)
		TFW_WARN_ADDR(msg, &req->conn->peer->addr);
}

/**
 * Wrappers for calling tfw_http_cli_error_resp_and_log() and
 * tfw_http_srv_error_resp_and_log() functions in client/server
 * connection contexts depending on configuration settings:
 * sending response error messages and logging.
 *
 * NOTE: tfw_client_drop() and tfw_client_block() must be called
 * only from client connection context, and tfw_srv_client_drop()
 * and tfw_srv_client_block() - only from server connection context.
 */
static inline void
tfw_client_drop(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_cli_error_resp_and_log(tfw_blk_flags & TFW_BLK_ERR_REPLY,
					tfw_blk_flags & TFW_BLK_ERR_NOLOG,
					req, status, msg);
}

static inline void
tfw_client_block(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_cli_error_resp_and_log(tfw_blk_flags & TFW_BLK_ATT_REPLY,
					tfw_blk_flags & TFW_BLK_ATT_NOLOG,
					req, status, msg);
}

static inline void
tfw_srv_client_drop(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_srv_error_resp_and_log(tfw_blk_flags & TFW_BLK_ERR_REPLY,
					tfw_blk_flags & TFW_BLK_ERR_NOLOG,
					req, status, msg);
}

static inline void
tfw_srv_client_block(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_srv_error_resp_and_log(tfw_blk_flags &	TFW_BLK_ATT_REPLY,
					tfw_blk_flags & TFW_BLK_ATT_NOLOG,
					req, status, msg);
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_req_process(TfwConn *conn, struct sk_buff *skb, unsigned int off)
{
	int r = TFW_BLOCK;
	unsigned int data_off = off;
	unsigned int skb_len = skb->len;

	BUG_ON(!conn->msg);
	BUG_ON(data_off >= skb_len);

	TFW_DBG2("Received %u client data bytes on conn=%p msg=%p\n",
		 skb_len - off, conn, conn->msg);

	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
	while (data_off < skb_len) {
		int req_conn_close;
		TfwHttpMsg *hmsib = NULL;
		TfwHttpReq *req = (TfwHttpReq *)conn->msg;
		TfwHttpParser *parser = &req->parser;

		/*
		 * Process/parse data in the SKB.
		 * @off points at the start of data for processing.
		 * @data_off is the current offset of data to process in
		 * the SKB. After processing @data_off points at the end
		 * of latest data chunk. However processing may have
		 * stopped in the middle of the chunk. Adjust it to point
		 * to the right location within the chunk.
		 */
		off = data_off;
		r = ss_skb_process(skb, &data_off, tfw_http_parse_req, req);
		data_off -= parser->to_go;
		req->msg.len += data_off - off;
		TFW_ADD_STAT_BH(data_off - off, clnt.rx_bytes);

		TFW_DBG2("Request parsed: len=%u parsed=%d msg_len=%lu"
			 " ver=%d res=%d\n",
			 skb_len - off, data_off - off, req->msg.len,
			 req->version, r);

		switch (r) {
		default:
			TFW_ERR("Unrecognized HTTP request "
				"parser return code, %d\n", r);
			BUG();
		case TFW_BLOCK:
			TFW_DBG2("Block invalid HTTP request\n");
			TFW_INC_STAT_BH(clnt.msgs_parserr);
			tfw_client_drop(req, 403, "failed to parse request");
			return TFW_BLOCK;
		case TFW_POSTPONE:
			r = tfw_gfsm_move(&conn->state,
					  TFW_HTTP_FSM_REQ_CHUNK, skb, off);
			TFW_DBG3("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
			if (r == TFW_BLOCK) {
				TFW_INC_STAT_BH(clnt.msgs_filtout);
				tfw_client_block(req, 403, "postponed"
					       " request has been"
					       " filtered out");
				return TFW_BLOCK;
			}
			/*
			 * TFW_POSTPONE status means that parsing succeeded
			 * but more data is needed to complete it. Lower layers
			 * just supply data for parsing. They only want to know
			 * if processing of a message should continue or not.
			 */
			return TFW_PASS;
		case TFW_PASS:
			/*
			 * The request is fully parsed,
			 * fall through and process it.
			 */
			BUG_ON(!(req->flags & TFW_HTTP_CHUNKED)
			       && (req->content_length != req->body.len));
		}

		r = tfw_gfsm_move(&conn->state,
				  TFW_HTTP_FSM_REQ_MSG, skb, off);
		TFW_DBG3("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
		/* Don't accept any following requests from the peer. */
		if (r == TFW_BLOCK) {
			TFW_INC_STAT_BH(clnt.msgs_filtout);
			tfw_client_block(req, 403, "parsed request"
				       " has been filtered out");
			return TFW_BLOCK;
		}

		/*
		 * The time the request was received is used for age
		 * calculations in cache, and for eviction purposes.
		 */
		req->cache_ctl.timestamp = tfw_current_timestamp();
		req->jrxtstamp = jiffies;

		/* Assign the right Vhost for this request. */
		if (tfw_http_req_set_context(req)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			tfw_client_drop(req, 500, "cannot find"
				      "Vhost for request");
			return TFW_BLOCK;
		}

		/*
		 * In HTTP 0.9 the server always closes the connection
		 * after sending the response.
		 *
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
			&& !(req->flags & __TFW_HTTP_CONN_MASK)))
		{
			req->flags |= TFW_HTTP_CONN_CLOSE;
		}

		/*
		 * The request has been successfully parsed and processed.
		 * If the connection will be closed after the response to
		 * the request is sent to the client, then there's no need
		 * to process pipelined requests. Also, the request may be
		 * released when handled in tfw_cache_req_process() below.
		 * So, save the needed request flag for later use as it
		 * may not be accessible later through @req->flags.
		 * If the connection must be closed, it also should be marked
		 * with @Conn_Stop flag - to left it alive for sending responses
		 * and, at the same time, to stop passing data for processing
		 * from the lower layer.
		 */
		if((req_conn_close = req->flags & TFW_HTTP_CONN_CLOSE))
			TFW_CONN_TYPE(req->conn) |= Conn_Stop;

		if (!req_conn_close && (data_off < skb_len)) {
			/*
			 * Pipelined requests: create a new sibling message.
			 * @skb is replaced with pointer to a new SKB.
			 */
			hmsib = tfw_http_msg_create_sibling((TfwHttpMsg *)req,
							    &skb, data_off,
							    Conn_Clnt);
			if (hmsib == NULL) {
				/*
				 * Not enough memory. Unfortunately, there's
				 * no recourse. The caller expects that data
				 * is processed in full, and can't deal with
				 * partially processed data.
				 */
				TFW_WARN("Not enough memory to create"
					 " a request sibling\n");
				TFW_INC_STAT_BH(clnt.msgs_otherr);
				tfw_client_drop(req, 500, "cannot create"
					      " sibling request");
				return TFW_BLOCK;
			}
		}

		/*
		 * Complete HTTP message has been collected and processed
		 * with success. Mark the message as complete in @conn as
		 * further handling of @conn depends on that. Future SKBs
		 * will be put in a new message.
		 * On an error the function returns from anywhere inside
		 * the loop. @conn->msg holds the reference to the message,
		 * which can be used to release it.
		 */
		tfw_connection_unlink_msg(conn);

		/*
		 * Add the request to the list of the client connection
		 * to preserve the correct order of responses to requests.
		 */
		tfw_http_req_add_seq_queue(req);

		/*
		 * The request should either be stored or released.
		 * Otherwise we lose the reference to it and get a leak.
		 */
		if (tfw_cache_process(req, NULL, tfw_http_req_cache_cb)) {
			HTTP_SEND_RESP(req, 500, "request dropped:"
				       " processing error");
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return TFW_PASS;
		}

		/*
		 * According to RFC 7230 6.3.2, connection with a client
		 * must be dropped after a response is sent to that client,
		 * if the client sends "Connection: close" header field in
		 * the request. Subsequent requests from the client coming
		 * over the same connection are ignored.
		 *
		 * Note: This connection's @conn must not be dereferenced
		 * from this point on.
		 */
		if (req_conn_close)
			break;

		if (hmsib) {
			/*
			 * Switch connection to the new sibling message.
			 * Data processing will continue with the new SKB.
			 */
			data_off = 0;
			skb_len = skb->len;
			conn->msg = (TfwMsg *)hmsib;
		}
	}

	return r;
}

/**
 * This is the second half of tfw_http_resp_process().
 * tfw_http_resp_process() runs in SoftIRQ whereas tfw_http_resp_cache_cb()
 * runs in cache thread that is scheduled at an appropriate TDB node.
 *
 * HTTP requests are usually much smaller than HTTP responses, so it's
 * better to transfer requests to a TDB node to make any adjustments.
 * The other benefit of the scheme is that less work is done in SoftIRQ.
 */
static void
tfw_http_resp_cache_cb(TfwHttpReq *req, TfwHttpResp *resp)
{
	TFW_DBG2("%s: req = %p, resp = %p\n", __func__, req, resp);
	/*
	 * Typically we're at a node far from the node where @resp was
	 * received, so we do an inter-node transfer. However, this is
	 * the final place where the response will be stored. Upcoming
	 * requests will get responded to by the current node without
	 * inter-node data transfers. (see tfw_http_req_cache_cb())
	 */
	if (tfw_http_adjust_resp(resp, req)) {
		HTTP_SEND_RESP(req, 500, "response dropped: processing error");
		TFW_INC_STAT_BH(serv.msgs_otherr);
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		return;
	}
	/*
	 * Responses from cache don't have @resp->conn. Also, for those
	 * responses @req->jtxtstamp is not set and remains zero.
	 *
	 * TODO: Currently APM holds the pure roundtrip time (RTT) from
	 * the time a request is forwarded to the time a response to it
	 * is received and parsed. Perhaps it makes sense to penalize
	 * server connections which get broken too often. What would be
	 * a fast and simple algorithm for that? Keep in mind, that the
	 * value of RTT has an upper boundary in the APM.
	 */
	if (resp->conn)
		tfw_apm_update(((TfwServer *)resp->conn->peer)->apmref,
				resp->jrxtstamp,
				resp->jrxtstamp - req->jtxtstamp);
	tfw_http_resp_fwd(req, resp);
}

/*
 * Request messages that were forwarded to a backend server are added
 * to and kept in @fwd_queue of the connection @conn for that server.
 * If a paired request is not found, then the response is deleted.
 *
 * If a paired client request is missing, then it seems upsream server
 * is misbehaving, so the caller has to drop the server connection.
 *
 * TODO: When a response is received and a paired request is found,
 * pending (unsent) requests in the connection are forwarded to the
 * server right away. In current design, @fwd_queue is locked until
 * after a request is submitted to SS for sending. It shouldn't be
 * necessary to lock @fwd_queue for that. Please see a similar TODO
 * comment to tfw_http_req_fwd(). Also, please see the issue #687.
 */
static TfwHttpReq *
tfw_http_popreq(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmresp->conn;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;
	LIST_HEAD(equeue);

	spin_lock(&srv_conn->fwd_qlock);
	if (unlikely(list_empty(fwd_queue))) {
		BUG_ON(srv_conn->qsize);
		spin_unlock(&srv_conn->fwd_qlock);
		TFW_WARN("Paired request missing, "
			 "HTTP Response Splitting attack?\n");
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return NULL;
	}
	req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);
	if ((TfwMsg *)req == srv_conn->msg_sent)
		srv_conn->msg_sent = NULL;
	tfw_http_req_delist(srv_conn, req);
	tfw_http_conn_nip_adjust(srv_conn);
	/*
	 * Run special processing if the connection is in repair
	 * mode. Otherwise, forward pending requests to the server.
	 *
	 * @hmresp is holding a reference to the server connection
	 * while forwarding is done, so there's no need to take an
	 * additional reference.
	 */
	if (unlikely(tfw_srv_conn_restricted(srv_conn)))
		tfw_http_conn_fwd_repair(srv_conn, &equeue);
	else if (tfw_http_conn_need_fwd(srv_conn))
		tfw_http_conn_fwd_unsent(srv_conn, &equeue);
	spin_unlock(&srv_conn->fwd_qlock);

	tfw_http_req_zap_error(&equeue);

	return req;
}

/*
 * Post-process the response. Pass it to modules registered with GFSM
 * for further processing. Finish the request/response exchange properly
 * in case of an error.
 */
static int
tfw_http_resp_gfsm(TfwHttpMsg *hmresp, struct sk_buff *skb, unsigned int off)
{
	int r;
	TfwHttpReq *req;

	BUG_ON(!hmresp->conn);

	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG, skb, off);
	TFW_DBG3("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
	if (r == TFW_BLOCK)
		goto error;
	/* Proceed with the next GSFM processing */

	r = tfw_gfsm_move(&hmresp->conn->state,
			  TFW_HTTP_FSM_LOCAL_RESP_FILTER, skb, off);
	TFW_DBG3("TFW_HTTP_FSM_LOCAL_RESP_FILTER return code %d\n", r);
	if (r == TFW_PASS)
		return TFW_PASS;
	/* Proceed with the error processing */
error:
	/*
	 * Send an error response to the client, otherwise the pairing
	 * of requests and responses will be broken. If a paired request
	 * is not found, then something is terribly wrong.
	 */
	req = tfw_http_popreq(hmresp);
	if (unlikely(!req)) {
		tfw_http_conn_msg_free(hmresp);
		return TFW_BLOCK;
	}

	tfw_srv_client_block(req, 502, "response blocked: filtered out");
	tfw_http_conn_msg_free(hmresp);
	TFW_INC_STAT_BH(serv.msgs_filtout);
	return r;
}

/*
 * Set up the response @hmresp with data needed down the road,
 * get the paired request, and then pass the response to cache
 * for further processing.
 */
static int
tfw_http_resp_cache(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req;
	TfwGState *state;
	TfwHttpMsg *prev_resp;
	void *prev_state_obj;
	time_t timestamp = tfw_current_timestamp();

	/*
	 * The time the response was received is used in cache
	 * for age calculations, and for APM and Load Balancing.
	 */
	hmresp->cache_ctl.timestamp = timestamp;
	((TfwHttpResp *)hmresp)->jrxtstamp = jiffies;
	/*
	 * If 'Date:' header is missing in the response, then
	 * set the date to the time the response was received.
	 */
	if (!(hmresp->flags & TFW_HTTP_HAS_HDR_DATE))
		((TfwHttpResp *)hmresp)->date = timestamp;
	/*
	 * Cache adjusted and filtered responses only. Responses
	 * are received in the same order as requests, so we can
	 * just pop the first request. If a paired request is not
	 * found, then something is terribly wrong, and pairing
	 * of requests and responses is broken. The response is
	 * deleted, and an error is returned.
	 */
	req = tfw_http_popreq(hmresp);
	if (unlikely(!req)) {
		tfw_http_conn_msg_free(hmresp);
		return -ENOENT;
	}

	/*
	 * This hook isn't in tfw_http_resp_fwd() because it isn't needed
	 * to count responses from a cache.
	 * FSM needs TfwHttpReq to record data. It needs TfwHttpResp as well.
	 * It will be added to the request later in tfw_http_resp_fwd(), but it's
	 * needed now. Save previous (NULL) value for the sake of safety
	 */
	state = &hmresp->conn->state;
	prev_state_obj = state->obj;
	state->obj = req;
	prev_resp = req->resp;
	req->resp = hmresp;
	tfw_gfsm_move(state, TFW_HTTP_FSM_RESP_MSG_FWD, NULL, 0);
	state->obj = prev_state_obj;
	req->resp = prev_resp;

	/*
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @conn as
	 * further handling of @conn depends on that. Future SKBs
	 * will be put in a new message.
	 */
	tfw_connection_unlink_msg(hmresp->conn);
	if (tfw_cache_process(req, (TfwHttpResp *)hmresp,
			      tfw_http_resp_cache_cb))
	{
		HTTP_SEND_RESP(req, 500, "response dropped: processing error");
		tfw_http_conn_msg_free(hmresp);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		/* Proceed with processing of the next response. */
	}

	return 0;
}

/*
 * Finish a response that is terminated by closing the connection.
 */
static void
tfw_http_resp_terminate(TfwHttpMsg *hm)
{
	struct sk_buff *skb = ss_skb_peek_tail(&hm->msg.skb_list);

	BUG_ON(!skb);

	/*
	 * Note that in this case we don't have data to process.
	 * All data has been processed already. The response needs
	 * to go through Tempesta's post-processing, and then be
	 * sent to the client. The full skb->len is used as the
	 * offset to mark this case in the post-processing phase.
	 */
	if (tfw_http_resp_gfsm(hm, skb, skb->len) != TFW_PASS)
		return;
	tfw_http_resp_cache(hm);
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_resp_process(TfwConn *conn, struct sk_buff *skb, unsigned int off)
{
	int r = TFW_BLOCK;
	unsigned int data_off = off;
	unsigned int skb_len = skb->len;
	TfwHttpReq *bad_req;
	TfwHttpMsg *hmresp;
	bool filtout = false;

	BUG_ON(!conn->msg);
	BUG_ON(data_off >= skb_len);

	TFW_DBG2("received %u server data bytes on conn=%p msg=%p\n",
		skb->len - off, conn, conn->msg);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
	while (data_off < skb_len) {
		TfwHttpMsg *hmsib = NULL;
		TfwHttpParser *parser;

		hmresp = (TfwHttpMsg *)conn->msg;
		parser = &hmresp->parser;

		/*
		 * Process/parse data in the SKB.
		 * @off points at the start of data for processing.
		 * @data_off is the current offset of data to process in
		 * the SKB. After processing @data_off points at the end
		 * of latest data chunk. However processing may have
		 * stopped in the middle of the chunk. Adjust it to point
		 * at correct location within the chunk.
		 */
		off = data_off;
		r = ss_skb_process(skb, &data_off, tfw_http_parse_resp, hmresp);
		data_off -= parser->to_go;
		hmresp->msg.len += data_off - off;
		TFW_ADD_STAT_BH(data_off - off, serv.rx_bytes);

		TFW_DBG2("Response parsed: len=%u parsed=%d msg_len=%lu"
			 " ver=%d res=%d\n",
			 skb_len - off, data_off - off, hmresp->msg.len,
			 hmresp->version, r);

		switch (r) {
		default:
			TFW_ERR("Unrecognized HTTP response "
				"parser return code, %d\n", r);
			BUG();
		case TFW_BLOCK:
			/*
			 * The response has not been fully parsed. There's no
			 * choice but report a critical error. The lower layer
			 * will close the connection and release the response
			 * message, and well as all request messages that went
			 * out on this connection and are waiting for paired
			 * response messages.
			 */
			TFW_DBG2("Block invalid HTTP response\n");
			TFW_INC_STAT_BH(serv.msgs_parserr);
			goto bad_msg;
		case TFW_POSTPONE:
			r = tfw_gfsm_move(&conn->state,
					  TFW_HTTP_FSM_RESP_CHUNK, skb, off);
			TFW_DBG3("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
			if (r == TFW_BLOCK) {
				TFW_INC_STAT_BH(serv.msgs_filtout);
				filtout = true;
				goto bad_msg;
			}
			/*
			 * TFW_POSTPONE status means that parsing succeeded
			 * but more data is needed to complete it. Lower layers
			 * just supply data for parsing. They only want to know
			 * if processing of a message should continue or not.
			 */
			return TFW_PASS;
		case TFW_PASS:
			/*
			 * The response is fully parsed,
			 * fall through and process it.
			 */
			if (!(hmresp->flags
			      & (TFW_HTTP_CHUNKED | TFW_HTTP_VOID_BODY))
			    && (hmresp->content_length != hmresp->body.len))
				goto bad_msg;
		}

		/*
		 * Pass the response to GFSM for further processing.
		 * Drop server connection in case of serious error or security
		 * event.
		 */
		r = tfw_http_resp_gfsm(hmresp, skb, off);
		if (unlikely(r < TFW_PASS))
			return TFW_BLOCK;

		/*
		 * If @skb's data has not been processed in full, then
		 * we have pipelined responses. Create a sibling message.
		 * @skb is replaced with a pointer to a new SKB.
		 */
		if (data_off < skb_len) {
			hmsib = tfw_http_msg_create_sibling(hmresp, &skb,
							    data_off,
							    Conn_Srv);
			/*
			 * In case of an error there's no recourse. The
			 * caller expects that data is processed in full,
			 * and can't deal with partially processed data.
			 */
			if (hmsib == NULL) {
				TFW_WARN("Insufficient memory "
					 "to create a response sibling\n");
				TFW_INC_STAT_BH(serv.msgs_otherr);

				/*
				 * Unable to create a sibling message.
				 * Send the parsed response to the client
				 * and close the server connection.
				 */
				tfw_http_resp_cache(hmresp);
				return TFW_BLOCK;
			}
		}

		/*
		 * If a non critical error occured in further GFSM processing,
		 * then the response and the paired request had been handled.
		 * Keep the server connection open for data exchange.
		 */
		if (unlikely(r != TFW_PASS)) {
			r = TFW_PASS;
			goto next_resp;
		}
		/*
		 * Pass the response to cache for further processing.
		 * In the end, the response is sent on to the client.
		 */
		if (tfw_http_resp_cache(hmresp))
			return TFW_BLOCK;
next_resp:
		if (hmsib) {
			/*
			 * Switch the connection to the sibling message.
			 * Data processing will continue with the new SKB.
			 */
			data_off = 0;
			skb_len = skb->len;
			conn->msg = (TfwMsg *)hmsib;
		}
	}

	return r;
bad_msg:
	bad_req = tfw_http_popreq(hmresp);
	if (bad_req) {
		if (filtout)
			tfw_srv_client_block(bad_req, 502,
					     "response blocked:"
					     " filtered out");
		else
			tfw_srv_client_drop(bad_req, 500,
					    "response dropped:"
					    " processing error");
	}
	tfw_http_conn_msg_free(hmresp);
	return r;
}

/**
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off)
{
	TfwConn *c = (TfwConn *)conn;

	if (unlikely(!c->msg)) {
		c->msg = tfw_http_conn_msg_alloc(c);
		if (!c->msg) {
			__kfree_skb(skb);
			return -ENOMEM;
		}
		TFW_DBG2("Link new msg %p with connection %p\n", c->msg, c);
	}

	TFW_DBG2("Add skb %p to message %p\n", skb, c->msg);
	ss_skb_queue_tail(&c->msg->skb_list, skb);

	return (TFW_CONN_TYPE(c) & Conn_Clnt)
		? tfw_http_req_process(c, skb, off)
		: tfw_http_resp_process(c, skb, off);
}

/**
 * Calculate the key of an HTTP request by hashing URI and Host header values.
 */
unsigned long
tfw_http_req_key_calc(TfwHttpReq *req)
{
	TfwStr host;

	if (req->hash)
		return req->hash;

	req->hash = tfw_hash_str(&req->uri_path);

	tfw_http_msg_clnthdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
				 TFW_HTTP_HDR_HOST, &host);
	if (!TFW_STR_EMPTY(&host))
		req->hash ^= tfw_hash_str(&host);

	return req->hash;
}
EXPORT_SYMBOL(tfw_http_req_key_calc);

static TfwConnHooks http_conn_hooks = {
	.conn_init	= tfw_http_conn_init,
	.conn_repair	= tfw_http_conn_repair,
	.conn_drop	= tfw_http_conn_drop,
	.conn_release	= tfw_http_conn_release,
	.conn_send	= tfw_http_conn_send,
};

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
		TFW_ERR_NL("Unsupported argument: '%s'\n", action);
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
			TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[2]);
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
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

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
		TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	return 0;
}

/* Macros specific to *_set_body() functions. */
#define __TFW_STR_SET_BODY()						\
	msg->len += l_size - clen_str->len + b_size - body_str->len;	\
	body_str->ptr = new_body;					\
	body_str->len = b_size;						\
	clen_str->ptr = new_length;					\
	clen_str->len = l_size;

static void
tfw_http_set_body(resp_code_t code, char *new_length, size_t l_size,
		  char *new_body, size_t b_size)
{
	unsigned long prev_len;
	TfwStr *msg = &http_predef_resps[code];
	TfwStr *clen_str = TFW_STR_CLEN_CH(msg);
	TfwStr *body_str = TFW_STR_BODY_CH(msg);
	void *prev_body_ptr = body_str->ptr;
	void *prev_clen_ptr = NULL;

	if (prev_body_ptr) {
		prev_clen_ptr = clen_str->ptr;
		prev_len = clen_str->len + body_str->len;
	}

	__TFW_STR_SET_BODY();

	if (!prev_body_ptr)
		return;

	BUG_ON(!prev_clen_ptr);
	if (prev_body_ptr != __TFW_STR_CH(&http_4xx_resp_body, 1)->ptr &&
	    prev_body_ptr != __TFW_STR_CH(&http_5xx_resp_body, 1)->ptr)
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
		TFW_ERR("undefined HTTP status group: [%d]\n", status_code);
		return -EINVAL;
	}

	clen_str = __TFW_STR_CH(msg, 0);
	body_str = __TFW_STR_CH(msg, 1);
	prev_body_ptr = body_str->ptr;

	if (prev_body_ptr) {
		prev_clen_ptr = clen_str->ptr;
		prev_len = clen_str->len + body_str->len;
	}

	__TFW_STR_SET_BODY();

	for (i = begin; i < end; ++i) {
		TfwStr *msg = &http_predef_resps[i];
		TfwStr *body_str = TFW_STR_BODY_CH(msg);
		if (!body_str->ptr ||
		    body_str->ptr == prev_body_ptr)
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
 * Set message body for predefined response with corresponding code.
 */
static int
tfw_http_config_resp_body(int status_code, const char *src_body, size_t b_size)
{
	resp_code_t code;
	size_t digs_count, l_size;
	char *new_length, *new_body;
	char buff[TFW_ULTOA_BUF_SIZ] = {0};

	if (!(digs_count = tfw_ultoa(b_size, buff, TFW_ULTOA_BUF_SIZ))) {
		TFW_ERR("too small buffer for Content-Length header\n");
		return -E2BIG;
	}

	l_size = 2 * SLEN(S_CRLF) + SLEN(S_F_CONTENT_LENGTH) + digs_count;
	new_length = (char *)__get_free_pages(GFP_KERNEL,
					      get_order(l_size + b_size));
	if (!new_length) {
		TFW_ERR("can't allocate memory for Content-Length"
			"header and body\n");
		return -ENOMEM;
	}
	snprintf(new_length, l_size + 1, "%s%s%s%s",
		 S_CRLF, S_F_CONTENT_LENGTH , buff, S_CRLF);
	new_body = new_length + l_size;
	memcpy(new_body, src_body, b_size);

	if (status_code == HTTP_STATUS_4XX || status_code == HTTP_STATUS_5XX) {
		tfw_http_set_common_body(status_code, new_length,
					 l_size, new_body, b_size);
		return 0;
	}

	code = tfw_http_enum_resp_code(status_code);
	if (code == RESP_NUM) {
		TFW_ERR_NL("Unexpected status code: [%d]\n",
			   status_code);
		return -EINVAL;
	}

	tfw_http_set_body(code, new_length, l_size, new_body, b_size);

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
		if (!body_str->ptr)
			continue;

		if (body_str->ptr == body_str_4xx->ptr ||
		    body_str->ptr == body_str_5xx->ptr)
			continue;

		clen_str = TFW_STR_CLEN_CH(&http_predef_resps[i]);
		free_pages((unsigned long)clen_str->ptr,
			   get_order(clen_str->len + body_str->len));
	}

	if (body_str_4xx->ptr) {
		BUG_ON(!clen_str_4xx->ptr);
		free_pages((unsigned long)clen_str_4xx->ptr,
			   get_order(clen_str_4xx->len + body_str_4xx->len));
	}
	if (body_str_5xx->ptr) {
		BUG_ON(!clen_str_5xx->ptr);
		free_pages((unsigned long)clen_str_5xx->ptr,
			   get_order(clen_str_5xx->len + body_str_5xx->len));
	}
}

static int
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
			if (status[0] == '4') {
				*out = HTTP_STATUS_4XX;
				return 0;
			}
			if (status[0] == '5') {
				*out = HTTP_STATUS_5XX;
				return 0;
			}
		}
		return -EINVAL;
	}
	/*
	 * For simple HTTP status value only
	 * three-digit numbers are acceptable
	 * currently.
	 */
	if (i != 3)
		return -EINVAL;

	return kstrtoint(status, 10, out);
}

static int
tfw_cfgop_resp_body(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	char *body_data;
	size_t body_size;
	int code, ret = 0;

	if (tfw_cfg_check_val_n(ce, 2))
		return -EINVAL;

	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	if (tfw_cfgop_parse_http_status(ce->vals[0], &code))
	{
		TFW_ERR_NL("Unable to parse 'response_body' value: '%s'\n",
			   ce->vals[0]
			   ? ce->vals[0]
			   : "No value specified");
		return -EINVAL;
	}

	body_data = tfw_cfg_read_file(ce->vals[1], &body_size);
	if (!body_data) {
		TFW_ERR_NL("Cannot read file with error response: '%s'\n",
			   ce->vals[1]);
		return -EINVAL;
	}

	ret = tfw_http_config_resp_body(code, body_data, body_size - 1);
	vfree(body_data);

	return ret;
}

static TfwCfgSpec tfw_http_specs[] = {
	{
		.name = "block_action",
		.deflt = NULL,
		.handler = tfw_cfgop_block_action,
		.allow_repeat = true,
		.allow_none = true,
	},
	{
		.name = "response_body",
		.deflt = NULL,
		.handler = tfw_cfgop_resp_body,
		.allow_repeat = true,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_resp_body,
	},
	{ 0 }
};

TfwMod tfw_http_mod  = {
	.name	= "http",
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
	int r;
	/* Make sure @req->httperr doesn't take too much space. */
	BUILD_BUG_ON(FIELD_SIZEOF(TfwHttpMsg, httperr)
		     > FIELD_SIZEOF(TfwHttpMsg, parser));

	r = tfw_gfsm_register_fsm(TFW_FSM_HTTP, tfw_http_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&http_conn_hooks, TFW_FSM_HTTP);

	/* Must be last call - we can't unregister the hook. */
	ghprio = tfw_gfsm_register_hook(TFW_FSM_TLS,
					TFW_GFSM_HOOK_PRIORITY_ANY,
					TFW_TLS_FSM_DATA_READY,
					TFW_FSM_HTTP, TFW_HTTP_FSM_INIT);
	if (ghprio < 0)
		return ghprio;
	tfw_mod_register(&tfw_http_mod);

	return 0;
}

void
tfw_http_exit(void)
{
	tfw_mod_unregister(&tfw_http_mod);
	tfw_gfsm_unregister_hook(TFW_FSM_TLS, ghprio, TFW_TLS_FSM_DATA_READY);
	tfw_connection_hooks_unregister(TFW_FSM_HTTP);
	tfw_gfsm_unregister_fsm(TFW_FSM_HTTP);
}
