/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include "cache.h"
#include "classifier.h"
#include "client.h"
#include "hash.h"
#include "http_msg.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "tls.h"
#include "apm.h"

#include "sync_socket.h"

#define RESP_BUF_LEN			128
static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_buf);
int ghprio; /* GFSM hook priority. */

#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"

#define S_200			"HTTP/1.1 200 OK"
#define S_302			"HTTP/1.1 302 Found"
#define S_403			"HTTP/1.1 403 Forbidden"
#define S_404			"HTTP/1.1 404 Not Found"
#define S_500			"HTTP/1.1 500 Internal Server Error"
#define S_502			"HTTP/1.1 502 Bad Gateway"
#define S_504			"HTTP/1.1 504 Gateway Timeout"

#define S_F_HOST		"Host: "
#define S_F_DATE		"Date: "
#define S_F_CONTENT_LENGTH	"Content-Length: "
#define S_F_LOCATION		"Location: "
#define S_F_CONNECTION		"Connection: "

#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"
#define S_V_CONN_CLOSE		"close"
#define S_V_CONN_KA		"keep-alive"

#define S_H_CONN_KA		S_F_CONNECTION S_V_CONN_KA S_CRLFCRLF
#define S_H_CONN_CLOSE		S_F_CONNECTION S_V_CONN_CLOSE S_CRLFCRLF

/*
 * Prepare current date in the format required for HTTP "Date:"
 * header field. See RFC 2616 section 3.3.
 */
static void
tfw_http_prep_date_from(char *buf, time_t date)
{
	struct tm tm;
	char *ptr = buf;

	static char *wday[] __read_mostly =
		{ "Sun, ", "Mon, ", "Tue, ",
		  "Wed, ", "Thu, ", "Fri, ", "Sat, " };
	static char *month[] __read_mostly =
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
tfw_http_prep_302(TfwHttpMsg *hmresp, TfwHttpReq *req, TfwStr *cookie)
{
	size_t data_len = S_302_FIXLEN;
	int conn_flag = req->flags & __TFW_HTTP_CONN_MASK;
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

	if (tfw_http_msg_setup(hmresp, &it, data_len))
		return TFW_BLOCK;

	tfw_http_prep_date(__TFW_STR_CH(&rh, 1)->ptr);
	tfw_http_msg_write(&it, hmresp, &rh);
	/*
	 * HTTP/1.0 may have no host part, so we create relative URI.
	 * See RFC 1945 9.3 and RFC 7231 7.1.2.
	 */
	if (host.len) {
		static TfwStr proto = { .ptr = S_HTTP, .len = SLEN(S_HTTP) };
		tfw_http_msg_write(&it, hmresp, &proto);
		tfw_http_msg_write(&it, hmresp, &host);
	}
	tfw_http_msg_write(&it, hmresp, &req->uri_path);
	tfw_http_msg_write(&it, hmresp, &part03);
	tfw_http_msg_write(&it, hmresp, cookie);
	tfw_http_msg_write(&it, hmresp, crlf);

	return TFW_PASS;
}

/*
 * Perform operations common to sending an error response to a client.
 * Set current date in the header of an HTTP error response, and set
 * the "Connection:" header field if it was present in the request.
 *
 * NOTE: This function expects that the last chunk of @msg is CRLF.
 */
static int
tfw_http_send_resp(TfwHttpReq *req, TfwStr *msg, const TfwStr *date)
{
	int conn_flag = req->flags & __TFW_HTTP_CONN_MASK;
	TfwStr *crlf = __TFW_STR_CH(msg, TFW_STR_CHUNKN(msg) - 1);
	TfwHttpMsg *hmresp;
	TfwMsgIter it;

	if (conn_flag) {
		unsigned long crlf_len = crlf->len;
		if (conn_flag == TFW_HTTP_CONN_KA) {
			crlf->ptr = S_H_CONN_KA;
			crlf->len = SLEN(S_H_CONN_KA);
		} else {
			crlf->ptr = S_H_CONN_CLOSE;
			crlf->len = SLEN(S_H_CONN_CLOSE);
		}
		msg->len += crlf->len - crlf_len;
	}

	if (!(hmresp = tfw_http_msg_alloc_err_resp()))
		return -ENOMEM;
	if (tfw_http_msg_setup(hmresp, &it, msg->len)) {
		tfw_http_msg_free(hmresp);
		return -ENOMEM;
	}

	tfw_http_prep_date(date->ptr);
	tfw_http_msg_write(&it, hmresp, msg);

	tfw_http_resp_init_ss_flags((TfwHttpResp *)hmresp, req);
	tfw_http_resp_fwd(req, (TfwHttpResp *)hmresp);

	return 0;
}

#define S_200_PART_01	S_200 S_CRLF S_F_DATE
#define S_200_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 200 response: Success.
 */
int
tfw_http_send_200(TfwHttpReq *req)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_200_PART_01, .len = SLEN(S_200_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_200_PART_02, .len = SLEN(S_200_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_200_PART_01 S_V_DATE S_200_PART_02 S_CRLF),
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 200 response to the client\n");

	return tfw_http_send_resp(req, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_403_PART_01	S_403 S_CRLF S_F_DATE
#define S_403_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 403 response: Access is forbidden.
 */
int
tfw_http_send_403(TfwHttpReq *req)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_403_PART_01, .len = SLEN(S_403_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_403_PART_02, .len = SLEN(S_403_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_403_PART_01 S_V_DATE S_403_PART_02 S_CRLF),
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 403 response\n");

	return tfw_http_send_resp(req, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_404_PART_01	S_404 S_CRLF S_F_DATE
#define S_404_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 404 response: Tempesta is unable to find the requested data.
 */
int
tfw_http_send_404(TfwHttpReq *req)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_404_PART_01, .len = SLEN(S_404_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_404_PART_02, .len = SLEN(S_404_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_404_PART_01 S_V_DATE S_404_PART_02 S_CRLF),
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 404 response: %s\n", reason);

	return tfw_http_send_resp(req, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_500_PART_01	S_500 S_CRLF S_F_DATE
#define S_500_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 500 response: there was an internal error while forwarding
 * the request to a server.
 */
static int
tfw_http_send_500(TfwHttpReq *req)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_500_PART_01, .len = SLEN(S_500_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_500_PART_02, .len = SLEN(S_500_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_500_PART_01 S_V_DATE S_500_PART_02 S_CRLF),
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 500 response\n");

	return tfw_http_send_resp(req, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_502_PART_01	S_502 S_CRLF S_F_DATE
#define S_502_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 502 response: Tempesta is unable to forward the request to
 * the designated server.
 */
int
tfw_http_send_502(TfwHttpReq *req)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_502_PART_01, .len = SLEN(S_502_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_502_PART_02, .len = SLEN(S_502_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_502_PART_01 S_V_DATE S_502_PART_02 S_CRLF),
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 502 response\n");

	return tfw_http_send_resp(req, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_504_PART_01	S_504 S_CRLF S_F_DATE
#define S_504_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 504 response: did not receive a timely response from
 * the designated server.
 */
int
tfw_http_send_504(TfwHttpReq *req)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_504_PART_01, .len = SLEN(S_504_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_504_PART_02, .len = SLEN(S_504_PART_02) },
			{ .ptr = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_504_PART_01 S_V_DATE S_504_PART_02 S_CRLF),
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 504 response\n");

	return tfw_http_send_resp(req, &rh, __TFW_STR_CH(&rh, 1));
}

static inline bool
tfw_http_req_is_nonidempotent(TfwHttpReq *req)
{
	return (req->flags & TFW_HTTP_NON_IDEMP);
}

/*
 * Set the request @req in server connection @srv_conn as idempotent.
 * Called only when a request turns idempotent from a non-idempotent.
 */
static inline void
__tfw_http_req_nonidemp_delist(TfwConnection *srv_conn, TfwHttpReq *req)
{
	list_del_init(&req->nip_list);
	if (list_empty(&srv_conn->nip_queue))
		clear_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/*
 * Set the request @req in server connection @srv_conn as non-idempotent.
 */
static inline void
__tfw_http_req_nonidemp_enlist(TfwConnection *srv_conn, TfwHttpReq *req)
{
	BUG_ON(!list_empty(&req->nip_list));
	list_add_tail(&req->nip_list, &srv_conn->nip_queue);
	set_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/*
 * If @req in server connection @srv_conn is non-idempotent, then set
 * it as idempotent.
 */
static inline void
tfw_http_req_nonidemp_delist(TfwConnection *srv_conn, TfwHttpReq *req)
{
	if (!list_empty(&req->nip_list))
		__tfw_http_req_nonidemp_delist(srv_conn, req);
}

/*
 * If a request on the list of non-idempotent requests in server
 * connection @srv_conn had become idempotent, then set it as such.
 */
static inline void
tfw_http_conn_nonidemp_delist(TfwConnection *srv_conn)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, &srv_conn->nip_queue, nip_list)
		if (!tfw_http_req_is_nonidempotent(req)) {
			BUG_ON(list_empty(&req->nip_list));
			__tfw_http_req_nonidemp_delist(srv_conn, req);
		}
}

/*
 * Tell if the server connection's forwarding queue is on hold.
 * It's on hold it the request that was sent last was non-idempotent.
 */
static inline bool
tfw_http_conn_on_hold(TfwConnection *srv_conn)
{
	TfwHttpReq *req = (TfwHttpReq *)srv_conn->msg_sent;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));
	return (req && tfw_http_req_is_nonidempotent(req));
}

/*
 * Tell if the server connection's forwarding queue is drained.
 * It's drained if there're no requests in the queue after the
 * request that was sent last.
 */
static inline bool
tfw_http_conn_drained(TfwConnection *srv_conn)
{
	TfwMsg *msg;
	struct list_head *fwd_queue = &srv_conn->msg_queue;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	if (list_empty(fwd_queue))
		return true;
	if (!srv_conn->msg_sent)
		return false;
	msg = (TfwMsg *)list_last_entry(fwd_queue, TfwHttpReq, fwd_list);
	if (srv_conn->msg_sent == msg)
		return true;
	return false;
}

/*
 * Tell if the server connection's forwarding queue has requests
 * that need to be forwarded.
 */
static inline bool
tfw_http_conn_need_fwd(TfwConnection *srv_conn)
{
	return (!tfw_http_conn_on_hold(srv_conn)
		&& !tfw_http_conn_drained(srv_conn));
}

/*
 * Common actions in case of an error while forwarding requests.
 * Erroneous requests are removed from the forwarding queue and placed
 * in @equeue. The error code for an error response is saved as well.
 */
static inline void
tfw_http_req_move2equeue(TfwConnection *srv_conn, TfwHttpReq *req,
			 struct list_head *equeue, unsigned short status)
{
	tfw_http_req_nonidemp_delist(srv_conn, req);
	list_move_tail(&req->fwd_list, equeue);
	srv_conn->qsize--;
	req->rstatus = status;
}

/*
 * Delete requests that were not forwarded due to an error. Send an
 * error response to a client. The response will be attached to the
 * request and sent to the client in proper seq order.
 */
static void
tfw_http_req_zap_error(struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;

	TFW_DBG2("%s: queue is %sempty\n",
		 __func__, list_empty(err_queue) ? "" : "NOT ");

	list_for_each_entry_safe(req, tmp, equeue, fwd_list) {
		list_del_init(&req->fwd_list);
		if (req->rstatus == 500)
			tfw_http_send_500(req);
		else if (req->rstatus == 504)
			tfw_http_send_504(req);
		else
			BUG();
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
}

/*
 * Forward requests in the server connection @srv_conn. The requests
 * are forwarded until a non-idempotent request is found in the queue.
 * Must be called with a lock on the server connection's @msg_queue.
 */
static void
__tfw_http_req_fwd_stalled(TfwConnection *srv_conn, struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->msg_queue;

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	/*
	 * Process the server connection's queue of pending requests.
	 * The queue is locked against concurrent updates: inserts of
	 * outgoing requests, or closing of the server connection. Do
	 * it as fast as possible by moving failed requests to other
	 * queues that can be processed without the lock.
	 */
	req = srv_conn->msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->msg_sent, fwd_list)
	    : list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwd_queue, fwd_list) {
		unsigned long jtimeout = jiffies - req->jtstamp;
		if (time_after(jtimeout, srv->qjtimeout)) {
			TFW_DBG2("%s: Eviction: req=[%p] overdue=[%dms]\n",
				 __func__, req,
				jiffies_to_msecs(jtimeout - srv->qjtimeout));
			tfw_http_req_move2equeue(srv_conn, req, equeue, 504);
			continue;
		}
		/*
		 * If unable to send to the server connection due to
		 * an error, then move the request to @err_queue for
		 * sending a 500 error response later. That is safe
		 * as the response will be sent in proper seq order.
		 */
		if (tfw_connection_send(srv_conn, (TfwMsg *)req)) {
			TFW_DBG2("%s: Forwarding error: conn=[%p] req=[%p]\n",
				 __func__, srv_conn, req);
			tfw_http_req_move2equeue(srv_conn, req, equeue, 500);
			continue;
		}
		srv_conn->msg_sent = (TfwMsg *)req;
		/* Stop sending if the request is non-idempotent. */
		if (tfw_http_req_is_nonidempotent(req)) {
			TFW_DBG2("%s: Break on non-idempotent: req=[%p]\n",
				 __func__, req);
			break;
		}
		/* See if a non-idempotent request has become idempotent. */
		tfw_http_req_nonidemp_delist(srv_conn, req);
	}
}

/*
 * Forward stalled requests in server connection @srv_conn.
 *
 * This function expects that the queue in the server connection
 * is locked. The queue in unlocked inside the function which is
 * very non-traditional. Please use with caution.
 */
static void
tfw_http_req_fwd_stalled(TfwConnection *srv_conn)
{
	LIST_HEAD(equeue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->msg_qlock));
	BUG_ON(list_empty(&srv_conn->msg_queue));

	__tfw_http_req_fwd_stalled(srv_conn, &equeue);
	spin_unlock(&srv_conn->msg_qlock);

	if (!list_empty(&equeue))
		tfw_http_req_zap_error(&equeue);
}

/*
 * Forward the request @req to server connection @srv_conn.
 *
 * The request is added to the server connection (forwarding) queue.
 * If forwarding is on hold at this moment, then the request will be
 * forwarded later. Otherwise, if the queue is drained, then forward
 * the request to the server immediately. If the queue is not drained,
 * then forward all stalled requests to the server.
 *
 * Forwarding to a server is considered to be on hold after
 * a non-idempotent request is forwarded to the server. The hold
 * is removed when the holding non-idempotent request is followed
 * by another request from the same client, which enables pipelining.
 */
static void
tfw_http_req_fwd(TfwConnection *srv_conn, TfwHttpReq *req)
{
	bool drained;

	TFW_DBG2("%s: srv_conn=[%p], req=[%p]\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock(&srv_conn->msg_qlock);
	drained = tfw_http_conn_drained(srv_conn);
	list_add_tail(&req->fwd_list, &srv_conn->msg_queue);
	srv_conn->qsize++;
	if (tfw_http_req_is_nonidempotent(req))
		__tfw_http_req_nonidemp_enlist(srv_conn, req);
	if (tfw_http_conn_on_hold(srv_conn)) {
		spin_unlock(&srv_conn->msg_qlock);
		TFW_DBG2("%s: Server connection is on hold: conn=[%p]\n",
			 __func__, srv_conn);
		return;
	}
	if (!drained) {
		TFW_DBG2("%s: Server connection is not drained: conn=[%p]\n",
			 __func__, srv_conn);
		tfw_http_req_fwd_stalled(srv_conn);
		/* The queue is unlocked inside the function. */
		return;
	}
	if (tfw_connection_send(srv_conn, (TfwMsg *)req)) {
		tfw_http_req_nonidemp_delist(srv_conn, req);
		list_del_init(&req->fwd_list);
		srv_conn->qsize--;
		spin_unlock(&srv_conn->msg_qlock);
		TFW_DBG2("%s: Forwarding error: conn=[%p] req=[%p]\n",
			 __func__, srv_conn, req);
		tfw_http_send_500(req);
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return;
	}
	srv_conn->msg_sent = (TfwMsg *)req;
	spin_unlock(&srv_conn->msg_qlock);
}

/*
 * Handle non-idempotent requests in case of a connection repair
 * (re-send or re-schedule).
 *
 * Non-idempotent requests that were forwarded but not responded to
 * are not re-sent or re-scheduled by default. Configuration option
 * can be used to have those requests re-sent or re-scheduled as well.
 *
 * Note: @srv_conn->msg_sent may change in result.
 */
static inline void
tfw_http_req_fwd_handlenip(TfwConnection *srv_conn)
{
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	if (req_sent && tfw_http_req_is_nonidempotent(req_sent)
	    && likely(!(srv->flags & TFW_SRV_RETRY_NON_IDEMP)))
	{
		BUG_ON(list_empty(&req_sent->nip_list));
		srv_conn->msg_sent =
			(&req_sent->fwd_list == srv_conn->msg_queue.next) ?
			NULL : (TfwMsg *)list_prev_entry(req_sent, fwd_list);
		__tfw_http_req_nonidemp_delist(srv_conn, req_sent);
		list_del_init(&req_sent->fwd_list);
		srv_conn->qsize--;
		tfw_http_send_404(req_sent);
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
}

/*
 * Re-forward requests in a server connection. Requests that exceed
 * the set limits are evicted.
 */
static void
__tfw_http_req_fwd_resend(TfwConnection *srv_conn,
			  bool one_msg, struct list_head *equeue)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwd_queue = &srv_conn->msg_queue;

	TFW_DBG2("%s: conn=[%p] one_msg=[%s]\n",
		 __func__, srv_conn, one_msg ? "true" : "false");
	BUG_ON(!srv_conn->msg_sent);
	BUG_ON(list_empty(&((TfwHttpReq *)srv_conn->msg_sent)->fwd_list));

	req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);
	end = ((TfwHttpReq *)srv_conn->msg_sent)->fwd_list.next;

	/* An equivalent of list_for_each_entry_safe_from() */
	for (tmp = list_next_entry(req, fwd_list);
	     &req->fwd_list != end;
	     req = tmp, tmp = list_next_entry(tmp, fwd_list))
	{
		if (req->retries++ >= srv->retry_max) {
			TFW_DBG2("%s: Eviction: req=[%p] retries=[%d]\n",
				 __func__, req, req->retries);
			tfw_http_req_move2equeue(srv_conn, req, equeue, 504);
			continue;
		}
		if (tfw_connection_send(srv_conn, (TfwMsg *)req)) {
			TFW_DBG2("%s: Forwarding error: conn=[%p] req=[%p]\n",
				 __func__, srv_conn, req);
			tfw_http_req_move2equeue(srv_conn, req, equeue, 500);
			continue;
		}
		srv_conn->msg_resent = (TfwMsg *)req;
		if (unlikely(one_msg))
			break;
	}
}

/*
 * Handle the complete re-forwarding of requests in a server connection
 * that is being repaired, after the first request had been re-forwarded.
 * The connection is not scheduled until all requests in it are re-sent.
 */
static void
tfw_http_req_fwd_repair(TfwConnection *srv_conn)
{
	LIST_HEAD(equeue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->msg_qlock));
	BUG_ON(!(srv_conn->flags & (TFW_CONN_B_QFORWD | TFW_CONN_B_RESEND)));

	if (list_empty(&srv_conn->msg_queue)) {
		clear_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		clear_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
	} else if (test_bit(TFW_CONN_B_QFORWD, &srv_conn->flags)) {
		if (tfw_http_conn_need_fwd(srv_conn))
			__tfw_http_req_fwd_stalled(srv_conn, &equeue);
	} else {
		srv_conn->msg_resent = NULL;
		if (srv_conn->msg_sent) {
			__tfw_http_req_fwd_resend(srv_conn, false, &equeue);
			if (srv_conn->msg_resent != srv_conn->msg_sent)
				srv_conn->msg_sent = srv_conn->msg_resent;
		}
		set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		if (tfw_http_conn_need_fwd(srv_conn))
			__tfw_http_req_fwd_stalled(srv_conn, &equeue);
	}
	spin_unlock(&srv_conn->msg_qlock);

	if (!list_empty(&equeue))
		tfw_http_req_zap_error(&equeue);
}

/*
 * Allocate a new HTTP message structure, and link it with
 * the connection structure. Increment the number of users
 * of the connection structure. Initialize GFSM for the message.
 */
static TfwMsg *
tfw_http_conn_msg_alloc(TfwConnection *conn)
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

		spin_lock(&conn->msg_qlock);
		req = list_first_entry_or_null(&conn->msg_queue,
					       TfwHttpReq, fwd_list);
		spin_unlock(&conn->msg_qlock);
		if (req && (req->method == TFW_HTTP_METH_HEAD))
			hm->flags |= TFW_HTTP_VOID_BODY;
		TFW_INC_STAT_BH(serv.rx_messages);
	}

	return (TfwMsg *)hm;
}

/*
 * Free an HTTP message.
 * Also, free the connection structure if there's no more references.
 *
 * This function should be used anytime when there's a chance that
 * a connection structure may belong to multiple messages, which is
 * almost always. If a connection is suddenly closed then it still
 * can be safely dereferenced and used in the code.
 * In rare cases we're sure that a connection structure in a message
 * doesn't have multiple users. For instance, when an error response
 * is prepared and sent by Tempesta, that HTTP message does not need
 * a connection structure. The message is then immediately destroyed,
 * and a simpler tfw_http_msg_free() can be used for that.
 *
 * NOTE: @hm->conn might be NULL if @hm is the response that was served
 * from the cache.
 */
static void
tfw_http_conn_msg_free(TfwHttpMsg *hm)
{
	if (unlikely(!hm))
		return;

	if (hm->conn) {
		/*
		 * Unlink connection while there is at least one reference.
		 * Use atomic exchange to avoid races with new messages arrival
		 * on the connection.
		 */
		__cmpxchg((unsigned long *)&hm->conn->msg, (unsigned long)hm,
			  0UL, sizeof(long));
		tfw_connection_put(hm->conn);
	}

	tfw_http_msg_free(hm);
}

/*
 * Re-schedule requests in a dead server connection's queue to a live
 * server connection. Idempotent requests are always rescheduled.
 * Non-idempotent requests may be rescheduled depending on the option
 * in configuration.
 *
 * FIXME: It appears that a re-scheduled request should be put in a
 * new server connection's queue according to its original timestamp.
 * It may matter as old requests are evicted. However, that is time
 * consuming. For now just put them at the end of the queue.
 */
static void
tfw_http_req_fwd_resched(TfwConnection *srv_conn)
{
	TfwHttpReq *req, *tmp;
	TfwConnection *sconn;
	struct list_head *fwd_queue = &srv_conn->msg_queue;

	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

	/* Handle non-idempotent requests. */
	tfw_http_req_fwd_handlenip(srv_conn);

	/* Process complete queue. */
	list_for_each_entry_safe(req, tmp, fwd_queue, fwd_list) {
		tfw_http_req_nonidemp_delist(srv_conn, req);
		list_del_init(&req->fwd_list);
		srv_conn->qsize--;
		if (!(sconn = tfw_sched_get_srv_conn((TfwMsg *)req))) {
			TFW_WARN("Unable to find a backend server\n");
			tfw_http_send_404(req);
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			continue;
		}
		if (req->retries++ >= ((TfwServer *)sconn->peer)->retry_max) {
			TFW_DBG2("%s: Eviction: req=[%p] retries=[%d]\n",
				 __func__, req, req->retries);
			tfw_http_send_504(req);
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			tfw_connection_put(sconn);
			continue;
		}
		tfw_http_req_fwd(sconn, req);
		tfw_connection_put(sconn);
	}
	BUG_ON(srv_conn->qsize);
}

/*
 * Find requests in the server's connection queue that were forwarded
 * to the server. These are unanswered requests. According to RFC 7230
 * 6.3.2, "a client MUST NOT pipeline immediately after connection
 * establishment". To address that, re-send the first request to the
 * server. When a response comes, that will trigger resending of the
 * rest of those unanswered requests (tfw_http_req_fwd_repair()).
 */
static void
tfw_http_conn_repair(TfwConnection *srv_conn)
{
	LIST_HEAD(equeue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));
	BUG_ON(!tfw_connection_restricted(srv_conn));

	/* See if requests need to be rescheduled. */
	if (unlikely(!tfw_connection_live(srv_conn))) {
		tfw_http_req_fwd_resched(srv_conn);
		return;
	}
	spin_lock(&srv_conn->msg_qlock);
	/* Handle non-idempotent requests. */
	tfw_http_req_fwd_handlenip(srv_conn);
	/* Re-send the first unanswered request. */
	srv_conn->msg_resent = NULL;
	if (srv_conn->msg_sent) {
		__tfw_http_req_fwd_resend(srv_conn, true, &equeue);
		if (!srv_conn->msg_resent)
			srv_conn->msg_sent = NULL;
	}
	/* Send the remaining unsent requests. */
	if (!srv_conn->msg_resent) {
		set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		if (tfw_http_conn_need_fwd(srv_conn))
			__tfw_http_req_fwd_stalled(srv_conn, &equeue);
	}
	spin_unlock(&srv_conn->msg_qlock);

	if (!list_empty(&equeue))
		tfw_http_req_zap_error(&equeue);
}

/*
 * Connection with a peer is created.
 *
 * Called when a connection is created. We need to initialize connection
 * state machine here.
 */
static int
tfw_http_conn_init(TfwConnection *conn)
{
	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Srv) {
		if (!list_empty(&conn->msg_queue))
			set_bit(TFW_CONN_B_RESEND, &conn->flags);
	}
	tfw_gfsm_state_init(&conn->state, conn, TFW_HTTP_FSM_INIT);
	return 0;
}

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
 * Connection with a peer is released.
 *
 * For server connections the requests that were sent to that server are
 * kept in the queue until a paired response comes. That will never happen
 * now. Keep the queue. When the connection is restored the requests will
 * be re-sent to the server.
 *
 * Called when a connection is released. There are no users at that time,
 * so locks are not needed.
 */
static void
tfw_http_conn_release(TfwConnection *srv_conn)
{
	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	clear_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
	clear_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
}

/*
 * Drop client connection's resources.
 *
 * Desintegrate the list, but do not free the requests. These requests
 * have not been answered yet. They are held in the lists of respective
 * server connections until paired responses come. If a response comes
 * after the list is destroyed, then both the request and the response
 * are dropped at the sight of an empty list. The requests from the
 * dead client connection are then removed from that server connection.
 *
 * Locking is necessary as the list is constantly probed from server
 * connection threads.
 */
static void
tfw_http_conn_cli_drop(TfwConnection *cli_conn)
{
	TfwHttpMsg *hmreq, *tmp;
	struct list_head *seq_queue = &cli_conn->msg_queue;
	LIST_HEAD(zap_queue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, cli_conn);
	BUG_ON(!(TFW_CONN_TYPE(cli_conn) & Conn_Clnt));

	if (list_empty_careful(seq_queue))
		return;

	spin_lock(&cli_conn->msg_qlock);
	list_splice_tail_init(seq_queue, &zap_queue);
	spin_unlock(&cli_conn->msg_qlock);

	list_for_each_entry_safe(hmreq, tmp, &zap_queue, msg.seq_list)
		list_del_init(&hmreq->msg.seq_list);
}

/*
 * Connection with a peer is dropped.
 *
 * Release resources that are not needed anymore, and keep other
 * resources that are needed while there are users of the connection.
 */
static void tfw_http_resp_terminate(TfwHttpMsg *hm);

static void
tfw_http_conn_drop(TfwConnection *conn)
{
	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		tfw_http_conn_cli_drop(conn);
	} else if (conn->msg) {
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
tfw_http_conn_send(TfwConnection *conn, TfwMsg *msg)
{
	return ss_send(conn->sk, &msg->skb_list, msg->ss_flags);
}

/**
 * Create a sibling for @msg message.
 * Siblings in HTTP are pipelined requests that share the same SKB.
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
	 * The sibling message is set up with a new SKB as
	 * the starting SKB. The new SKB is split off from
	 * the original SKB and contains the first part of
	 * new message. The original SKB is shrunk to have
	 * just data from the original message.
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
 * skb's can be shared between number of HTTP messages. We don't copy skb if
 * it's shared - we modify skb's safely and shared skb is still owned by one
 * CPU.
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
	static const char const * __read_mostly s_http_version[] = {
		[0 ... _TFW_HTTP_VER_COUNT] = NULL,
		[TFW_HTTP_VER_09] = "0.9 ",
		[TFW_HTTP_VER_10] = "1.0 ",
		[TFW_HTTP_VER_11] = "1.1 ",
		[TFW_HTTP_VER_20] = "2.0 ",
	};
	TfwVhost *vhost = tfw_vhost_get_default();
	TfwStr rh = {
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

/**
 * Adjust the request before proxying it to real server.
 */
static int
tfw_http_adjust_req(TfwHttpReq *req)
{
	int r;
	TfwHttpMsg *hm = (TfwHttpMsg *)req;

	tfw_http_req_init_ss_flags(req);

	r = tfw_http_add_x_forwarded_for(hm);
	if (r)
		return r;

	r = tfw_http_add_hdr_via(hm);
	if (r)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
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

	tfw_http_resp_init_ss_flags(resp, req);

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
 * Forward responses to the client in the correct order.
 */
void
tfw_http_resp_fwd(TfwHttpReq *req, TfwHttpResp *resp)
{
	TfwHttpReq *tmp;
	TfwConnection *cli_conn = req->conn;
	struct list_head *seq_queue = &cli_conn->msg_queue;
	LIST_HEAD(out_queue);

	TFW_DBG2("%s: req=[%p], resp=[%p]\n", __func__, req, resp);

	/*
	 * Starting with the first request on the list, pick consecutive
	 * requests that have a paired response. Remove those requests
	 * from the list, and put them on the list of outgoing responses.
	 *
	 * However, if the list is empty, then then it's either a bug,
	 * or the client connection had been closed. If it's a bug, then
	 * the correct order of responses to requests may be broken. The
	 * client connection needs to be closed.
	 */
	spin_lock(&cli_conn->msg_qlock);
	if (list_empty(seq_queue)) {
		spin_unlock(&cli_conn->msg_qlock);
		TFW_DBG2("%s: The client's request missing: conn=[%p]\n",
			 __func__, cli_conn);
		ss_close_sync(cli_conn->sk, true);
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
		return;
	}
	req->resp = (TfwHttpMsg *)resp;
	do {
		req = list_first_entry(seq_queue, TfwHttpReq, msg.seq_list);
		if (req->resp == NULL)
			break;
		list_move_tail(&req->msg.seq_list, &out_queue);
	} while (!list_empty(seq_queue));
	spin_unlock(&cli_conn->msg_qlock);

	/* Forward responses to the client. */
	list_for_each_entry_safe(req, tmp, &out_queue, msg.seq_list) {
		list_del_init(&req->msg.seq_list);
		resp = (TfwHttpResp *)req->resp;
		/*
		 * If the client connection is dead, then discard all
		 * @req and @resp in the @out_queue. Remaining requests
		 * from the client in the @seq_queue will be handled at
		 * the time the client connection is released.
		 */
		if (!tfw_connection_live(cli_conn)) {
			TFW_DBG2("%s: Client connection dead: conn=[%p]\n",
				 __func__, cli_conn);
			goto loop_discard;
		}
		/*
		 * Close the client connection in case of an error.
		 * Otherwise, the correct order of responses may be broken.
		 */
		if (tfw_cli_conn_send(cli_conn, (TfwMsg *)resp)) {
			TFW_DBG2("%s: Forwarding error: conn=[%p] resp=[%p]\n",
				 __func__, cli_conn, resp);
			ss_close_sync(cli_conn->sk, true);
		}
loop_discard:
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
	}
}

/**
 * The request is served from cache.
 * Send the response as is and unrefer its data.
 */
static void
tfw_http_req_cache_service(TfwHttpReq *req, TfwHttpResp *resp)
{
	if (tfw_http_adjust_resp(resp, req))
		goto resp_err;
	tfw_http_resp_fwd(req, resp);
	TFW_INC_STAT_BH(clnt.msgs_fromcache);
	return;
resp_err:
	tfw_http_send_500(req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
	return;
}

/**
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 404 or 500 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpReq *req, TfwHttpResp *resp)
{
	int r;
	TfwConnection *srv_conn = NULL;

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
	 *
	 * TODO #593: check whether req->sess->srv_conn is alive. If not,
	 * then get a new connection for req->sess->srv_conn->peer from
	 * an appropriate scheduler. That eliminates the long generic
	 * scheduling work flow. When the first request in a session is
	 * scheduled by the generic logic, TfwSession->srv_conn must be
	 * initialized to point at the appropriate TfwConnection, so that
	 * all subsequent session hits are scheduled much faster.
	 */
	if (!(srv_conn = tfw_sched_get_srv_conn((TfwMsg *)req))) {
		TFW_WARN("Unable to find a backend server\n");
		goto send_502;
	}

	if (tfw_http_adjust_req(req))
		goto send_500;

	/* Forward request to the server. */
	tfw_http_req_fwd(srv_conn, req);
	goto conn_put;

send_502:
	tfw_http_send_502(req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
	return;
send_500:
	tfw_http_send_500(req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
conn_put:
	tfw_connection_put(srv_conn);
}

static void
tfw_http_req_mark_nonidempotent(TfwHttpReq *req)
{
	/* See RFC 7231 4.2.1 */
	static const unsigned int __read_mostly safe_methods =
		(1 << TFW_HTTP_METH_GET) | (1 << TFW_HTTP_METH_HEAD);
	TfwLocation *loc = req->location;
	TfwLocation *loc_dflt = req->vhost->loc_dflt;
	TfwLocation *base_loc = (tfw_vhost_get_default())->loc_dflt;

	/*
	 * Search in the current location of the current vhost. If there
	 * are no entries there, then search in the default location of
	 * the current vhost. If there are no entries there either, then
	 * search in the default location of the default vhost - that is,
	 * in the global policies.
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
 * Set a flag if the request is non-idempotent. Add the request to
 * the list of the client connection to preserve the correct order
 * of responses. If the request follows a non-idempotent request
 * in flight, then the preceding request becomes idempotent.
 */
static void
tfw_http_req_add_seq_queue(TfwHttpReq *req)
{
	TfwHttpReq *preq;
	TfwConnection *cli_conn = req->conn;
	struct list_head *seq_queue = &cli_conn->msg_queue;

	tfw_http_req_mark_nonidempotent(req);

	spin_lock(&cli_conn->msg_qlock);
	preq = !list_empty(seq_queue)
	     ? list_last_entry(seq_queue, TfwHttpReq, msg.seq_list)
	     : NULL;
	if (preq && (preq->flags & TFW_HTTP_NON_IDEMP))
		preq->flags &= ~TFW_HTTP_NON_IDEMP;
	list_add_tail(&req->msg.seq_list, seq_queue);
	spin_unlock(&cli_conn->msg_qlock);
}

static int
tfw_http_req_set_context(TfwHttpReq *req)
{
	req->vhost = tfw_vhost_match(&req->uri_path);
	req->location = tfw_location_match(req->vhost, &req->uri_path);

	return !req->vhost;
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_req_process(TfwConnection *conn, struct sk_buff *skb, unsigned int off)
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
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			TFW_INC_STAT_BH(clnt.msgs_parserr);
			return TFW_BLOCK;
		case TFW_POSTPONE:
			r = tfw_gfsm_move(&conn->state,
					  TFW_HTTP_FSM_REQ_CHUNK, skb, off);
			TFW_DBG3("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
			if (r == TFW_BLOCK) {
				tfw_http_conn_msg_free((TfwHttpMsg *)req);
				TFW_INC_STAT_BH(clnt.msgs_filtout);
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
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			TFW_INC_STAT_BH(clnt.msgs_filtout);
			return TFW_BLOCK;
		}

		/*
		 * The time the request was received is used in cache
		 * for age calculations, and for APM and Load Balancing.
		 */
		req->cache_ctl.timestamp = tfw_current_timestamp();
		req->jtstamp = jiffies;

		/* Assign the right Vhost for this request. */
		if (tfw_http_req_set_context(req)) {
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
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
		 */
		req_conn_close = req->flags & TFW_HTTP_CONN_CLOSE;

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
				tfw_http_conn_msg_free((TfwHttpMsg *)req);
				TFW_INC_STAT_BH(clnt.msgs_otherr);
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
			tfw_http_send_500(req);
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
			return TFW_STOP;

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
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_send_500(req);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return;
	}
	/*
	 * Responses from cache don't have @resp->conn.
	 *
	 * FIXME: The same check is performed in tfw_http_popreq()
	 * which happens just a bit earlier. Is there a way to avoid
	 * it here? The condition is considered rare, and there's no
	 * need to check for it in the regular path. The real issue
	 * here is that APM stats can't handle response times that
	 * are >= USHORT_MAX. So for now don't count the requests
	 * that are re-sent after a server connection is restored.
	 */
	if (resp->conn && !tfw_connection_restricted(resp->conn))
		tfw_apm_update(((TfwServer *)resp->conn->peer)->apm,
			       resp->jtstamp, resp->jtstamp - req->jtstamp);
	tfw_http_resp_fwd(req, resp);
	TFW_INC_STAT_BH(serv.msgs_forwarded);
	return;
}

/*
 * Request messages that were forwarded to a backend server are added
 * to and kept in @msg_queue of the connection @conn for that server.
 * If a paired request is not found, then the response is deleted.
 *
 * If a paired client request is missing, then it seems upsream server is
 * misbehaving, so the caller has to drop the server connection.
 */
static TfwHttpReq *
tfw_http_popreq(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req;
	TfwConnection *srv_conn = hmresp->conn;
	struct list_head *fwd_queue = &srv_conn->msg_queue;

	spin_lock(&srv_conn->msg_qlock);
	if (unlikely(list_empty(fwd_queue))) {
		BUG_ON(srv_conn->qsize);
		spin_unlock(&srv_conn->msg_qlock);
		/* @conn->msg will get NULLed in the process. */
		TFW_WARN("Paired request missing, "
			 "HTTP Response Splitting attack?\n");
		tfw_http_conn_msg_free(hmresp);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return NULL;
	}
	req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);
	list_del_init(&req->fwd_list);
	srv_conn->qsize--;
	if ((TfwMsg *)req == srv_conn->msg_sent)
		srv_conn->msg_sent = NULL;
	tfw_http_req_nonidemp_delist(srv_conn, req);
	tfw_http_conn_nonidemp_delist(srv_conn);
	/*
	 * Perform special processing if the connection is in repair
	 * mode. Otherwise, forward pending requests to the server.
	 * Note: The queue is unlocked inside tfw_http_req_fwd_repair()
	 * or tfw_http_req_fwd_stalled().
	 */
	if (unlikely(tfw_connection_restricted(srv_conn)))
		tfw_http_req_fwd_repair(srv_conn);
	else if (tfw_http_conn_need_fwd(srv_conn))
		tfw_http_req_fwd_stalled(srv_conn);
	else
		spin_unlock(&srv_conn->msg_qlock);

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

	tfw_http_send_502(req);
	tfw_http_conn_msg_free(hmresp);
	TFW_INC_STAT_BH(serv.msgs_filtout);
	return r;
}

static int
tfw_http_resp_cache(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req;
	time_t timestamp = tfw_current_timestamp();

	/*
	 * The time the response was received is used in cache
	 * for age calculations, and for APM and Load Balancing.
	 */
	hmresp->cache_ctl.timestamp = timestamp;
	hmresp->jtstamp = jiffies;
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
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @conn as
	 * further handling of @conn depends on that. Future SKBs
	 * will be put in a new message.
	 */
	tfw_connection_unlink_msg(hmresp->conn);
	if (tfw_cache_process(req, (TfwHttpResp *)hmresp,
			      tfw_http_resp_cache_cb))
	{
		tfw_http_send_500(req);
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
tfw_http_resp_process(TfwConnection *conn, struct sk_buff *skb,
		      unsigned int off)
{
	int r = TFW_BLOCK;
	unsigned int data_off = off;
	unsigned int skb_len = skb->len;
	TfwHttpReq *bad_req;
	TfwHttpMsg *hmresp;

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
			BUG_ON(!(hmresp->flags
				 & (TFW_HTTP_CHUNKED | TFW_HTTP_VOID_BODY))
			       && (hmresp->content_length != hmresp->body.len));
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
	if (bad_req)
		tfw_http_conn_msg_free((TfwHttpMsg *)bad_req);
	tfw_http_conn_msg_free(hmresp);
	return r;
}

/**
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off)
{
	TfwConnection *c = (TfwConnection *)conn;

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

	req->hash = tfw_hash_str(&req->uri_path) ^ req->method;

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

int __init
tfw_http_init(void)
{
	int r = tfw_gfsm_register_fsm(TFW_FSM_HTTP, tfw_http_msg_process);
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

	return 0;
}

void
tfw_http_exit(void)
{
	tfw_gfsm_unregister_hook(TFW_FSM_TLS, ghprio, TFW_TLS_FSM_DATA_READY);
	tfw_connection_hooks_unregister(TFW_FSM_HTTP);
	tfw_gfsm_unregister_fsm(TFW_FSM_HTTP);
}
