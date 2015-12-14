/**
 *		Tempesta FW
 *
 * HTTP processing.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
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
#include "server.h"
#include "hash.h"
#include "http_msg.h"
#include "http_sticky.h"
#include "log.h"
#include "sched.h"
#include "tls.h"

#include "sync_socket.h"

#define RESP_BUF_LEN			128
static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_buf);
int ghprio; /* GFSM hook priority. */

#define S_CRLF			"\r\n"
#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"

#define S_302			"HTTP/1.1 302 Found"
#define S_404			"HTTP/1.1 404 Not Found"
#define S_500			"HTTP/1.1 500 Internal Server Error"
#define S_502			"HTTP/1.1 502 Bad Gateway"

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

#define SLEN(s)			(sizeof(s) - 1)

/*
 * Prepare current date in the format required for HTTP "Date:"
 * header field. See RFC 2616 section 3.3.
 */
static void
tfw_http_prep_date(char *buf)
{
	struct tm tm;
	struct timespec ts;
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

	getnstimeofday(&ts);
	time_to_tm(ts.tv_sec, 0, &tm);

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

unsigned long tfw_hash_str(const TfwStr *str);

/*
 * Convert a C string to a printable hex string.
 *
 * Each character makes two hex digits, thus the size of the
 * output buffer must be twice of the length of input string.
 */
void
tfw_http_prep_hexstring(char *buf, u_char *value, size_t len)
{
	char *ptr = buf;

	while (len--) {
		*ptr++ = hex_asc_hi(*value);
		*ptr++ = hex_asc_lo(*value++);
	}
}

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
TfwHttpMsg *
tfw_http_prep_302(TfwHttpMsg *hmreq, TfwStr *cookie)
{
	size_t data_len = S_302_FIXLEN;
	int conn_flag = hmreq->flags & __TFW_HTTP_CONN_MASK;
	TfwHttpReq *req = (TfwHttpReq *)hmreq;
	TfwHttpMsg *resp;
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

	if (!(req->flags & TFW_HTTP_STICKY_SET))
		return NULL;

	tfw_http_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
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

	resp = tfw_http_msg_create(&it, Conn_Srv, data_len);
	if (resp == NULL)
		return NULL;

	tfw_http_prep_date(__TFW_STR_CH(&rh, 1)->ptr);
	tfw_http_msg_write(&it, resp, &rh);
	/*
	 * HTTP/1.0 may have no host part, so we create relative URI.
	 * See RFC 1945 9.3 and RFC 7231 7.1.2.
	 */
	if (host.len) {
		static TfwStr proto = { .ptr = S_HTTP, .len = SLEN(S_HTTP) };
		tfw_http_msg_write(&it, resp, &proto);
		tfw_http_msg_write(&it, resp, &host);
	}
	tfw_http_msg_write(&it, resp, &req->uri_path);
	tfw_http_msg_write(&it, resp, &part03);
	tfw_http_msg_write(&it, resp, cookie);
	tfw_http_msg_write(&it, resp, crlf);

	return resp;
}

/*
 * Perform operations common to sending an error response to a client.
 * Set current date in the header of an HTTP error response, and set
 * the "Connection:" header field if it was present in the request.
 *
 * NOTE: This function expects that the last chunk of @msg is CRLF.
 */
static int
tfw_http_send_resp(TfwHttpMsg *hmreq, TfwStr *msg, const TfwStr *date)
{
	int conn_flag = hmreq->flags & __TFW_HTTP_CONN_MASK;
	TfwStr *crlf = __TFW_STR_CH(msg, TFW_STR_CHUNKN(msg) - 1);
	TfwHttpMsg *resp;
	TfwMsgIter it;

	if (conn_flag) {
		unsigned long crlf_len = crlf->len;
		if (conn_flag == TFW_HTTP_CONN_CLOSE) {
			crlf->ptr = S_H_CONN_CLOSE;
			crlf->len = SLEN(S_H_CONN_CLOSE);
		} else if (conn_flag == TFW_HTTP_CONN_KA) {
			crlf->ptr = S_H_CONN_KA;
			crlf->len = SLEN(S_H_CONN_KA);
		}
		msg->len += crlf->len - crlf_len;
	}

	resp = tfw_http_msg_create(&it, Conn_Srv, msg->len);
	if (resp == NULL)
		return -ENOMEM;

	tfw_http_prep_date(date->ptr);
	tfw_http_msg_write(&it, resp, msg);

	tfw_connection_send(hmreq->conn, (TfwMsg *)resp, true);
	tfw_http_msg_free(resp);

	return 0;
}

#define S_404_PART_01	S_404 S_CRLF S_F_DATE
#define S_404_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 404 response: Tempesta is unable to find the requested data.
 */
static int
tfw_http_send_404(TfwHttpMsg *hmreq)
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

	TFW_DBG("Send HTTP 404 response to the client\n");

	return tfw_http_send_resp(hmreq, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_500_PART_01	S_500 S_CRLF S_F_DATE
#define S_500_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 500 response: there was an internal error while forwarding
 * the request to a server.
 */
static int
tfw_http_send_500(TfwHttpMsg *hmreq)
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

	TFW_DBG("Send HTTP 500 response to the client\n");

	return tfw_http_send_resp(hmreq, &rh, __TFW_STR_CH(&rh, 1));
}

#define S_502_PART_01	S_502 S_CRLF S_F_DATE
#define S_502_PART_02	S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
/*
 * HTTP 502 response: Tempesta is unable to forward the request to
 * the designated server.
 */
int
tfw_http_send_502(TfwHttpMsg *hmreq)
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

	TFW_DBG("Send HTTP 502 response to the client\n");

	return tfw_http_send_resp(hmreq, &rh, __TFW_STR_CH(&rh, 1));
}

/*
 * Allocate a new HTTP message structure, and link it with
 * the connection structure. Increment the number of users
 * of the connection structure. Initialize GFSM for the message.
 */
TfwMsg *
tfw_http_conn_msg_alloc(TfwConnection *conn)
{
	TfwHttpMsg *hm = tfw_http_msg_alloc(TFW_CONN_TYPE(conn));
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_connection_get(conn);
	tfw_gfsm_state_init(&hm->msg.state, conn, TFW_HTTP_FSM_INIT);

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
 */
void
tfw_http_conn_msg_free(TfwHttpMsg *hm)
{
	if (unlikely(hm == NULL))
		return;
	if (tfw_connection_put(hm->conn)) {
		TFW_CONN_TYPE(hm->conn) & Conn_Clnt
			? tfw_cli_conn_release(hm->conn)
			: tfw_srv_conn_release(hm->conn);
		hm->conn = NULL;
	}
	tfw_http_msg_free(hm);
}

/**
 * TODO Initialize allocated Client structure by HTTP specific callbacks
 * and FSM.
 */
static int
tfw_http_conn_init(TfwConnection *conn)
{
	return 0;
}

static void
tfw_http_conn_destruct(TfwConnection *conn)
{
	TfwMsg *msg, *tmp;

	spin_lock(&conn->msg_qlock);
	list_for_each_entry_safe(msg, tmp, &conn->msg_queue, msg_list) {
		BUG_ON(((TfwHttpMsg *)msg)->conn
			&& (((TfwHttpMsg *)msg)->conn == conn));
		/*
		 * Connection with a server is closed, and there are
		 * requests in the queue that are kept until a paired
		 * response comes. That will never happen now. Send
		 * a client an error response. If the connection with
		 * a client must be closed after a response is sent
		 * to that client, then close the connection now.
		 *
		 * Hold @msg->conn reference through @msg until
		 * the connection is dropped.
		 *
		 * Note: It's essential that there's no incoming
		 * data activity in the connection with a client
		 * after a request with "Connection: close" header.
		 */
		tfw_http_send_404((TfwHttpMsg *)msg);
		if (((TfwHttpMsg *)msg)->flags & TFW_HTTP_CONN_CLOSE)
			tfw_connection_drop(((TfwHttpMsg *)msg)->conn);
		tfw_http_conn_msg_free((TfwHttpMsg *)msg);
	}
	INIT_LIST_HEAD(&conn->msg_queue);
	spin_unlock(&conn->msg_qlock);

	tfw_http_conn_msg_free((TfwHttpMsg *)conn->msg);
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

/**
 * Removes Connection header from HTTP message @msg if @conn_flg is zero,
 * and replace or set a new header value otherwise.
 *
 * skb's can be shared between number of HTTP messages. We don't copy skb if
 * it's shared - we modify skb's safely and shared skb is still owned by one
 * CPU.
 */
static int
tfw_http_set_hdr_connection(TfwHttpMsg *hm, int conn_flg)
{
	if ((hm->flags & __TFW_HTTP_CONN_MASK) == conn_flg)
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
	int r = 0;
	TfwHttpMsg *m = (TfwHttpMsg *)req;

	r = tfw_http_add_x_forwarded_for(m);
	if (r)
		return r;

	return tfw_http_set_hdr_connection(m, TFW_HTTP_CONN_KA);
}

/**
 * Adjust the response before proxying it to real client.
 */
static int
tfw_http_adjust_resp(TfwHttpResp *resp, TfwHttpReq *req)
{
	int r, conn_flg = req->flags & __TFW_HTTP_CONN_MASK;
	TfwHttpMsg *m = (TfwHttpMsg *)resp;

	r = tfw_http_sticky_resp_process(m, (TfwHttpMsg *)req);
	if (r < 0)
		return r;

	/*
	 * TODO adjust Keep-Alive header.
	 * See also rfc2616 13.5.1 and rfc7234
	 */
	return tfw_http_set_hdr_connection(m, conn_flg);
}

/*
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 404 or 500 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpReq *req, TfwHttpResp *resp)
{
	int r;
	int req_conn_close = !!(req->flags & TFW_HTTP_CONN_CLOSE);
	TfwConnection *srv_conn, *cli_conn = req->conn;

	if (resp) {
		/*
		 * The response is prepared, send it as is. The response
		 * is either passed through from the back-end server, or
		 * it is generated from the cache, so unrefer all its data.
		 */
		if (tfw_http_adjust_resp(resp, req) == 0)
			tfw_connection_send(cli_conn, (TfwMsg *)resp, true);
		if (req_conn_close)
			tfw_connection_drop(cli_conn);
		return;
	}

	/*
	 * Dispatch request to an appropriate server. Schedulers
	 * should make a decision based on an unmodified request,
	 * so this must be done before any request mangling.
	 *
	 * The code below is typically called on remote NUMA node.
	 * That's not good, but we must run TDB lookup on the node
	 * before this is executed, to avoid unnecessary work in
	 * SoftIRQ and to speed up the cache operation.
	 * At the same time, cache hits are expected to prevail
	 * over cache misses, so this is not a frequent path.
	 */
	srv_conn = tfw_sched_get_srv_conn((TfwMsg *)req);
	if (srv_conn == NULL) {
		TFW_ERR("Unable to find a backend server\n");
		goto send_404;
	}

	/*
	 * Sticky cookie module may send a response to the client
	 * when sticky cookie presence is enforced and the cookie
	 * is missing from the request.
	 */
	r = tfw_http_sticky_req_process((TfwHttpMsg *)req);
	if (r < 0) {
		goto send_500;
	}
	else if (r > 0) {
		/* Response sent, nothing to do */
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
		goto conn_put;
	}

	if (tfw_http_adjust_req(req))
		goto send_500;

	/* Add request to the server connection. */
	spin_lock(&srv_conn->msg_qlock);
	list_add_tail(&req->msg.msg_list, &srv_conn->msg_queue);
	spin_unlock(&srv_conn->msg_qlock);

	/* Send request to the server. */
	tfw_connection_send(srv_conn, (TfwMsg *)req, false);
	goto conn_put;

send_404:
	tfw_http_send_404((TfwHttpMsg *)req);
	if (req_conn_close)
		tfw_connection_drop(cli_conn);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
	return;
send_500:
	tfw_http_send_500((TfwHttpMsg *)req);
	if (req_conn_close)
		tfw_connection_drop(cli_conn);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
conn_put:
	if (tfw_connection_put(srv_conn))
		tfw_srv_conn_release(srv_conn);
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
		TfwHttpMsg *hmreq = (TfwHttpMsg *)conn->msg;
		TfwHttpParser *parser = &hmreq->parser;

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
		r = ss_skb_process(skb, &data_off, tfw_http_parse_req, hmreq);
		data_off -= parser->to_go;
		hmreq->msg.len += data_off - off;

		TFW_DBG2("Request parsed: len=%u parsed=%d msg_len=%lu"
			 " res=%d\n",
			 skb_len - off, data_off - off, hmreq->msg.len, r);

		switch (r) {
		default:
			TFW_ERR("Unrecognized HTTP request "
				"parser return code, %d\n", r);
			BUG();
		case TFW_BLOCK:
			TFW_DBG2("Block invalid HTTP request\n");
			return TFW_BLOCK;
		case TFW_POSTPONE:
			r = tfw_gfsm_move(&hmreq->msg.state,
					  TFW_HTTP_FSM_REQ_CHUNK, skb, off);
			TFW_DBG3("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
			if (r == TFW_BLOCK)
				return TFW_BLOCK;
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
			;
		}

		r = tfw_gfsm_move(&hmreq->msg.state,
				  TFW_HTTP_FSM_REQ_MSG, skb, off);
		TFW_DBG3("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
		/* Don't accept any following requests from the peer. */
		if (r == TFW_BLOCK)
			return TFW_BLOCK;

		if (data_off < skb_len) {
			/*
			 * Pipelined requests: create a new sibling message.
			 * @skb is replaced with pointer to a new SKB.
			 */
			hmsib = tfw_http_msg_create_sibling(hmreq, &skb,
							    data_off,
							    Conn_Clnt);
			if (hmsib == NULL) {
				/*
				 * Not enough memory. Unfortunately, there's
				 * no recourse. The caller expects that data
				 * is processed in full, and can't deal with
				 * partially processed data.
				 */
				TFW_WARN("Not enough memory "
					 "to create a request sibling\n");
				return TFW_BLOCK;
			}
		}
		/*
		 * Complete HTTP message has been collected and successfully
		 * processed. Mark the message as complete in @conn, because
		 * further handling of @conn depends on that. Future SKBs
		 * will be put in a new message.
		 * Otherwise, the function returns from inside the loop.
		 * @conn->msg holds the reference to the message, which can
		 * be used to release it.
		 */
		conn->msg = NULL;
		/*
		 * The request should either be stored or released.
		 * Otherwise we lose the reference to it and get a leak.
		 * As it may be released, save the needed flag for later use.
		 */
		req_conn_close = !!(hmreq->flags & TFW_HTTP_CONN_CLOSE);
		tfw_cache_req_process((TfwHttpReq *)hmreq,
				      tfw_http_req_cache_cb);

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
	int req_conn_close = !!(req->flags & TFW_HTTP_CONN_CLOSE);
	TfwConnection *cli_conn = req->conn;

	/* Cache original response before any mangling. */
	tfw_cache_add(resp, req);

	/*
	 * Typically we're at a node far from the node where @resp was
	 * received, so we do an inter-node transfer. However, this is
	 * the final place where the response will be stored. Upcoming
	 * requests will get responded to by the current node without
	 * inter-node data transfers. (see tfw_http_req_cache_cb())
	 */
	if (tfw_http_adjust_resp(resp, req))
		goto err;

	tfw_connection_send(cli_conn, (TfwMsg *)resp, false);
err:
	/* Now we don't need the request and the reponse anymore. */
	tfw_http_conn_msg_free((TfwHttpMsg *)resp);
	if (req_conn_close)
		tfw_connection_drop(cli_conn);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

/*
 * Request messages that were forwarded to a backend server are added
 * to and kept in @msg_queue of the connection @conn for that server.
 */
static TfwHttpReq *
tfw_http_popreq(TfwConnection *conn)
{
	TfwMsg *msg;

	spin_lock(&conn->msg_qlock);
	if (unlikely(list_empty(&conn->msg_queue))) {
		spin_unlock(&conn->msg_qlock);
		return NULL;
	}
	msg = list_first_entry(&conn->msg_queue, TfwMsg, msg_list);
	list_del(&msg->msg_list);
	spin_unlock(&conn->msg_qlock);

	return (TfwHttpReq *)msg;
}

/*
 * A complete response message has been collected. However an error
 * occured on further processing. Such errors are considered rare.
 * Delete the response and the corresponding (paired) request, and
 * keep the connection open for data exchange.
 */
static inline void
tfw_http_delpair(TfwConnection *conn, TfwHttpMsg *hmresp)
{
	TfwHttpMsg *hmreq = (TfwHttpMsg *)tfw_http_popreq(conn);

	if (hmreq)
		tfw_http_conn_msg_free(hmreq);
	/* conn->msg will get NULLed in the process. */
	tfw_http_conn_msg_free(hmresp);
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

	BUG_ON(!conn->msg);
	BUG_ON(data_off >= skb_len);

	TFW_DBG2("received %u server data bytes on conn=%p msg=%p\n",
		skb->len - off, conn, conn->msg);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
	while (data_off < skb_len) {
		TfwHttpReq *req;
		TfwHttpMsg *hmsib = NULL;
		TfwHttpMsg *hmresp = (TfwHttpMsg *)conn->msg;
		TfwHttpParser *parser = &hmresp->parser;

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
		r = ss_skb_process(skb, &data_off, tfw_http_parse_resp, hmresp);
		data_off -= parser->to_go;
		hmresp->msg.len += data_off - off;

		TFW_DBG2("Response parsed: len=%u parsed=%d msg_len=%lu"
			 " res=%d\n",
			 skb_len - off, data_off - off, hmresp->msg.len, r);

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
			return TFW_BLOCK;
		case TFW_POSTPONE:
			r = tfw_gfsm_move(&hmresp->msg.state,
					  TFW_HTTP_FSM_RESP_CHUNK, skb, off);
			TFW_DBG3("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
			if (r == TFW_BLOCK)
				/*
				 * We don't have a complete response. There's
				 * no choice but report a critical error.
				 */
				return TFW_BLOCK;
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
			;
		}

		r = tfw_gfsm_move(&hmresp->msg.state,
				  TFW_HTTP_FSM_RESP_MSG, skb, off);
		TFW_DBG3("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
		if (r == TFW_BLOCK) {
			tfw_http_delpair(conn, hmresp);
			goto next_resp;
		}

		r = tfw_gfsm_move(&hmresp->msg.state,
				  TFW_HTTP_FSM_LOCAL_RESP_FILTER, skb, off);
		TFW_DBG3("TFW_HTTP_FSM_LOCAL_RESP_FILTER return code %d\n", r);
		if (r == TFW_BLOCK)
			tfw_http_delpair(conn, hmresp);
next_resp:
		if (data_off < skb_len) {
			/*
			 * Pipelined responses: create a new sibling message.
			 * @skb is replaced with pointer to a new SKB.
			 */
			hmsib = tfw_http_msg_create_sibling(hmresp, &skb,
							    data_off,
							    Conn_Srv);
			if (hmsib == NULL) {
				/*
				 * Not enough memory. Unfortunately, there's
				 * no recourse. The caller expects that data
				 * is processed in full, and can't deal with
				 * partially processed data.
				 */
				TFW_WARN("Not enough memory "
					 "to create a response sibling\n");
				return TFW_BLOCK;
			}
		}
		/*
		 * Cache adjusted and filtered responses only. Responses
		 * are received in the same order as requests, so we can
		 * just pop the first request. If a paired request is not
		 * found, delete the response and keep the connection open
		 * for data exchange until that gets impossible.
		 */
		if ((req = tfw_http_popreq(conn)) != NULL) {
			/*
			 * Complete HTTP message has been collected and
			 * successfully processed. Mark the message as
			 * complete in @conn, because further handling
			 * of @conn depends on that. Future SKBs will
			 * be put in a new message.
			 * Otherwise, the function returns from inside
			 * the loop. @conn->msg holds the reference to
			 * the message, which can be used to release it.
			 */
			conn->msg = NULL;
			tfw_cache_resp_process((TfwHttpResp *)hmresp,
					       req, tfw_http_resp_cache_cb);
		} else {
			/* @conn->msg will get NULLed in the process. */
			TFW_WARN("Paired request missing\n");
			tfw_http_conn_msg_free(hmresp);
		}

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
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off)
{
	TfwConnection *c = (TfwConnection *)conn;

	return (TFW_CONN_TYPE(c) & Conn_Clnt)
		? tfw_http_req_process(c, skb, off)
		: tfw_http_resp_process(c, skb, off);
}

/**
 * Calculate key of a HTTP request by hashing its URI and Host header value.
 */
unsigned long
tfw_http_req_key_calc(TfwHttpReq *req)
{
	TfwStr host;

	if (req->hash)
		return req->hash;

	req->hash = tfw_hash_str(&req->uri_path);

	tfw_http_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
			     TFW_HTTP_HDR_HOST, &host);
	if (!TFW_STR_EMPTY(&host))
		req->hash ^= tfw_hash_str(&req->uri_path);

	return req->hash;
}
EXPORT_SYMBOL(tfw_http_req_key_calc);

static TfwConnHooks http_conn_hooks = {
	.conn_init	= tfw_http_conn_init,
	.conn_destruct	= tfw_http_conn_destruct,
	.conn_msg_alloc	= tfw_http_conn_msg_alloc,
};

int __init
tfw_http_init(void)
{
	int r = tfw_gfsm_register_fsm(TFW_FSM_HTTP, tfw_http_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&http_conn_hooks, TFW_FSM_HTTP);

	/* Must be last call - we can't unregister the hook. */
	ghprio = tfw_gfsm_register_hook(TFW_FSM_HTTPS,
					TFW_GFSM_HOOK_PRIORITY_ANY,
					TFW_HTTPS_FSM_TODO_ISSUE_81,
					TFW_FSM_HTTP, TFW_HTTP_FSM_INIT);
	if (ghprio < 0)
		return ghprio;

	return 0;
}

void
tfw_http_exit(void)
{
	tfw_gfsm_unregister_hook(TFW_FSM_HTTPS, ghprio,
				 TFW_HTTPS_FSM_TODO_ISSUE_81);
	tfw_connection_hooks_unregister(TFW_FSM_HTTP);
	tfw_gfsm_unregister_fsm(TFW_FSM_HTTP);
}
