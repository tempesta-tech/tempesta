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
#define S_F_SET_COOKIE		"Set-Cookie: "

#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"

#define SLEN(s)			(sizeof(s) - 1)

/*
 * HTTP 302 response.
 * The response redirects the client to the same URI as the original request,
 * but it includes 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 */
#define S_302_PART_01		S_302 S_CRLF S_F_DATE
/* Insert current date */
#define S_302_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF	\
				S_F_LOCATION S_HTTP
/* Insert full location URI */
#define S_302_PART_03		S_CRLF S_F_SET_COOKIE
/* Insert cookie name and value */
#define S_302_PART_04		S_CRLFCRLF
#define S_302_FIXLEN		SLEN(S_302_PART_01 S_V_DATE S_302_PART_02 \
				     S_302_PART_03 S_302_PART_04)

/*
 * HTTP 404 response: Tempesta is unable to find the requested data.
 */
#define S_404_PART_01		S_404 S_CRLF S_F_DATE
/* Insert current date */
#define S_404_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLFCRLF
#define S_404_FIXLEN		SLEN(S_404_PART_01 S_V_DATE S_404_PART_02)

/*
 * HTTP 500 response: there was an internal error while forwarding
 * the request to a server.
 */
#define S_500_PART_01		S_500 S_CRLF S_F_DATE
/* Insert current date */
#define S_500_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLFCRLF
#define S_500_FIXLEN		SLEN(S_500_PART_01 S_V_DATE S_500_PART_02)

/*
 * HTTP 502 response: Tempesta is unable to forward the request to
 * the designated server.
 */
#define S_502_PART_01		S_502 S_CRLF S_F_DATE
/* Insert current date */
#define S_502_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLFCRLF
#define S_502_FIXLEN		SLEN(S_502_PART_01 S_V_DATE S_502_PART_02)

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

TfwHttpMsg *
tfw_http_prep_302(TfwHttpMsg *hm, TfwStr *cookie)
{
	size_t data_len = S_302_FIXLEN;
	TfwHttpMsg *resp;
	TfwHttpReq *req = (TfwHttpReq *)hm;
	TfwMsgIter it;
	TfwStr host;
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_302_PART_01, .len = SLEN(S_302_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_302_PART_02, .len = SLEN(S_302_PART_02) }
		},
		.len = SLEN(S_302_PART_01 S_302_PART_02 S_V_DATE),
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	if (!(hm->flags & TFW_HTTP_STICKY_SET))
		return NULL;

	tfw_http_msg_hdr_val(&hm->h_tbl->tbl[TFW_HTTP_HDR_HOST],
			     TFW_HTTP_HDR_HOST, &host);

	/* Add variable part of data length to get the total */
	data_len += req->host.len ? : host.len;
	data_len += req->uri_path.len + cookie->len;

	resp = tfw_http_msg_create(&it, Conn_Srv, data_len);
	if (resp == NULL)
		return NULL;

	tfw_http_prep_date(__TFW_STR_CH(&rh, 1)->ptr);
	tfw_http_msg_write(&it, resp, &rh);
	if (!TFW_STR_EMPTY(&req->host))
		tfw_http_msg_write(&it, resp, &req->host);
	else
		tfw_http_msg_write(&it, resp, &host);
	tfw_http_msg_write(&it, resp, &req->uri_path);
	tfw_http_msg_write(&it, resp, &(TfwStr){ .ptr = S_302_PART_03,
						 .len = SLEN(S_302_PART_03)});
	tfw_http_msg_write(&it, resp, cookie);
	tfw_http_msg_write(&it, resp, &(TfwStr){ .ptr = S_302_PART_04,
						 .len = SLEN(S_302_PART_04)});

	return resp;
}

static int
tfw_http_send_resp(TfwHttpMsg *hm, const TfwStr *msg, const TfwStr *date)
{
	TfwHttpMsg *resp;
	TfwMsgIter it;

	resp = tfw_http_msg_create(&it, Conn_Srv, msg->len);
	if (resp == NULL)
		return -ENOMEM;

	tfw_http_prep_date(date->ptr);
	tfw_http_msg_write(&it, resp, msg);

	tfw_connection_send(hm->conn, (TfwMsg *)resp);
	tfw_http_msg_free(resp);

	return 0;
}

static int
tfw_http_send_404(TfwHttpMsg *hm)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_404_PART_01, .len = SLEN(S_404_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_404_PART_02, .len = SLEN(S_404_PART_02) },
		},
		.len = S_404_FIXLEN,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 404 response to the client\n");

	return tfw_http_send_resp(hm, &rh, __TFW_STR_CH(&rh, 1));
}

static int
tfw_http_send_500(TfwHttpMsg *hm)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_500_PART_01, .len = SLEN(S_500_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_500_PART_02, .len = SLEN(S_500_PART_02) },
		},
		.len = S_500_FIXLEN,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 500 response to the client\n");

	return tfw_http_send_resp(hm, &rh, __TFW_STR_CH(&rh, 1));
}

int
tfw_http_send_502(TfwHttpMsg *hm)
{
	TfwStr rh = {
		.ptr = (TfwStr []){
			{ .ptr = S_502_PART_01, .len = SLEN(S_502_PART_01) },
			{ .ptr = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .ptr = S_502_PART_02, .len = SLEN(S_502_PART_02) },
		},
		.len = S_502_FIXLEN,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	TFW_DBG("Send HTTP 502 response to the client\n");

	return tfw_http_send_resp(hm, &rh, __TFW_STR_CH(&rh, 1));
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
	}
	tfw_http_msg_free(hm);
}

/**
 * TODO Initialize allocated Client structure by HTTP specific callbacks and FSM.
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
tfw_http_adjust_resp(TfwHttpResp *resp)
{
	/*
	 * TODO adjust Connection header and all connection-token headers
	 * (e.g. Keep-Alive) according to our policy.
	 */
	(void)resp;

	return 0;
}

/*
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 404 or 500 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpReq *req, TfwHttpResp *resp, void *data)
{
	int r;
	TfwConnection *conn;

	if (resp) {
		/*
		 * We have prepared response, send it as is.
		 * TODO should we adjust it somehow?
		 */
		tfw_connection_send(req->conn, (TfwMsg *)resp);
		return;
	} else {
		/*
		 * Dispatch request to an appropriate server. Schedulers
		 * should make a decision based on an unmodified request,
		 * so this must be done before any request mangling.
		 */
		conn = tfw_sched_get_srv_conn((TfwMsg *)req);
		if (conn == NULL) {
			TFW_ERR("Unable to find a backend server\n");
			goto send_404;
		}
		r = tfw_http_sticky_req_process((TfwHttpMsg *)req);
		if (r < 0) {
			goto send_500;
		} else if (r > 0) {
			/* Response sent, nothing to do */
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			goto conn_put;
		}
		if (tfw_http_adjust_req(req))
			goto send_500;

		/* Add request to the server connection. */
		spin_lock(&conn->msg_qlock);
		list_add_tail(&req->msg.msg_list, &conn->msg_queue);
		spin_unlock(&conn->msg_qlock);

		/* Send request to the server. */
		tfw_connection_send(conn, (TfwMsg *)req);
		goto conn_put;
	}
	BUG();	/* NOTREACHED */

send_404:
	tfw_http_send_404((TfwHttpMsg *)req);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
	return;
send_500:
	tfw_http_send_500((TfwHttpMsg *)req);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
conn_put:
	if (tfw_connection_put(conn))
		tfw_srv_conn_release(conn);
	return;
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
	BUG_ON(off >= skb_len);

	TFW_DBG2("Received %u client data bytes on conn=%p msg=%p\n",
		 skb_len - off, conn, conn->msg);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
	while (data_off < skb_len) {
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
					 "to create request sibling\n");
				return TFW_BLOCK;
			}
		}
		/*
		 * The request should either be stored or released.
		 * Otherwise we lose the reference to it and get a leak.
		 */
		tfw_cache_req_process((TfwHttpReq *)hmreq,
				      tfw_http_req_cache_cb, NULL);

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
	/*
	 * All data in the SKB has been processed, and the processing
	 * is successful. A complete HTTP message has been collected,
	 * and stored or released. Future SKBs should be put in a new
	 * message.
	 *
	 * Otherwise, the function just returns from inside the loop.
	 * conn->msg contains the reference to a message, which can
	 * be used to release it.
	 */
	conn->msg = NULL;

	return r;
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_resp_process(TfwConnection *conn, struct sk_buff *skb,
		      unsigned int off)
{
	int r;
	unsigned int data_off = off;
	TfwHttpMsg *hmreq, *hmresp = (TfwHttpMsg *)conn->msg;

	BUG_ON(!hmresp);

	TFW_DBG2("received %u server data bytes on conn=%p msg=%p\n",
		skb->len - off, conn, hmresp);

	r = ss_skb_process(skb, &data_off, tfw_http_parse_resp, hmresp);
	hmresp->msg.len += data_off - off;

	TFW_DBG2("response parsed: len=%u parsed=%d res=%d\n",
		skb->len - off, data_off - off, r);

	switch (r) {
	default:
		TFW_ERR("Unrecognized HTTP response "
			"parser return code, %d\n", r);
		BUG();
	case TFW_BLOCK:
		/*
		 * The response has not been fully parsed.
		 * We have no choice but report a critical error.
		 * The lower layer will close the connection and release
		 * the response message, and well as all request messages
		 * that went out on this connection and are waiting for
		 * paired response messages.
		 */
		TFW_DBG2("Block invalid HTTP response\n");
		return TFW_BLOCK;
	case TFW_POSTPONE:
		r = tfw_gfsm_move(&hmresp->msg.state,
				  TFW_HTTP_FSM_RESP_CHUNK, skb, off);
		TFW_DBG3("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
		if (r == TFW_BLOCK)
			/*
			 * We don't have a complete response.
			 * We have no choice but report a critical error.
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
	if (r == TFW_BLOCK)
		goto delreq;

	r = tfw_gfsm_move(&hmresp->msg.state,
			  TFW_HTTP_FSM_LOCAL_RESP_FILTER, skb, off);
	TFW_DBG3("TFW_HTTP_FSM_LOCAL_RESP_FILTER return code %d\n", r);
	if (r == TFW_BLOCK)
		goto delreq;

	if (tfw_http_adjust_resp((TfwHttpResp *)hmresp))
		goto delreq;

	/*
	 * Cache adjusted and filtered responses only.
	 * We get responses in the same order as requests,
	 * so we can just pop the first request.
	 */
	spin_lock(&conn->msg_qlock);
	if (unlikely(list_empty(&conn->msg_queue))) {
		spin_unlock(&conn->msg_qlock);
		TFW_WARN("Response w/o request\n");
		goto freeresp;
	}
	hmreq = (TfwHttpMsg *)
		list_first_entry(&conn->msg_queue, TfwMsg, msg_list);
	list_del(&hmreq->msg.msg_list);
	spin_unlock(&conn->msg_qlock);

	r = tfw_http_sticky_resp_process(hmresp, hmreq);
	if (r < 0)
		goto freereq;

	/*
	 * Send the response to client before caching it.
	 * The cache frees the response and the request.
	 * conn->msg will get NULLed in the process.
	 */
	tfw_connection_send(hmreq->conn, (TfwMsg *)hmresp);
	tfw_cache_add((TfwHttpResp *)hmresp, (TfwHttpReq *)hmreq);

	return TFW_PASS;

	/*
	 * We've got a complete response message. However an error
	 * occured on further processing. Such errors are considered
	 * rare. Remove the response and the corresponding (paired)
	 * request, and keep the connection open for data exchange.
	 */
delreq:
	spin_lock(&conn->msg_qlock);
	if (unlikely(list_empty(&conn->msg_queue))) {
		spin_unlock(&conn->msg_qlock);
		TFW_WARN("Response w/o request\n");
		goto freeresp;
	}
	hmreq = (TfwHttpMsg *)
		list_first_entry(&conn->msg_queue, TfwMsg, msg_list);
	list_del(&hmreq->msg.msg_list);
	spin_unlock(&conn->msg_qlock);
freereq:
	tfw_http_conn_msg_free(hmreq);
freeresp:
	/* conn->msg will get NULLed in the process. */
	tfw_http_conn_msg_free(hmresp);

	return TFW_PASS;
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
 * Calculate key of a HTTP request by hashing its URI and Host header.
 *
 * Requests with the same URI and Host are mapped to the same key with
 * high probability. Different keys may be calculated for the same Host and URI
 * when they consist of many chunks.
 */
unsigned long
tfw_http_req_key_calc(TfwHttpReq *req)
{
	if (req->hash)
		return req->hash;

	req->hash = tfw_hash_str(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST])
		    ^ tfw_hash_str(&req->uri_path);

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
