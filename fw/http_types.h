/**
 *		Tempesta FW
 *
 * Copyright (C) 2018-2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_TYPES_H__
#define __TFW_HTTP_TYPES_H__

enum {
        /* Common flags for requests and responses. */
        TFW_HTTP_FLAGS_COMMON   = 0,
        /*
         * Connection management flags.
         *
         * CONN_CLOSE: the connection is to be closed after response is
         * forwarded to the client. Set if:
         * - 'Connection:' header contains 'close' term;
         * - there is no possibility to serve further requests from the same
         * connection due to errors or protocol restrictions.
         *
         * CONN_KA: 'Connection:' header contains 'keep-alive' term. The flag
         * is not set for HTTP/1.1 connections which are persistent by default.
         * CONN_EXTRA: 'Connection:' header contains additional terms.
         *
         * CONN_CLOSE and CONN_KA flags are mutual exclusive.
         */
        TFW_HTTP_B_CONN_CLOSE   = TFW_HTTP_FLAGS_COMMON,
        /*
         * This flag is set only together with previos one.
         * Typically we close connection gracefully with
         * TCP shutdown, but in case of attack, we should
         * do it immediately using tcp_close.
         */
        TFW_HTTP_B_CONN_CLOSE_FORCE,
        TFW_HTTP_B_CONN_KA,
        TFW_HTTP_B_CONN_UPGRADE,
        TFW_HTTP_B_CONN_EXTRA,
        /* Message is a websocket upgrade request */
        TFW_HTTP_B_UPGRADE_WEBSOCKET,
        /* Message upgrade header contains extra fields */
        TFW_HTTP_B_UPGRADE_EXTRA,
        /*
         * Chunked is last transfer encoding.
         * It is important to notice that there is a valid case
         * when we receive chunked encoded response with empty
         * body on HEAD request.
         */
        TFW_HTTP_B_CHUNKED,
        /* Chunked in the middle of applied transfer encodings. */
        TFW_HTTP_B_CHUNKED_APPLIED,
        /* Message has chunked trailer headers part. */
        TFW_HTTP_B_CHUNKED_TRAILER,
        /* Message has transfer encodings other than chunked. */
        TFW_HTTP_B_TE_EXTRA,
        /* The message body is limited by the connection closing. */
        TFW_HTTP_B_UNLIMITED,
        /* Media type is multipart/form-data. */
        TFW_HTTP_B_CT_MULTIPART,
        /* Multipart/form-data request has a boundary parameter. */
        TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
        /* Content-length header was parsed. */
        TFW_HTTP_B_REQ_CONTENT_LENGTH_PARSED,
        /* Singular header presents more than once. */
        TFW_HTTP_B_FIELD_DUPENTRY,
        /* Message headers are fully parsed */
        TFW_HTTP_B_HEADERS_PARSED,
        /* Message is fully parsed */
        TFW_HTTP_B_FULLY_PARSED,
        /* Message has HTTP/2 format. */
        TFW_HTTP_B_H2,
        /*
         * Message has all mandatory pseudo-headers
         * (applicable for HTTP/2 mode only).
         */
        TFW_HTTP_B_H2_HDRS_FULL,

        /* Request flags. */
        TFW_HTTP_FLAGS_REQ,
        /* Sticky cookie is found and verified. */
        TFW_HTTP_B_HAS_STICKY   = TFW_HTTP_FLAGS_REQ,
        /* Request fitted no cache cookie rule */
        TFW_HTTP_B_CHAIN_NO_CACHE,
        /* Request is non-idempotent. */
        TFW_HTTP_B_NON_IDEMP,
        /* Request stated 'Accept: text/html' header */
        TFW_HTTP_B_ACCEPT_HTML,
        /* Request is created by HTTP health monitor. */
        TFW_HTTP_B_HMONITOR,
        /* Client was disconnected, drop the request. */
        TFW_HTTP_B_REQ_DROP,
        /* Request is PURGE with an 'X-Tempesta-Cache: get' header. */
        TFW_HTTP_B_PURGE_GET,
        /* Need strip 1 leading CR */
        TFW_HTTP_B_NEED_STRIP_LEADING_CR,
        /* Need strip 1 leading LF */
        TFW_HTTP_B_NEED_STRIP_LEADING_LF,
        /*
         * Request should be challenged, but requested resourse
         * is non-challengeable. Try to service such request
         * from cache.
         */
        TFW_HTTP_B_JS_NOT_SUPPORTED,
        /*
         * Response is fully processed and ready to be
         * forwarded to the client.
         */
        TFW_HTTP_B_REQ_RESP_READY,

	/*
	 * Rewrite method from HEAD to GET. Applicable only to request that can
	 * be employed from cache.
	 */
	TFW_HTTP_B_REQ_HEAD_TO_GET,

	/* Request contains `Expect: 100-continue`. */
	TFW_HTTP_B_EXPECT_CONTINUE,
	/* 100-continue response has been queued. */
	TFW_HTTP_B_CONTINUE_QUEUED,

        /* Response flags */
        TFW_HTTP_FLAGS_RESP,
        /* Response has no body. */
        TFW_HTTP_B_VOID_BODY    = TFW_HTTP_FLAGS_RESP,
        /* Response has header 'Date:'. */
        TFW_HTTP_B_HDR_DATE,
        /* Response has header 'Last-Modified:'. */
        TFW_HTTP_B_HDR_LMODIFIED,
        /*
         * Response has header 'Etag: ' and this header is
         * not enclosed in double quotes.
         */
        TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES,
        /* Request URI is absolute (HTTP/1.x only) */
        TFW_HTTP_B_ABSOLUTE_URI,
        /*
         * This is the error response, connection
         * will be closed after sending it.
         */
        TFW_HTTP_B_CLOSE_ERROR_RESPONSE,

	/* This is 100-continue response. */
	TFW_HTTP_B_CONTINUE_RESP,

        _TFW_HTTP_FLAGS_NUM
};

/* Forward declaration of common HTTP types. */
typedef struct tfw_http_sess_t		TfwHttpSess;
typedef struct tfw_http_msg_t		TfwHttpMsg;
typedef struct tfw_http_req_t		TfwHttpReq;
typedef struct tfw_http_resp_t		TfwHttpResp;
typedef struct tfw_vhost_t		TfwVhost;
typedef struct tfw_hdr_mods_desc_t	TfwHdrModsDesc;
typedef struct tfw_hdr_mods_t		TfwHdrMods;
typedef struct frang_global_cfg_t	FrangGlobCfg;
typedef struct frang_vhost_cfg_t	FrangVhostCfg;
typedef struct tfw_http_cookie_t	TfwStickyCookie;
typedef struct tfw_http_stream_t        TfwStream;

#endif /* __TFW_HTTP_TYPES_H__ */
