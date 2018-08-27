/*
 *		Tempesta FW
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_SESS_H__
#define __TFW_HTTP_SESS_H__

#include "http.h"

/**
 * HTTP session pinning.
 *
 * An HTTP session may be pinned to a server from main or backup group
 * according to a match rules defined in HTTP scheduler. But when live
 * reconfiguration happens, the next situations may appear:
 *
 * 1. Session pinning is switched to 'enable'. Nothing special, use general
 * scheduling routine to obtain target server and pin the session to it.
 *
 * 2. Session pinning is switched to 'disable'. Keep using pinned server until
 * session is expired. (Alternative: unpin session from a server and use generic
 * scheduling algorithm.)
 *
 * 3. A new server is added to main/backup group. New sessions will be
 * eventually pinned to the server.
 *
 * 4. A server is removed from main/backup group. Re-pin sessions of that
 * server to others using generic scheduling routine if allowed. Otherwise
 * mark the session as expired, since the pinned server instance will never
 * go up.
 *
 * 5. Main and backup group is removed from new configuration. Same as p. 4.
 *
 * 6. Main and backup group are no more interchangeable; according to the new
 * HTTP match rules sessions must be pinned to completely other server groups.
 * This cases cannot be deduced during live reconfiguration, manual session
 * removing is required. End user should avoid such configurations.
 *
 * @srv_conn	- last used connection;
 * @lock	- protects whole @TfwStickyConn;
 */
typedef struct {
	TfwSrvConn		*srv_conn;
	rwlock_t		lock;
} TfwStickyConn;

/**
 * HTTP session descriptor.
 *
 * @hmac	- crypto hash from values of an HTTP request;
 * @hentry	- hash list entry for all sessions hash;
 * @users	- the session use counter;
 * @ts		- timestamp for the client's session;
 * @expire	- expiration time for the session;
 * @st_conn	- upstream server connection servicing the session;
 */
struct tfw_http_sess_t {
	unsigned char		hmac[SHA1_DIGEST_SIZE];
	struct hlist_node	hentry;
	atomic_t		users;
	unsigned long		ts;
	unsigned long		expires;
	TfwStickyConn		st_conn;
};

enum {
	/* Internal error, may be any number < 0. */
	TFW_HTTP_SESS_FAILURE = -1,
	/* Session successfully obtained. */
	TFW_HTTP_SESS_SUCCESS = 0,
	/* Can't obtain session: new client; a redirection message sent. */
	TFW_HTTP_SESS_REDIRECT_SENT,
	/* Sticky cookie violated, client must be blocked. */
	TFW_HTTP_SESS_VIOLATE,
	/* JS challenge enabled, but request is not challengable. */
	TFW_HTTP_SESS_JS_NOT_SUPPORTED
};

int tfw_http_sess_obtain(TfwHttpReq *req);
int tfw_http_sess_req_process(TfwHttpReq *req);
int tfw_http_sess_resp_process(TfwHttpResp *resp);
void tfw_http_sess_put(TfwHttpSess *sess);

bool tfw_http_sess_max_misses(void);
unsigned int tfw_http_sess_mark_size(void);
TfwStr *tfw_http_sess_mark_name(void);

/* Sticky sessions scheduling routines. */
TfwSrvConn *tfw_http_sess_get_srv_conn(TfwMsg *msg);

void tfw_http_sess_use_sticky_sess(bool use);

#endif /* __TFW_HTTP_SESS_H__ */
