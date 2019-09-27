/*
 *		Tempesta FW
 *
 * Copyright (C) 2017-2018 Tempesta Technologies, Inc.
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
 */

#define STICKY_NAME_MAXLEN	(32)
#define STICKY_OPT_MAXLEN	(256)


/**
 * JavaScript challenge.
 *
 * To pass JS challenge client must repeat it's request in exact time frame
 * specified by JS code.
 *
 * @body	- body (html with JavaScript code);
 * @delay_min	- minimal timeout client must wait before repeat the request,
 *		  in jiffies;
 * @delay_limit	- maximum time required to deliver request form a client to the
 *		  Tempesta, in jiffies;
 * @delay_range	- time interval starting after @delay_min for a client to make
 *		  a repeated request, in msecs;
 * @st_code	- status code for response with JS challenge;
 */
typedef struct {
	TfwStr			body;
	unsigned long		delay_min;
	unsigned long		delay_limit;
	unsigned long		delay_range;
	unsigned short		st_code;
} TfwCfgJsCh;

/**
 * Sticky cookie configuration.
 *
 * @shash		- Secret server value to generate reliable client
 *			  identifiers.
 * @name		- name of sticky cookie;
 * @name_eq		- @name plus "=" to make some operations faster;
 * @js_challenge	- JS challenge configuration;
 * @redirect_code	- redirect status code for set-cookie and js challenge
 *			  responses;
 * @sess_lifetime	- session lifetime in seconds;
 * @max_misses		- maximum count of requests with invalid cookie;
 * @tmt_sec		- maximum time (in seconds) to wait the request
 *			  with valid cookie;
 * @learn		- learn backend cookie instead of adding our own
 *			  session cookie;
 * @enforce		- don't forward requests to backend unless session
 *			  cookie is set;
 */
struct tfw_http_cookie_t {
	struct crypto_shash	*shash;
	char			key[SHA1_DIGEST_SIZE];
	char			sticky_name[STICKY_NAME_MAXLEN + 1];
	char			options_str[STICKY_OPT_MAXLEN];
	TfwStr			options;
	TfwStr			name;
	TfwStr			name_eq;
	TfwCfgJsCh		*js_challenge;
	unsigned int		redirect_code;
	unsigned int		sess_lifetime;
	unsigned int		max_misses;
	unsigned int		tmt_sec;
	unsigned int		learn : 1,
				enforce : 1;
};

/**
 * HTTP session descriptor.
 *
 * @hmac	- crypto hash from values of an HTTP request;
 * @hentry	- hash list entry for all sessions hash;
 * @users	- the session use counter;
 * @ts		- timestamp for the client's session;
 * @expire	- expiration time for the session;
 * @vhost	- vhost for the session if known;
 * @srv_conn	- upstream server connection for the session;
 * @lock	- protects @vhost and @srv_conn;
 */
struct tfw_http_sess_t {
	unsigned char		hmac[SHA1_DIGEST_SIZE];
	struct hlist_node	hentry;
	atomic_t		users;
	unsigned long		ts;
	unsigned long		expires;
	TfwVhost		*vhost;
	TfwSrvConn		*srv_conn;
	rwlock_t		lock;
};

#define STICKY_KEY_MAXLEN	SHA1_DIGEST_SIZE

enum {
	/* Internal error, may be any number < 0. */
	TFW_HTTP_SESS_FAILURE = -1,
	/* Session successfully obtained. */
	TFW_HTTP_SESS_SUCCESS = 0,
	/* Can't obtain session: new client; a redirection message sent. */
	TFW_HTTP_SESS_REDIRECT_NEED,
	/* Sticky cookie violated, client must be blocked. */
	TFW_HTTP_SESS_VIOLATE,
	/* JS challenge enabled, but request is not challengable. */
	TFW_HTTP_SESS_JS_NOT_SUPPORTED
};

int tfw_http_sess_obtain(TfwHttpReq *req);
int tfw_http_sess_req_process(TfwHttpReq *req);
int tfw_http_sess_resp_process(TfwHttpResp *resp);
void tfw_http_sess_put(TfwHttpSess *sess);
void tfw_http_sess_pin_vhost(TfwHttpSess *sess, TfwVhost *vhost);

void tfw_http_sess_redir_enable(void);
bool tfw_http_sess_max_misses(void);
unsigned int tfw_http_sess_mark_size(void);
const TfwStr *tfw_http_sess_mark_name(void);

/* Sticky sessions scheduling routines. */
TfwSrvConn *tfw_http_sess_get_srv_conn(TfwMsg *msg);

#endif /* __TFW_HTTP_SESS_H__ */
