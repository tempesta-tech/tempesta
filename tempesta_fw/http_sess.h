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

typedef struct {
	TfwSrvConn		*srv_conn;
	TfwSrvGroup		*main_sg;
	TfwSrvGroup		*backup_sg;
	rwlock_t		conn_lock;
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


int tfw_http_sess_obtain(TfwHttpReq *req);
int tfw_http_sess_resp_process(TfwHttpResp *resp, TfwHttpReq *req);
void tfw_http_sess_put(TfwHttpSess *sess);

#endif /* __TFW_HTTP_SESS_H__ */
