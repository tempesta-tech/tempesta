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
 * Sticky sessions configuration.
 */
typedef struct {
	u_int		enabled : 1,
			allow_failover : 1;
} TfwCfgStickySess;

/**
  * List item of server connections binded to HTTP session.
  *
  * @list	- member in the list of connections;
  * @sg		- target server group;
  * @conn	- last used connection of primary or backup server;
  * @lock	- protect for the whole struct.
  */
typedef struct {
	struct list_head	list;
	TfwSrvGroup		*sg;
	TfwSrvConn		*conn;
	rwlock_t		lock;
} TfwHttpSessConn;

int tfw_http_sess_obtain(TfwHttpReq *req);
int tfw_http_sess_resp_process(TfwHttpResp *resp, TfwHttpReq *req);
void tfw_http_sess_put(TfwHttpSess *sess);

TfwHttpSessConn *tfw_http_sess_get_conn(TfwHttpReq *req, TfwSrvGroup *sg);

#endif /* __TFW_HTTP_SESS_H__ */
