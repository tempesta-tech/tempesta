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
  * @conn	- last used connection of primary or backup server;
  * @lock	- protect for the whole struct.
  *
  * Sticky session cannot be pinned to more than server in the same time.
  * Server group @sg *must* have either exactly one backup server group listed
  * in 'sched_http_rules' (http_scheduler) or no backups. All other variants
  * meants that session will be pinned to more than one server in the end.
  *
  */
typedef struct {
	struct list_head	list;
	TfwSrvConn		*conn;
	u_int			use_backup;
	rwlock_t		lock;
} TfwStickyConn;

int tfw_http_sess_obtain(TfwHttpReq *req);
int tfw_http_sess_resp_process(TfwHttpResp *resp, TfwHttpReq *req);
void tfw_http_sess_put(TfwHttpSess *sess);

TfwStickyConn *tfw_http_sess_get_conn(TfwHttpReq *req, TfwSrvGroup *sg);

#endif /* __TFW_HTTP_SESS_H__ */
