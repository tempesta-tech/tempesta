/**
 *		Tempesta FW
 *
 * Copyright (C) 2022 Tempesta Technologies, Inc.
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
#ifndef __TFW_WS_H__
#define __TFW_WS_H__

typedef struct tfw_conn_t TfwConn;

int tfw_ws_msg_process(TfwConn *conn, struct sk_buff *skb);
TfwConn *tfw_ws_srv_new_steal_sk(TfwSrvConn *srv_conn);
void tfw_ws_cli_mod_timer(TfwCliConn *conn);

#endif /* __TFW_WS_H__ */
