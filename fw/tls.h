/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#ifndef __TFW_TLS_H__
#define __TFW_TLS_H__

#include "ttls.h"
#include "http_types.h"
#include "str.h"

void tfw_tls_cfg_require(void);
void tfw_tls_cfg_configured(bool global);
void tfw_tls_set_allow_any_sni(bool match);
int tfw_tls_cfg_alpn_protos(const char *cfg_str);
int tfw_tls_encrypt(struct sock *sk, struct sk_buff *skb, unsigned int mss_now,
                    unsigned int limit);

typedef struct tfw_conn_t TfwConn;
int tfw_tls_connection_recv(TfwConn *conn, struct sk_buff *skb);
bool tfw_tls_get_allow_any_sni_reconfig(void);

TfwVhost* tfw_tls_find_vhost_by_name(BasicStr *srv_name);

#endif /* __TFW_TLS_H__ */
