/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2021 Tempesta Technologies, Inc.
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

#include <net/tls_hs.h>

void tfw_tls_cfg_require(void);
void tfw_tls_cfg_configured(bool global);
void tfw_tls_match_any_sni_to_dflt(bool match);
int tfw_tls_cfg_alpn_protos(const char *cfg_str, bool *deprecated);
void tfw_tls_free_alpn_protos(void);
int tfw_tls_encrypt(struct sock *sk, struct sk_buff *skb, unsigned int limit);

int tfw_tls_msg_process(struct sock *sk, struct sk_buff *skb);


#endif /* __TFW_TLS_H__ */
