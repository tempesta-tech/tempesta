/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#ifndef __TFW_CACHE_H__
#define __TFW_CACHE_H__

#include "http.h"

int tfw_cache_process(TfwHttpMsg *msg, tfw_http_cache_cb_t action);
bool tfw_cache_is_enabled_or_not_configured(void);
TfwHttpResp *tfw_cache_build_resp_stale(TfwHttpReq *req);
void tfw_cache_put_entry(int node, void *ce);

extern unsigned int cache_default_ttl;

#endif /* __TFW_CACHE_H__ */
