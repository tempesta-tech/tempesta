/**
 *		Tempesta FW
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __TFW_HTTP_SESS_CONF_H__
#define __TFW_HTTP_SESS_CONF_H__

#include "cfg.h"
#include "http_types.h"

extern TfwCfgSpec tfw_http_sess_specs[];

int tfw_http_sess_cfgop_begin(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce);
int tfw_http_sess_cfgop_finish(TfwVhost *vhost, TfwCfgSpec *cs);
void tfw_http_sess_cfgop_cleanup(TfwCfgSpec *cs);
int tfw_http_sess_cfg_finish(TfwVhost *vhost);

void tfw_http_sess_cookie_clean(TfwVhost *vhost);

#endif /* __TFW_HTTP_SESS_CONF_H__ */
