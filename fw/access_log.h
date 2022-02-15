/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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
#ifndef __TFW_ACCESS_LOG_H__
#define __TFW_ACCESS_LOG_H__

#include "http_types.h"

#define TODO_LOG_CONN(resp)  pr_info("%s:%d (%s): conn => %p, conn->peer => %p", &__FILE__[28], __LINE__, __FUNCTION__, (resp)->conn, (resp)->conn ? (resp)->conn->peer : NULL);
void do_access_log_req(TfwHttpReq *req, int status, unsigned long content_length);
void do_access_log(TfwHttpResp *resp);

#endif /* __TFW_ACCESS_LOG_H__ */
