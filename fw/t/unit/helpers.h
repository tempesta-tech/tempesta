/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_TEST_HELPER_H__
#define __TFW_TEST_HELPER_H__

#include "http.h"

/*
 * These functions help to create fake HTTP messages for testing without
 * involving complicated stuff like sk_buff manipulations.
 */
TfwHttpReq *test_req_alloc(size_t data_len);
void test_req_free(TfwHttpReq *req);
TfwHttpResp *test_resp_alloc(size_t data_len);
TfwHttpResp *test_resp_alloc_no_data(void);
void test_resp_free(TfwHttpResp *req);

#endif /* __TFW_TEST_HELPER_H__ */
