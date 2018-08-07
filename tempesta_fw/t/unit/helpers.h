/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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

/* These functions help to create fake HTTP messages for testing without
 * involving complicated stuff like sk_buff manipulations. */
TfwHttpReq *test_req_alloc(size_t data_len);
void test_req_free(TfwHttpReq *req);
TfwHttpResp *test_resp_alloc(size_t data_len);
void test_resp_free(TfwHttpResp *req);

/* Helpers to start/stop minimum 'http_sticky' functionality, necessary
 * for some tests (e.g. in 'test_http_parser'). */
int test_helper_sticky_start(const char *name, unsigned int misses);
void test_helper_sticky_stop(void);

#endif /* __TFW_TEST_HELPER_H__ */
