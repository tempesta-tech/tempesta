/**
 *		Tempesta FW
 *
 * This file contains utils that help to test certain Tempesta FW modules.
 * They implement things like stubbing, mocking, generating data for testing.
 *
 * Actually things contained in this file are wrong a bit.
 * Good code tends to have most of the logic in pure stateless loosely-coupled
 * well-isolated functions that may be tested without faking any state.
 * But this is not reachable most of the time, especially when performance is
 * a goal and you have to build the architecture keeping it in mind.
 * So over time, we expect to see a decent amount of helpers here.
 *
 * These things are specific to Tempesta FW, so they are located here,
 * and generic testing functions/macros are located in test.c/test.h
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include "http_msg.h"

static TfwConnection conn_req, conn_resp;

TfwHttpReq *
test_req_alloc(size_t data_len)
{
	TfwHttpReq *req;
	TfwMsgIter it;

	/* Actually there were more code here, mostly it was copy-paste from
	 * tfw_http_msg_alloc(). It is removed because we need to test how it
	 * initializes the message and we would not like to test the copy-paste.
	 */
	req = (TfwHttpReq *)tfw_http_msg_create(NULL, &it, Conn_HttpClnt,
						data_len);
	BUG_ON(!req);

	memset(&conn_req, 0, sizeof(TfwConnection));
	tfw_connection_init(&conn_req);
	conn_req.proto.type = Conn_HttpClnt;
	req->conn = &conn_req;

	return req;
}

void
test_req_free(TfwHttpReq *req)
{
	/* In tests we are stricter: we don't allow to free a NULL pointer
	 * to be sure exactly what we are free'ing and to catch bugs early. */
	BUG_ON(!req);

	tfw_http_msg_free((TfwHttpMsg *)req);
}

TfwHttpResp *
test_resp_alloc(size_t data_len)
{
	TfwHttpResp *resp;
	TfwMsgIter it;

	resp = (TfwHttpResp *)tfw_http_msg_create(NULL, &it, Conn_HttpSrv,
						  data_len);
	BUG_ON(!resp);

	memset(&conn_resp, 0, sizeof(TfwConnection));
	tfw_connection_init(&conn_req);
	conn_resp.proto.type = Conn_HttpSrv;
	resp->conn = &conn_resp;

	return resp;
}

void
test_resp_free(TfwHttpResp *resp)
{
	BUG_ON(!resp);
	tfw_http_msg_free((TfwHttpMsg *)resp);
}
