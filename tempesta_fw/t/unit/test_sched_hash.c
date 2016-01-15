/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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

#include "http_msg.h"

#include "helpers.h"
#include "sched_helper.h"
#include "test.h"
#include "kallsyms_helper.h"

char req_str1[] = "GET http://natsys-lab.com/ HTTP/1.1\r\n\r\n";
char req_str2[] = "GET http://natsys-lab.com:8080/ HTTP/1.1\r\n\r\n";
char req_str3[] = "GET http://natsys-lab.com/foo/ HTTP/1.1\r\n\r\n";
char req_str4[] = "GET http://natsys-lab.com:8080/cgi-bin/show.pl?entry=tempesta HTTP/1.1\r\n\r\n";

char *req_strs[] = {
	req_str1,
	req_str2,
	req_str3,
	req_str4,
};
size_t req_strs_size = sizeof(req_strs) / sizeof(req_strs[0]);

static int (*tfw_http_parse_req_ptr)(void *req_data, unsigned char *data, size_t len);

TEST(tfw_sched_hash, sg_empty)
{
	int i, j;

	TfwSrvGroup *sg = test_create_sg("test", "hash");

	for (i = 0; i < req_strs_size; ++i) {
		for (j = 0; j < 3; ++j) {
			TfwConnection *conn;
			TfwHttpReq *req = test_req_alloc(strlen(req_strs[i]));

			tfw_http_parse_req_ptr(req, req_strs[i], strlen(req_strs[i]));

			conn = sg->sched->sched_srv((TfwMsg *)req, sg);
			EXPECT_TRUE(conn == NULL);

			test_req_free(req);
		}
	}

	test_sg_release_all();
}

TEST(tfw_sched_hash, one_srv_in_sg_and_zero_conn)
{
	int i, j;

	TfwSrvGroup *sg = test_create_sg("test", "hash");
	test_create_srv("127.0.0.1", sg);

	for (i = 0; i < req_strs_size; ++i) {
		for (j = 0; j < 3; ++j) {
			TfwConnection *conn;
			TfwHttpReq *req = test_req_alloc(strlen(req_strs[i]));

			tfw_http_parse_req(req, req_strs[i], strlen(req_strs[i]));

			conn = sg->sched->sched_srv((TfwMsg *)req, sg);
			EXPECT_TRUE(conn == NULL);

			test_req_free(req);
		}
	}

	test_sg_release_all();
}

TEST(tfw_sched_hash, one_srv_in_sg_and_max_conn)
{
	int i, j;

	TfwSrvGroup *sg = test_create_sg("test", "hash");
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_SRV_MAX_CONN; ++i) {
		test_create_conn((TfwPeer *)srv);
	}
	sg->sched->update_grp(sg);

	for (i = 0; i < req_strs_size; ++i) {
		TfwConnection *s = NULL;

		for (j = 0; j < 3 * TFW_SRV_MAX_CONN; ++j) {
			TfwConnection *conn;
			TfwHttpReq *req = test_req_alloc(strlen(req_strs[i]));

			tfw_http_parse_req(req, req_strs[i], strlen(req_strs[i]));

			conn = sg->sched->sched_srv((TfwMsg *)req, sg);
			if (!s) {
				s = conn;
			} else {
				EXPECT_TRUE(conn == s);
			}

			test_req_free(req);
			tfw_connection_put(conn);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_hash, max_srv_in_sg_and_zero_conn)
{
	int i, j;

	TfwSrvGroup *sg = test_create_sg("test", "hash");

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		test_create_srv("127.0.0.1", sg);
	}

	for (i = 0; i < req_strs_size; ++i) {
		for (j = 0; j < 2 * TFW_SG_MAX_SRV; ++j) {
			TfwConnection *conn;
			TfwHttpReq *req = test_req_alloc(strlen(req_strs[i]));

			tfw_http_parse_req(req, req_strs[i], strlen(req_strs[i]));

			conn = sg->sched->sched_srv((TfwMsg *)req, sg);
			EXPECT_TRUE(conn == NULL);

			test_req_free(req);
		}
	}

	test_sg_release_all();
}

TEST(tfw_sched_hash, max_srv_in_sg_and_max_conn)
{
	int i, j;

	TfwSrvGroup *sg = test_create_sg("test", "hash");

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			test_create_conn((TfwPeer *)srv);
		}
	}
	sg->sched->update_grp(sg);

	for (i = 0; i < req_strs_size; ++i) {
		TfwConnection *s = NULL;

		for (j = 0; j < 3 * TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN; ++j) {
			TfwConnection *conn;
			TfwHttpReq *req = test_req_alloc(strlen(req_strs[i]));

			tfw_http_parse_req(req, req_strs[i], strlen(req_strs[i]));

			conn = sg->sched->sched_srv((TfwMsg *)req, sg);
			if (!s) {
				s = conn;
			} else {
				EXPECT_TRUE(conn == s);
			}

			test_req_free(req);
			tfw_connection_put(conn);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST_SUITE(sched_hash)
{
	sched_helper_init();

	tfw_http_parse_req_ptr = get_sym_ptr("tfw_http_parse_req");
	BUG_ON(tfw_http_parse_req_ptr == NULL);

	TEST_RUN(tfw_sched_hash, sg_empty);
	TEST_RUN(tfw_sched_hash, one_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_hash, one_srv_in_sg_and_max_conn);
	TEST_RUN(tfw_sched_hash, max_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_hash, max_srv_in_sg_and_max_conn);
}
