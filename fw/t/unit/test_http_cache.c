/**
 *		Tempesta FW
 *
 * Test for proper cache key calculation when using vhosts and HTTP chains.
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "helpers.h"
#include "http.h"
#include "test.h"
#include "vhost.h"

static TfwHttpReq *test_req;
static TfwVhost test_vhost1, test_vhost2;
static BasicStr test_vhost1_name = { .data = "app1.example.com", .len = 16 };
static BasicStr test_vhost2_name = { .data = "app2.example.com", .len = 16 };

static void
test_http_cache_setup(void)
{
	test_req = test_req_alloc(1);
	EXPECT_NOT_NULL(test_req);

	/* Initialize test vhosts */
	memset(&test_vhost1, 0, sizeof(test_vhost1));
	memset(&test_vhost2, 0, sizeof(test_vhost2));
	test_vhost1.name = test_vhost1_name;
	test_vhost2.name = test_vhost2_name;
}

static void
test_http_cache_teardown(void)
{
	if (test_req) {
		test_req->vhost = NULL;
		test_req_free(test_req);
		test_req = NULL;
	}
}

/**
 * Test that cache key calculation correctly uses vhost name instead of host header.
 */
TEST(http_cache, uses_vhost_not_host)
{
	unsigned long key1, key2;
	TfwStr host;
	TfwStr uri_path;

	/* Set the Host header to a specific value */
	host.data = (void *)"same.host.example.com";
	host.len = 21;
	test_req->host = host;

	/* Set a URI path */
	uri_path.data = (void *)"/test/path";
	uri_path.len = 10;
	test_req->uri_path = uri_path;

	/* Calculate cache key with first vhost */
	test_req->vhost = &test_vhost1;
	test_req->hash = 0; /* Clear cached hash */
	key1 = tfw_http_req_key_calc(test_req);

	/* Now change to second vhost, same Host header */
	test_req->vhost = &test_vhost2;
	test_req->hash = 0; /* Clear cached hash */
	key2 = tfw_http_req_key_calc(test_req);

	/* Keys should be different because vhost names are different */
	EXPECT_NE(key1, key2);
}

/**
 * Test health monitoring requests are handled correctly.
 */
TEST(http_cache, health_monitor)
{
	unsigned long key1, key2, key3;
	TfwStr host_header;
	TfwStr uri_path;

	host_header.data = (void *)"any.host.com";
	host_header.len = 12;
	test_req->host = host_header;

	uri_path.data = (void *)"/health";
	uri_path.len = 7;
	test_req->uri_path = uri_path;

	__set_bit(TFW_HTTP_B_HMONITOR, test_req->flags);

	/* Key with vhost1 */
	test_req->vhost = &test_vhost1;
	test_req->hash = 0;
	key1 = tfw_http_req_key_calc(test_req);

	/* Key with vhost2 (different vhost name) */
	test_req->vhost = &test_vhost2;
	test_req->hash = 0;
	key2 = tfw_http_req_key_calc(test_req);

	/* Key with vhost = NULL (as per original test intent) */
	test_req->vhost = NULL;
	test_req->hash = 0;
	key3 = tfw_http_req_key_calc(test_req);

	/* Keys should be the same since only uri_path is used for HM requests */
	EXPECT_EQ(key1, key2);
	EXPECT_EQ(key1, key3);

	/* Clear the flag for next tests */
	__clear_bit(TFW_HTTP_B_HMONITOR, test_req->flags);
}

TEST_SUITE(http_cache)
{
	TEST_SETUP(test_http_cache_setup);
	TEST_TEARDOWN(test_http_cache_teardown);

	TEST_RUN(http_cache, uses_vhost_not_host);
	TEST_RUN(http_cache, health_monitor);
}
