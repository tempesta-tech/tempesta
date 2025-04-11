/**
 *		Tempesta FW
 *
 * Test for proper cache key calculation when using vhosts and HTTP chains.
 *
 * Copyright (C) 2023-2025 Tempesta Technologies, Inc.
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

#include "helpers.h"
#include "http.h"
#include "test.h"
#include "vhost.h"

/**
 * Test that cache key calculation correctly uses vhost name instead of host header.
 */
TEST(http_cache_key, uses_vhost_not_host)
{
	TfwHttpReq *req;
	unsigned long key1, key2;
	TfwVhost vhost1, vhost2;
	BasicStr vhost1_name = { .data = "app1.example.com", .len = 15 };
	BasicStr vhost2_name = { .data = "app2.example.com", .len = 15 };
	
	/* Create request with Host header */
	req = test_req_alloc(1);
	EXPECT_NOT_NULL(req);
	if (!req)
		return;
	
	/* Initialize test vhosts */
	memset(&vhost1, 0, sizeof(vhost1));
	memset(&vhost2, 0, sizeof(vhost2));
	vhost1.name = vhost1_name;
	vhost2.name = vhost2_name;
	
	/* Set the Host header to a specific value */
	TfwStr host = { 
		.data = (void *)"same.host.example.com",
		.len = 19
	};
	req->host = host;
	
	/* Set a URI path */
	TfwStr uri_path = {
		.data = (void *)"/test/path",
		.len = 10
	};
	req->uri_path = uri_path;
	
	/* Calculate cache key with first vhost */
	req->vhost = &vhost1;
	req->hash = 0; /* Clear cached hash */
	key1 = tfw_http_req_key_calc(req);
	
	/* Now change to second vhost, same Host header */
	req->vhost = &vhost2;
	req->hash = 0; /* Clear cached hash */
	key2 = tfw_http_req_key_calc(req);
	
	/* Keys should be different because vhost names are different */
	EXPECT_NE(key1, key2);
	
	//test_req_free(req); // TODO: kernel stuck here, why?
}

/**
 * Test that the cache key is the same even if the Host header changes
 * but the vhost remains the same (which is what happens with HTTP chains)
 */
TEST(http_cache_key, stable_with_http_chains)
{
	TfwHttpReq *req;
	unsigned long key1, key2;
	TfwVhost vhost;
	BasicStr vhost_name = { .data = "app2.example.com", .len = 15 };
	
	/* Create request with Host header */
	req = test_req_alloc(1);
	EXPECT_NOT_NULL(req);
	if (!req)
		return;
	
	/* Initialize test vhost */
	memset(&vhost, 0, sizeof(vhost));
	vhost.name = vhost_name;
	
	/* Set a URI path */
	TfwStr uri_path = {
		.data = (void *)"/test/path",
		.len = 10
	};
	req->uri_path = uri_path;
	
	/* Set the first Host header */
	TfwStr host1 = { 
		.data = (void *)"app1.example.com",
		.len = 15
	};
	req->host = host1;
	
	/* Set vhost to "app2" (as would happen with HTTP chains) */
	req->vhost = &vhost;
	req->hash = 0; /* Clear cached hash */
	key1 = tfw_http_req_key_calc(req);
	
	/* Change Host header but keep same vhost */
	TfwStr host2 = { 
		.data = (void *)"app3.example.com",
		.len = 15
	};
	req->host = host2;
	req->hash = 0; /* Clear cached hash */
	key2 = tfw_http_req_key_calc(req);
	
	/* Keys should be the same because vhost name is the same */
	EXPECT_EQ(key1, key2);
	
	//test_req_free(req); // TODO: kernel stuck here, why?
}

/**
 * Test fallback to host header when vhost is NULL
 */
TEST(http_cache_key, fallback_to_host)
{
	TfwHttpReq *req;
	unsigned long key1, key2;
	
	/* Create request with Host header */
	req = test_req_alloc(1);
	EXPECT_NOT_NULL(req);
	if (!req)
		return;
	
	/* Set a URI path */
	TfwStr uri_path = {
		.data = (void *)"/test/path",
		.len = 10
	};
	req->uri_path = uri_path;
	
	/* Set the first Host header */
	TfwStr host1 = { 
		.data = (void *)"app1.example.com",
		.len = 15
	};
	req->host = host1;
	
	/* No vhost */
	req->vhost = NULL;
	req->hash = 0; /* Clear cached hash */
	key1 = tfw_http_req_key_calc(req);
	
	/* Change Host header, still no vhost */
	TfwStr host2 = { 
		.data = (void *)"app2.example.com",
		.len = 15
	};
	req->host = host2;
	req->hash = 0; /* Clear cached hash */
	key2 = tfw_http_req_key_calc(req);
	
	/* Keys should be different because host headers are different */
	EXPECT_NE(key1, key2);
	
	//test_req_free(req); // TODO: kernel stuck here, why?
}

/**
 * Test health monitoring requests are handled correctly
 */
TEST(http_cache_key, health_monitor)
{
	TfwHttpReq *req;
	unsigned long key1, key2;
	TfwVhost vhost;
	BasicStr vhost_name = { .data = "app2.example.com", .len = 15 };
	
	/* Create request with Host header */
	req = test_req_alloc(1);
	EXPECT_NOT_NULL(req);
	if (!req)
		return;
	
	/* Initialize test vhost */
	memset(&vhost, 0, sizeof(vhost));
	vhost.name = vhost_name;
	
	/* Set the Host header and URI */
	TfwStr host = { 
		.data = (void *)"app1.example.com",
		.len = 15
	};
	req->host = host;
	
	TfwStr uri_path = {
		.data = (void *)"/health",
		.len = 7
	};
	req->uri_path = uri_path;
	
	/* Set health monitor flag */
	__set_bit(TFW_HTTP_B_HMONITOR, req->flags);
	
	/* Compute key with vhost */
	req->vhost = &vhost;
	req->hash = 0;
	key1 = tfw_http_req_key_calc(req);
	
	/* Compute key without vhost */
	req->vhost = NULL;
	req->hash = 0;
	key2 = tfw_http_req_key_calc(req);
	
	/* Keys should be the same since only uri_path is used for HM requests */
	EXPECT_EQ(key1, key2);
	
	//test_req_free(req); // TODO: kernel stuck here, why?
}

TEST_SUITE(http_cache_key)
{
	TEST_RUN(http_cache_key, uses_vhost_not_host);
	TEST_RUN(http_cache_key, stable_with_http_chains);
	TEST_RUN(http_cache_key, fallback_to_host);
	TEST_RUN(http_cache_key, health_monitor);
}
