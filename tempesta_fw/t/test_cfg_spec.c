/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include "../cfg_spec.h"
#include "test.h"

static const char *raw_cfg =
"http {						"
"	index index.php index.html index.htm;	"
"	tcp_nopush   on;			"
"						"
"	cache_size 8192;			"
"	cache_size auto;			"
"						"
"	server {				"
"		listen :80;			"
"		server_name example.com;	"
"						"
"		location / {			"
"			root /var/www;		"
"		}				"
"	}					"
"						"
"	upstream us {				"
"		server 10.0.0.1:8080 weight=10;	"
"		server 10.0.0.2:8080 weight=5;	"
"		server 10.0.0.3:8080;		"
"	}					"
"						"
"	server {				"
"		listen :8080 [::0]:8080;	"
"		server_name balancing;		"
"						"
"		location / {			"
"			proxy_pass http://us;	"
"		}				"
"	}					"
"}						";

static TfwCfgNode *parsed_cfg;

static void
parse_raw_cfg(void)
{
	parsed_cfg = tfw_cfg_parse(raw_cfg);
	BUG_ON(!parsed_cfg);
}

static void
free_parsed_cfg(void)
{
	tfw_cfg_node_free(parsed_cfg);
	parsed_cfg = NULL;
}

TEST(cfg_spec, allows_to_save_cfg_to_custom_struct)
{
	TfwAddr expected_addr;
	struct {
		const char *index1;
		const char *index2;
		bool tcp_nopush;
		int cache_size;

		const TfwAddr *upstream_addr;
		const char *upstream_addr_str;

		int upstream_weight_val;
		const char *upstream_weight_keyword;

	} http_cfg = { };

	const TfwCfgSpec spec[] = {
		{
			"http.index",
			.set_str = &http_cfg.index1
		},
		{
			"http.index",
			.val_pos = 1,
			.set_str = &http_cfg.index2
		},
		{
			"http.tcp_nopush",
			.set_bool = &http_cfg.tcp_nopush
		},
		{
			"http.cache_size",
			.set_int = &http_cfg.cache_size
		},
		{
			"http.upstream.server",
			.set_addr = &http_cfg.upstream_addr,
			.set_str = &http_cfg.upstream_addr_str
		},
		{
			"http.upstream.server",
			.attr="weight",
			.set_int = &http_cfg.upstream_weight_val,
		},
		{}
	};

	tfw_cfg_spec_apply(spec, parsed_cfg);

	EXPECT_STR_EQ(http_cfg.index1, "index.php");
	EXPECT_STR_EQ(http_cfg.index2, "index.html");
	EXPECT_EQ(http_cfg.tcp_nopush, true);
	EXPECT_EQ(http_cfg.cache_size, 8192);
	EXPECT_EQ(http_cfg.upstream_weight_val, 5);

	expected_addr.v4.sin_family = AF_INET;
	expected_addr.v4.sin_addr.s_addr = htonl(0x0A000003);
	expected_addr.v4.sin_port = htons(8080);
	EXPECT_TRUE(tfw_addr_eq(&expected_addr, http_cfg.upstream_addr));
	EXPECT_STR_EQ(http_cfg.upstream_addr_str, "10.0.0.3:8080");
}


static int index_cb_counter;
static int tcp_nopush_cb_counter;
static int cache_size_int_cb_counter;
static int cache_size_str_cb_counter;
static int us_cb_counter;
static int us_srv_addr_cb_counter;
static int us_srv_addr_weight_cb_counter;

static void
index_cb(const char *index)
{
	bool is_php = strcmp(index, "index.php");
	bool is_htm = strcmp(index, "index.htm");
	bool is_html = strcmp(index, "index.html");

	EXPECT_TRUE(is_php || is_htm || is_html);

	++index_cb_counter;
}

static void
tcp_nopush_cb(bool tcp_nopush)
{
	EXPECT_TRUE(tcp_nopush);

	++tcp_nopush_cb_counter;
}

static void
cache_size_int_cb(int cache_size)
{
	EXPECT_EQ(cache_size, 8192);

	++cache_size_int_cb_counter;
}

static void
cache_size_str_cb(const char *cache_size)
{
	bool is_auto = strcmp(cache_size, "auto");
	bool is_8192 = strcmp(cache_size, "8192");

	EXPECT_TRUE(is_auto || is_8192);

	++cache_size_str_cb_counter;
}

static void
us_cb(const TfwCfgNode *upstream)
{
	const char *name;

	TFW_CFG_NVAL(upstream, str, name);
	EXPECT_STR_EQ(name, "us");

	++us_cb_counter;
}

static void
us_srv_addr_cb(const TfwAddr *addr)
{
	TfwAddr expected_addr = {
		.v4.sin_family = AF_INET,
		.v4.sin_port = htons(8080)
	};

	EXPECT_EQ(us_cb_counter, 1);
	EXPECT_LT(us_srv_addr_cb_counter, 3);

	if (us_srv_addr_cb_counter == 0) {
		expected_addr.v4.sin_addr.s_addr = htonl(0x0A000001);
		EXPECT_TRUE(tfw_addr_eq(addr, &expected_addr));
	}

	if (us_srv_addr_cb_counter == 1) {
		expected_addr.v4.sin_addr.s_addr = htonl(0x0A000002);
		EXPECT_TRUE(tfw_addr_eq(addr, &expected_addr));
	}

	if (us_srv_addr_cb_counter == 2) {
		expected_addr.v4.sin_addr.s_addr = htonl(0x0A000003);
		EXPECT_TRUE(tfw_addr_eq(addr, &expected_addr));
	}

	++us_srv_addr_cb_counter;
}

static void
us_srv_addr_weight_cb(int weight)
{
	EXPECT_EQ(us_cb_counter, 1);
	EXPECT_LT(us_srv_addr_weight_cb_counter, 3);

	if (us_srv_addr_weight_cb_counter == 0) {
		EXPECT_EQ(us_srv_addr_cb_counter, 1);
		EXPECT_EQ(weight, 10);
	}

	if (us_srv_addr_weight_cb_counter == 1) {
		EXPECT_EQ(us_srv_addr_cb_counter, 2);
		EXPECT_EQ(weight, 5);
	}

	++us_srv_addr_weight_cb_counter;
}


TEST(cfg_spec, allows_to_handle_cfg_with_custom_callbacks)
{
	const TfwCfgSpec spec[] = {
		{
			"http.index",
			.val_each = true,
			.call_str = index_cb,
		},
		{
			"http.tcp_nopush",
			.call_bool = tcp_nopush_cb,
		},
		{
			"http.cache_size",
			.call_int = cache_size_int_cb,
			.call_str = cache_size_str_cb,
		},
		{
			"http.upstream",
			.call_node = us_cb,
		},
		{
			"http.upstream.server",
			.call_addr = us_srv_addr_cb
		},
		{
			"http.upstream.server",
			.attr = "weight",
			.call_int = us_srv_addr_weight_cb
		},
		{}
	};

	index_cb_counter = 0;
	tcp_nopush_cb_counter = 0;
	cache_size_int_cb_counter = 0;
	cache_size_str_cb_counter = 0;
	us_cb_counter = 0;
	us_srv_addr_cb_counter = 0;
	us_srv_addr_weight_cb_counter = 0;

	tfw_cfg_spec_apply(spec, parsed_cfg);

	EXPECT_EQ(index_cb_counter, 3);
	EXPECT_EQ(tcp_nopush_cb_counter, 1);
	EXPECT_EQ(cache_size_int_cb_counter, 1);
	EXPECT_EQ(cache_size_str_cb_counter, 2);
	EXPECT_EQ(us_cb_counter, 1);
	EXPECT_EQ(us_srv_addr_cb_counter, 3);
	EXPECT_EQ(us_srv_addr_weight_cb_counter, 2);
}

static int backends_cb_counter;

static void
backends_cb(const TfwAddr *be_addr)
{
	TfwAddr expected_v4 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.v4.sin_port = htons(8081),
	};
	TfwAddr expected_v6 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.v6.sin6_port = htons(8081)
	};
	TfwAddr *expected_addr = NULL;

	if (backends_cb_counter == 0)
		expected_addr = &expected_v4;

	if (backends_cb_counter == 1)
			expected_addr = &expected_v6;

	EXPECT_TRUE(tfw_addr_eq(expected_addr, be_addr));

	++backends_cb_counter;
}

TEST(cfg_spec, allows_to_specify_default_values)
{
	const TfwCfgSpec spec[] = {
		{
			"http.backends",
			"backends 127.0.0.1:8081 [::1]:8081;",
			.val_each = true,
			.call_addr = backends_cb
		},
		{}
	};

	backends_cb_counter = 0;

	tfw_cfg_spec_apply(spec, parsed_cfg);

	EXPECT_EQ(backends_cb_counter, 2);
}

TEST_SUITE(cfg_module)
{
	TEST_SETUP(parse_raw_cfg);
	TEST_TEARDOWN(free_parsed_cfg);

	TEST_RUN(cfg_spec, allows_to_save_cfg_to_custom_struct);
	TEST_RUN(cfg_spec, allows_to_handle_cfg_with_custom_callbacks);
	TEST_RUN(cfg_spec, allows_to_specify_default_values);
}
