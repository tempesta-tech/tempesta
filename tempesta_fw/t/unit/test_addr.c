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

#include "addr.h"
#include "test.h"


TEST(tfw_addr_fmt, formats_ipv4_addrs)
{
	TfwAddr a1 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = INADDR_ANY,
		.v4.sin_port = 0,
	};
	TfwAddr a2 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.v4.sin_port = htons(8001),
	};
	TfwAddr a3 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(0x0764FF0A),
		.v4.sin_port = htons(65535),
	};

	char s1[TFW_ADDR_STR_BUF_SIZE];
	char s2[TFW_ADDR_STR_BUF_SIZE];
	char s3[TFW_ADDR_STR_BUF_SIZE];
	size_t l1, l2, l3;

	memset(s1, 0xAA, sizeof(s1));
	memset(s2, 0xAA, sizeof(s2));
	memset(s3, 0xAA, sizeof(s3));

	l1 = tfw_addr_fmt(&a1, s1, sizeof(s1));
	l2 = tfw_addr_fmt(&a2, s2, sizeof(s2));
	l3 = tfw_addr_fmt(&a3, s3, sizeof(s3));

	EXPECT_EQ(0, memcmp("0.0.0.0", s1, ++l1));
	EXPECT_EQ(0, memcmp("127.0.0.1:8001", s2, ++l2));
	EXPECT_EQ(0, memcmp("7.100.255.10:65535", s3, ++l3));
}

TEST(tfw_addr_fmt, formats_ipv6_addrs)
{
	TfwAddr a0 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_ANY_INIT,
		.v6.sin6_port = 0,
	};
	TfwAddr a1 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.v6.sin6_port = 0,
	};
	TfwAddr a2 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_SITELOCAL_ALLROUTERS_INIT,
		.v6.sin6_port = htons(2718),
	};
	TfwAddr a3 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = { { { 0x00,0x12,0x34,0x56,0x00,0x00,0xBC,0xDE,
		                0xF0,0x01,0x00,0x00,0x00,0x00,0x06,0x07 } } },
		.v6.sin6_port = htons(65535),
	};


	const char *e0 = "::0";
	const char *e1 = "::1";
	const char *e2 = "[ff05::2]:2718";
	const char *e3 = "[12:3456::bcde:f001:0:0:607]:65535";

	char s0[TFW_ADDR_STR_BUF_SIZE];
	char s1[TFW_ADDR_STR_BUF_SIZE];
	char s2[TFW_ADDR_STR_BUF_SIZE];
	char s3[TFW_ADDR_STR_BUF_SIZE];
	size_t l0, l1, l2, l3;

	memset(s0, 0xAA, sizeof(s0));
	memset(s1, 0xAA, sizeof(s1));
	memset(s2, 0xAA, sizeof(s2));
	memset(s3, 0xAA, sizeof(s3));

	l0 = tfw_addr_fmt(&a0, s0, sizeof(s0));
	l1 = tfw_addr_fmt(&a1, s1, sizeof(s1));
	l2 = tfw_addr_fmt(&a2, s2, sizeof(s2));
	l3 = tfw_addr_fmt(&a3, s3, sizeof(s3));

	EXPECT_EQ(0, memcmp(e0, s0, ++l0));
	EXPECT_EQ(0, memcmp(e1, s1, ++l1));
	EXPECT_EQ(0, memcmp(e2, s2, ++l2));
	EXPECT_EQ(0, memcmp(e3, s3, ++l3));
}

TEST(tfw_addr_fmt, omits_port_80)
{
	TfwAddr a1 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.v4.sin_port = htons(80),
	};
	TfwAddr a2 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.v6.sin6_port = htons(80),
	};

	const char *e1 = "127.0.0.1";
	const char *e2 = "::1";

	char s1[TFW_ADDR_STR_BUF_SIZE];
	char s2[TFW_ADDR_STR_BUF_SIZE];
	size_t l1, l2;

	memset(s1, 0xAA, sizeof(s1));
	memset(s2, 0xAA, sizeof(s2));

	l1 = tfw_addr_fmt(&a1, s1, sizeof(s1));
	l2 = tfw_addr_fmt(&a2, s2, sizeof(s2));

	EXPECT_EQ(0, memcmp(e1, s1, ++l1));
	EXPECT_EQ(0, memcmp(e2, s2, ++l2));
}

TEST_SUITE(addr)
{
	TEST_RUN(tfw_addr_fmt, formats_ipv4_addrs);
	TEST_RUN(tfw_addr_fmt, formats_ipv6_addrs);
	TEST_RUN(tfw_addr_fmt, omits_port_80);
}
