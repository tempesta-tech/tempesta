/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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


TEST(tfw_addr_ntop, formats_ipv4_addrs)
{
	TfwAddr a1 = tfw_addr_new_v4(INADDR_ANY, 0);
	TfwAddr a2 = tfw_addr_new_v4(htonl(INADDR_LOOPBACK), htons(8001));
	TfwAddr a3 = tfw_addr_new_v4(htonl(0x0764FF0A), htons(65535));

	char s1[TFW_ADDR_STR_BUF_SIZE];
	char s2[TFW_ADDR_STR_BUF_SIZE];
	char s3[TFW_ADDR_STR_BUF_SIZE];
	size_t l1, l2, l3;

	memset(s1, 0xAA, sizeof(s1));
	memset(s2, 0xAA, sizeof(s2));
	memset(s3, 0xAA, sizeof(s3));

	l1 = tfw_addr_ntop(&a1, s1, sizeof(s1));
	l2 = tfw_addr_ntop(&a2, s2, sizeof(s2));
	l3 = tfw_addr_ntop(&a3, s3, sizeof(s3));

	EXPECT_EQ(0, memcmp("0.0.0.0", s1, ++l1));
	EXPECT_EQ(0, memcmp("127.0.0.1:8001", s2, ++l2));
	EXPECT_EQ(0, memcmp("7.100.255.10:65535", s3, ++l3));
}

TEST(tfw_addr_ntop, formats_ipv6_addrs)
{
	TfwAddr a0 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = 0,
	};
	TfwAddr a1 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = 0,
	};
	TfwAddr a2 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_SITELOCAL_ALLROUTERS_INIT,
		.sin6_port = htons(2718),
	};
	TfwAddr a3 = {
		.sin6_family = AF_INET6,
		.sin6_addr = { { { 0x00,0x12,0x34,0x56,0x00,0x00,0xBC,0xDE,
		                   0xF0,0x01,0x00,0x00,0x00,0x00,0x06,0x07 } } },
		.sin6_port = htons(65535),
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

	l0 = tfw_addr_ntop(&a0, s0, sizeof(s0));
	l1 = tfw_addr_ntop(&a1, s1, sizeof(s1));
	l2 = tfw_addr_ntop(&a2, s2, sizeof(s2));
	l3 = tfw_addr_ntop(&a3, s3, sizeof(s3));

	EXPECT_EQ(0, memcmp(e0, s0, ++l0));
	EXPECT_EQ(0, memcmp(e1, s1, ++l1));
	EXPECT_EQ(0, memcmp(e2, s2, ++l2));
	EXPECT_EQ(0, memcmp(e3, s3, ++l3));
}

TEST(tfw_addr_ntop, omits_port_80)
{
	TfwAddr a1 = tfw_addr_new_v4(htonl(INADDR_LOOPBACK), htons(80));

	TfwAddr a2 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(80),
	};

	const char *e1 = "127.0.0.1";
	const char *e2 = "::1";

	char s1[TFW_ADDR_STR_BUF_SIZE];
	char s2[TFW_ADDR_STR_BUF_SIZE];
	size_t l1, l2;

	memset(s1, 0xAA, sizeof(s1));
	memset(s2, 0xAA, sizeof(s2));

	l1 = tfw_addr_ntop(&a1, s1, sizeof(s1));
	l2 = tfw_addr_ntop(&a2, s2, sizeof(s2));

	EXPECT_EQ(0, memcmp(e1, s1, ++l1));
	EXPECT_EQ(0, memcmp(e2, s2, ++l2));
}

TEST(tfw_addr_pton, recognizes_v4_and_v6_addrs)
{
        DEFINE_TFW_STR(s1, "127.0.0.1");
        DEFINE_TFW_STR(s2, "127.0.0.1:8081");
        DEFINE_TFW_STR(s3, "1111::2:a:B");
        DEFINE_TFW_STR(s4, "[::1]:1234");
        DEFINE_TFW_STR(s5, "[::0]:5678");

	TfwAddr e1 = tfw_addr_new_v4(htonl(INADDR_LOOPBACK), htons(80));
	TfwAddr e2 = tfw_addr_new_v4(htonl(INADDR_LOOPBACK), htons(8081));

	TfwAddr e3 = {
		.sin6_family = AF_INET6,
		.sin6_addr = { { {
			0x11, 0x11, 0,0,0,0,0,0,0,0, 0,0x2, 0,0xa, 0,0xB
		} } },
		.sin6_port = htons(80)
	};
	TfwAddr e4 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(1234)
	};
	TfwAddr e5 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = htons(5678)
	};

        TfwAddr a1, a2, a3, a4, a5;
        int r1, r2, r3, r4, r5;

        r1 = tfw_addr_pton(&s1, &a1);
        r2 = tfw_addr_pton(&s2, &a2);
        r3 = tfw_addr_pton(&s3, &a3);
        r4 = tfw_addr_pton(&s4, &a4);
        r5 = tfw_addr_pton(&s5, &a5);

        EXPECT_OK(r1);
        EXPECT_OK(r2);
        EXPECT_OK(r3);
        EXPECT_OK(r4);
        EXPECT_OK(r5);
        EXPECT_TRUE(tfw_addr_eq(&a1, &e1));
        EXPECT_TRUE(tfw_addr_eq(&a2, &e2));
        EXPECT_TRUE(tfw_addr_eq(&a3, &e3));
        EXPECT_TRUE(tfw_addr_eq(&a4, &e4));
        EXPECT_TRUE(tfw_addr_eq(&a5, &e5));
}

TEST_SUITE(addr)
{
	TEST_RUN(tfw_addr_ntop, formats_ipv4_addrs);
	TEST_RUN(tfw_addr_ntop, formats_ipv6_addrs);
	TEST_RUN(tfw_addr_ntop, omits_port_80);
	TEST_RUN(tfw_addr_pton, recognizes_v4_and_v6_addrs);
}
