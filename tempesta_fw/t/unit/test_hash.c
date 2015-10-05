/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include <linux/bug.h>

//#include "hash.h"
#include "str.h"
#include "test.h"
#include "kallsyms_helper.h"
/* NOTE: hashing is a probabilistic thing. Some tests may give false results. */
unsigned long (*tfw_hash_str_ptr)(const TfwStr *str);
TEST(tfw_hash_str, calcs_diff_hash_for_diff_str)
{

	/* Note: collisions are possible.
	 * The hashes should be different with high probability,
	 * but at this point we are not going to write some statistical tests.
	 */
	TfwStr s1 = { .len = 10, .ptr = (void *)"foobarbaz1" };
	TfwStr s2 = { .len = 10, .ptr = (void *)"Foobarbaz1" };
	TfwStr s3 = { .len = 10, .ptr = (void *)"foobarbaz2" };
	TfwStr s4 = { .len = 9, .ptr = (void *)"foobarbaz" };
	TfwStr s5 = { .len = 11, .ptr = (void *)"foobarbaz11" };
	TfwStr s6 = { .len = 0, .ptr = (void *)"" };
	unsigned long h[6];
	int i, j;


	if(!tfw_hash_str_ptr){
	tfw_hash_str_ptr = get_sym_ptr("tfw_hash_str");
	}
	if(!tfw_hash_str_ptr){
	TFW_DBG("tfw_hash_str_ptr is null\n"); 
	}

	
	h[0] =	tfw_hash_str_ptr(&s1);
	h[1] =	tfw_hash_str_ptr(&s2);
	h[2] =	tfw_hash_str_ptr(&s3);
	h[3] =	tfw_hash_str_ptr(&s4);
	h[4] =	tfw_hash_str_ptr(&s5);
	h[5] =	tfw_hash_str_ptr(&s6);
	

	for (i = 0; i < 6; ++i) {
		for (j = 0; j < ARRAY_SIZE(h); ++j) {
			if (i != j && h[i] == h[j])
				TEST_FAIL("Equal hashes: h[%d] => %#lx,  "
				          "[%d] => %#lx", i, h[i], j, h[j]);
		}
	}
}

TEST(tfw_hash_str, calcs_same_hash_for_diff_chunks_n)
{
	unsigned long h1, h2, h3;

	TfwStr s1 = { .len = 17, .ptr = (void *)"Host: example.com" };

	TfwStr s2c1 = {	.len = 14, .ptr = (void *)"Host: example." };
	TfwStr s2c2 = {	.len = 3, .ptr = (void *)"com" };
	TfwStr s2chunks[] = { s2c1, s2c2 };
	TfwStr s2 = {
		.len = 14 + 3,
		.ptr = s2chunks
	};

	TfwStr s3c1 = {	.len = 1, .ptr = (void *)"H" };
	TfwStr s3c2 = {	.len = 0, .ptr = (void *)"" };
	TfwStr s3c3 = {	.len = 3, .ptr = (void *)"ost" };
	TfwStr s3c4 = {	.len = 1, .ptr = (void *)":" };
	TfwStr s3c5 = {	.len = 12, .ptr = (void *)" example.com" };
	TfwStr s3c6 = {	.len = 0, .ptr = NULL };
	TfwStr s3chunks[] = { s3c1, s3c2, s3c3, s3c4, s3c5, s3c6 };
	TfwStr s3 = {
		.len = 1 + 0 + 3 + 1 + 12 + 0,
		.ptr = s3chunks
	};

	TFW_STR_CHUNKN_INIT(&s2);
	__TFW_STR_CHUNKN_SET(&s3, 6);

	if(!tfw_hash_str_ptr){
	tfw_hash_str_ptr = get_sym_ptr("tfw_hash_str");
	}
	h1 = tfw_hash_str_ptr(&s1);
	h2 = tfw_hash_str_ptr(&s2);
	h3 = tfw_hash_str_ptr(&s3);

	EXPECT_EQ(h1, h2);
	EXPECT_EQ(h1, h3);
	EXPECT_EQ(h2, h1);
	EXPECT_EQ(h2, h3);
	EXPECT_EQ(h3, h1);
	EXPECT_EQ(h3, h2);
}

TEST(tfw_hash_str, hashes_all_chars)
{
	int i;
	unsigned long h1, h2;
	char buf1[256] = { 0 };
	char buf2[256] = { 0 };
	TfwStr s1 = { .len = 0,	.ptr = buf1 };
	TfwStr s2 = { .len = 0, .ptr = buf2 };

	/* Change of each individial byte in the string should change
	 * the hash value. */
	for (i = 0; i < 255; ++i) {
		s1.len = s2.len = (i + 1);
		buf1[i] = 'a';
		buf2[i] = 'b';

	if(!tfw_hash_str_ptr){
	tfw_hash_str_ptr = get_sym_ptr("tfw_hash_str");
	}
		h1 = tfw_hash_str_ptr(&s1);
		h2 = tfw_hash_str_ptr(&s2);
		if (h1 == h2)
			TEST_FAIL("Equal hashes (%#lx) for different strings:\n"
			          " s1: %.*s (len %u)\n"
			          " s2: %.*s (len %u)",
			          h1,
			          s1.len, (char *)s1.ptr, s1.len,
			          s2.len, (char *)s2.ptr, s2.len);

		buf2[i] = 'a';
		h2 = tfw_hash_str_ptr(&s2);
		if (h1 != h2)
			TEST_FAIL("Different hashes for equal strings:\n"
			          " s1: %#08lx: %.*s (len %u)\n"
			          " s2: %#08lx: %.*s (len %u)",
			          h1, s1.len, (char *)s1.ptr, s1.len,
			          h2, s2.len, (char *)s2.ptr, s2.len);
	}
}

TEST(tfw_hash_str, doesnt_read_behind_end_of_buf)
{
	char buf[256] = { 0 };
	TfwStr s = {
		.len = 0,
		.ptr = buf
	};

	unsigned long h1, h2;
	int i;

	if(!tfw_hash_str_ptr){
	tfw_hash_str_ptr = get_sym_ptr("tfw_hash_str");
	}
	for (i = 0; i < 255; ++i) {
		s.len = i;

		buf[i] = 'x';
		h1 = tfw_hash_str_ptr(&s);

		memset(&buf[i + 1], i, (sizeof(buf) - i - 1));
		h2 = tfw_hash_str_ptr(&s);

		EXPECT_EQ(h1, h2);
	}
}

TEST(tfw_hash_str, distributes_all_input_across_hash_bits)
{
	char buf[256];
	TfwStr str = {
		.ptr = buf,
		.len = sizeof(buf)
	};

	unsigned long h1, h2;
	int i;

	if(!tfw_hash_str_ptr){
	tfw_hash_str_ptr = get_sym_ptr("tfw_hash_str");
	}
	memset(buf, 'a', sizeof(buf));
	h1 = tfw_hash_str_ptr(&str);

	/* For a good hash function, a change of a single bit in the input will
	 * cause changing many bits in the output (with high probability).
	 * We don't write statistical tests here, just hope there is no
	 * collisions and check a couple of bytes in the output hash.
	 * Note that we check only low 32 bits since our hash function is a bit
	 * weak here and it doesn't calculate the high 64 bits.
	 */
	for (i = 0; i < sizeof(buf); ++i) {
		buf[i] = 'b';
		h2 = tfw_hash_str_ptr(&str);
		buf[i] = 'a';

		EXPECT_NE(h1 & 0x00000000000000FF, h2 & 0x00000000000000FF);
		EXPECT_NE(h1 & 0x00000000FF000000, h2 & 0x00000000FF000000);
	}
}

TEST_SUITE(hash)
{
	TEST_RUN(tfw_hash_str, calcs_diff_hash_for_diff_str);
	TEST_RUN(tfw_hash_str, calcs_same_hash_for_diff_chunks_n);
	TEST_RUN(tfw_hash_str, hashes_all_chars);
	TEST_RUN(tfw_hash_str, doesnt_read_behind_end_of_buf);
	TEST_RUN(tfw_hash_str, distributes_all_input_across_hash_bits);
}
