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

#include "hash.h"
#include "test.h"

/* NOTE: hashing is a probabilistic thing. Some tests may give false results. */

TEST(tfw_hash_str, calcs_diff_hash_for_diff_str)
{
	/* Note: collisions are possible.
	 * The hashes should be different with high probability,
	 * but at this point we are not going to write some statistical tests.
	 */
	int i, j;
	unsigned long h[6];
	TfwStr s0, s1, s2, s3, s4;

	s0.cnum = s1.cnum = s2.cnum = s3.cnum = s4.cnum = 1;

	s0.single_chunk.data = "foobarbaz1";
	s0.single_chunk.len  = 10;
	h[0] = tfw_hash_str(&s0);

	s1.single_chunk.data = "Foobarbaz1";
	s1.single_chunk.len  = 10;
	h[1] = tfw_hash_str(&s1);

	s2.single_chunk.data = "foobarbaz2";
	s2.single_chunk.len  = 10;
	h[2] = tfw_hash_str(&s2);

	s3.single_chunk.data = "foobarbaz";
	s3.single_chunk.len  = 9;
	h[3] = tfw_hash_str(&s3);

	s4.single_chunk.data = "foobarbaz11";
	s4.single_chunk.len  = 11;
	h[4] = tfw_hash_str(&s4);

	for (i = 0; i < ARRAY_SIZE(h); ++i) {
		for (j = 0; j < ARRAY_SIZE(h); ++j) {
			if (i != j && h[i] == h[j])
				TEST_FAIL("Equal hashes: h[%d] => %#lx,  "
				          "[%d] => %#lx", i, h[i], j, h[j]);
		}
	}
}

TEST(tfw_hash_str, calcs_same_hash_for_diff_chunks_n)
{
	TfwStr s1 = {
		.chunks = (void *)"Host: example.com",
		.len = 17,
		.cnum = 1
	};

	TfwStrChunk s2c1 = { .len = 14, .data = "Host: example." };
	TfwStrChunk s2c2 = { .len = 3, .data = "com" };
	TfwStrChunk s2chunks[] = { s2c1, s2c2 };
	TfwStr s2 = {
		.len = 17,
		.cnum = 2,
		.chunks = s2chunks,
	};

	TfwStrChunk s3c1 = { .len = 1, .data = "H" };
	TfwStrChunk s3c2 = { .len = 3, .data = "ost" };
	TfwStrChunk s3c3 = { .len = 1, .data = ":" };
	TfwStrChunk s3c4 = { .len = 12, .data = " example.com" };
	TfwStrChunk s3chunks[] = { s3c1, s3c2, s3c3, s3c4 };
	TfwStr s3 = {
		.len = 17,
		.cnum = 4,
		.chunks = s3chunks,
	};

	unsigned long h1, h2, h3;
	h1 = tfw_hash_str(&s1);
	h2 = tfw_hash_str(&s2);
	h3 = tfw_hash_str(&s3);

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
	TfwStr s1 = { .cnum = 1, .chunks = (void *)buf1 };
	TfwStr s2 = { .cnum = 1, .chunks = (void *)buf2 };

	/* Change of each individial byte in the string should change
	 * the hash value. */
	for (i = 0; i < 255; ++i) {
		s1.len = s2.len = (i + 1);
		buf1[i] = 'a';
		buf2[i] = 'b';

		h1 = tfw_hash_str(&s1);
		h2 = tfw_hash_str(&s2);
		if (h1 == h2)
			TEST_FAIL("Equal hashes (%#lx) for different strings:\n"
			          " s1: %.*s (len %u)\n"
			          " s2: %.*s (len %u)",
			          h1,
			          s1.len, s1.single_chunk.data, s1.len,
			          s2.len, s2.single_chunk.data, s2.len);

		buf2[i] = 'a';
		h2 = tfw_hash_str(&s2);
		if (h1 != h2)
			TEST_FAIL("Different hashes for equal strings:\n"
			          " s1: %#08lx: %.*s (len %u)\n"
			          " s2: %#08lx: %.*s (len %u)",
			          h1, s1.len, s1.single_chunk.data, s1.len,
			          h2, s2.len, s2.single_chunk.data, s2.len);
	}
}

TEST(tfw_hash_str, doesnt_read_behind_end_of_buf)
{
	char buf[256] = { 0 };
	TfwStr s = {
		.cnum = 1,
		.chunks = (void *)buf
	};

	unsigned long h1, h2;
	int i;

	for (i = 0; i < 255; ++i) {
		s.len = i;

		buf[i] = 'x';
		h1 = tfw_hash_str(&s);

		memset(&buf[i + 1], i, (sizeof(buf) - i - 1));
		h2 = tfw_hash_str(&s);

		EXPECT_EQ(h1, h2);
	}
}

TEST(tfw_hash_str, distributes_all_input_across_hash_bits)
{
	char buf[256];
	TfwStr str;
	unsigned long h1, h2;
	int i;

	str.single_chunk.data = buf;
	str.single_chunk.len = sizeof(buf);
	str.cnum = 1;

	memset(buf, 'a', sizeof(buf));
	h1 = tfw_hash_str(&str);

	/* For a good hash function, a change of a single bit in the input will
	 * cause changing many bits in the output (with high probability).
	 * We don't write statistical tests here, just hope there is no
	 * collisions and check a couple of bytes in the output hash.
	 * Note that we check only low 32 bits since our hash function is a bit
	 * weak here and it doesn't calculate the high 64 bits.
	 */
	for (i = 0; i < sizeof(buf); ++i) {
		buf[i] = 'b';
		h2 = tfw_hash_str(&str);
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
