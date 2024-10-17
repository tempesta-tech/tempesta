/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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
#include "ringbuffer.h"
#include "tfw_str_helper.h"
#include "test.h"

#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(...)

static void
fill_buf(unsigned char *buf, int size)
{
	int i;
	for (i = 0; i < size; ++i)
		buf[i] = i % 256;
}

static void
test_write_read(TfwStr *s1, char *buf, int expect_wr, int expect_rd)
{
	int r;
	TfwStr s2;

	TFW_STR_INIT(&s2);
	s2.data = buf;
	s2.len = s1->len;

	r = tfw_ringbuffer_write(&s1, 1);
	EXPECT_EQ(r, expect_wr);
	if (r != 0)
		return;
	EXPECT_EQ(tfw_ringbuffer_test_read(buf, s2.len), expect_rd);
	EXPECT_EQ(tfw_strcmp(s1, &s2), 0);
}

TEST(tfw_ringbuffer, init)
{
	EXPECT_EQ(tfw_ringbuffer_init(0), -EINVAL);
	EXPECT_EQ(tfw_ringbuffer_init(TFW_RINGBUFFER_MIN_SIZE - 1), -EINVAL);
	EXPECT_EQ(tfw_ringbuffer_init(TFW_RINGBUFFER_MIN_SIZE + 1), -EINVAL);
	EXPECT_EQ(tfw_ringbuffer_init(TFW_RINGBUFFER_MAX_SIZE * 2), -EINVAL);
	EXPECT_EQ(tfw_ringbuffer_init(TFW_RINGBUFFER_MIN_SIZE), 0);
	tfw_ringbuffer_cleanup();
}

TEST(tfw_ringbuffer, write_read)
{
	unsigned char *buf_wr, *buf_rd;
	TfwStr *s, sb;
	TfwStr *sps[16];
	int i;

	create_str_pool();

	kernel_fpu_end();
	buf_wr = vmalloc(TFW_RINGBUFFER_MIN_SIZE);
	buf_rd = vmalloc(TFW_RINGBUFFER_MIN_SIZE);
	kernel_fpu_begin();

	fill_buf(buf_wr, TFW_RINGBUFFER_MIN_SIZE);
	TFW_STR_INIT(&sb);
	sb.data = buf_wr;

	EXPECT_EQ(tfw_ringbuffer_init(TFW_RINGBUFFER_MIN_SIZE), 0);

	s = make_plain_str("0123456789");
	test_write_read(s, buf_rd, -EAGAIN, 0);
	tfw_ringbuffer_test_set_unmapped(0);
	test_write_read(s, buf_rd, 0, 0);

	s = make_compound_str("0123456789");
	test_write_read(s, buf_rd, 0, 0);

	sb.len = TFW_RINGBUFFER_MIN_SIZE;
	test_write_read(&sb, buf_rd, -ENOMEM, 0);

	sb.len = TFW_RINGBUFFER_MIN_SIZE - 1;
	test_write_read(&sb, buf_rd, 0, 0);

	sb.len = 0;
	test_write_read(&sb, buf_rd, 0, 0);

	sb.len = 1000;
	test_write_read(&sb, buf_rd, 0, 0);

	for (i = 0; i < 16; ++i) {
		sps[i] = make_compound_str("0123456789");
		sps[i]->data[0] += i;
	}
	EXPECT_EQ(tfw_ringbuffer_write(sps, 16), 0);
	EXPECT_EQ(tfw_ringbuffer_test_read(buf_rd, 160), 0);
	for (i = 0; i < 16; ++i) {
		int j;
		EXPECT_EQ(buf_rd[i*10], '0' + i);
		for (j = 1; j < 10; ++j)
			EXPECT_EQ(buf_rd[i*10+j], '0' + j);
		break;
	}

	kernel_fpu_end();
	vfree(buf_rd);
	vfree(buf_wr);
	kernel_fpu_begin();

	tfw_ringbuffer_cleanup();
}

TEST_SUITE(ringbuffer)
{
	TEST_RUN(tfw_ringbuffer, init);
	TEST_RUN(tfw_ringbuffer, write_read);
}
