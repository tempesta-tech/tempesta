/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2026 Tempesta Technologies, Inc.
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
#include "mmap_buffer.h"
#include "test.h"

#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(...)

static TfwMmapBufferHolder *holder;

static unsigned int
tfw_mmap_buffer_get_read_room(TfwMmapBufferHolder *holder, char **data)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);

	*data = buf->data + buf->tail % buf->size;

	return smp_load_acquire(&buf->head) - buf->tail;
}

static void
tfw_mmap_buffer_read_commit(TfwMmapBufferHolder *holder, unsigned int size)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);

	smp_store_release(&buf->tail, buf->tail + size);
}

static int
fill_buf(char *buf, int size)
{
	int i;

	for (i = 0; i < size; ++i)
		buf[i] = (char)(i % 256);

	return 0;
}

static int
check_buf(char *buf, int size)
{
	int i;

	for (i = 0; i < size; ++i) {
		if ((unsigned char)buf[i] != i % 256)
			return -EINVAL;
	}

	return 0;
}

static void
test_write_read(unsigned int size, unsigned int expected_room_size)
{
	char *data;
	unsigned int room_size;

	room_size = tfw_mmap_buffer_get_room(holder, &data);

	EXPECT_EQ(room_size, expected_room_size);
	fill_buf(data, room_size);
	tfw_mmap_buffer_commit(holder, room_size);

	room_size = tfw_mmap_buffer_get_read_room(holder, &data);
	EXPECT_ZERO(check_buf(data, room_size));
	tfw_mmap_buffer_read_commit(holder, room_size);
}

TEST(tfw_mmap_buffer, create)
{
	EXPECT_NULL(tfw_mmap_buffer_create(NULL, 0));
	EXPECT_NULL(tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MIN_SIZE - 1));
	EXPECT_NULL(tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MIN_SIZE + 1));
	EXPECT_NULL(tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MAX_SIZE * 2));
	holder = tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MIN_SIZE);
	EXPECT_NOT_NULL(holder);
	tfw_mmap_buffer_free(holder);
	holder = tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MAX_SIZE);
	EXPECT_NOT_NULL(holder);
	tfw_mmap_buffer_free(holder);
}

TEST(tfw_mmap_buffer, create_dev)
{
	holder = tfw_mmap_buffer_create("test", TFW_MMAP_BUFFER_MIN_SIZE);
	EXPECT_NOT_NULL(holder);
	EXPECT_NULL(tfw_mmap_buffer_create("test", TFW_MMAP_BUFFER_MIN_SIZE));
	tfw_mmap_buffer_free(holder);
}


TEST(tfw_mmap_buffer, write_read)
{
	TfwMmapBuffer *buf;
	char *data;
	unsigned int size, i;

	holder = tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MIN_SIZE);
	EXPECT_NOT_NULL(holder);

	buf = *this_cpu_ptr(holder->buf);

#define MAX_SIZE (buf->size - 1)

	size = tfw_mmap_buffer_get_room(holder, &data);
	EXPECT_EQ(size, MAX_SIZE);

	test_write_read(MAX_SIZE + 1, MAX_SIZE);
	test_write_read(0, MAX_SIZE);
	test_write_read(256, MAX_SIZE);
	test_write_read(MAX_SIZE, MAX_SIZE);

	/* Check all the possible head and tail offsets */
	for (i = 0; i < MAX_SIZE + 1; ++i)
		test_write_read(MAX_SIZE, MAX_SIZE);

	tfw_mmap_buffer_free(holder);

#undef MAX_SIZE
}

TEST_SUITE(mmap_buffer)
{
	TEST_RUN(tfw_mmap_buffer, create);
	TEST_RUN(tfw_mmap_buffer, create_dev);
	TEST_RUN(tfw_mmap_buffer, write_read);
}

