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
#include "mmap_buffer.h"
#include "test.h"

#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(...)

static TfwMmapBufferHolder *holder;

void
tfw_mmap_buffer_get_read_room(TfwMmapBufferHolder *holder,
							  char **part1, unsigned int *size1,
							  char **part2, unsigned int *size2)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);
	u64 head, tail;

	if (!atomic_read(&buf->is_ready)) {
		*size1 = 0;
		*size2 = 0;
		return;
	}

	head = smp_load_acquire(&buf->head) % buf->size;
	tail = buf->tail % buf->size;

	*part1 = buf->data + tail;

	if (head > tail) {
		*size1 = head - tail;
		*size2 = 0;
		return;
	}

	*size1 = buf->size - tail;
	*part2 = buf->data;
	*size2 = head;
}

void
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
test_write_read(unsigned int size, int expect_wr, int expect_rd)
{
	int r = 0;
	char *p1, *p2;
	unsigned int s1, s2, written;

#define WALK_BUFFER(func) \
	do { \
		written = 0; \
		while (1) { \
			unsigned int cur_size = min(size, s1); \
			r = func(p1, cur_size); \
			if (r) \
				break; \
			size -= cur_size; \
			s1 -= cur_size; \
			written += cur_size; \
			if (size == 0) \
				break; \
			if (p1 == p2 || s2 == 0) { \
				r = -ENOMEM; \
				break; \
			} \
			s1 = s2; \
			p1 = p2; \
		} \
	} while (0)

	tfw_mmap_buffer_get_room(holder, &p1, &s1, &p2, &s2);
	WALK_BUFFER(fill_buf);
	EXPECT_EQ(r, expect_wr);
	if (r)
		return;
	tfw_mmap_buffer_commit(holder, size);

	size = written;

	tfw_mmap_buffer_get_read_room(holder, &p1, &s1, &p2, &s2);
	WALK_BUFFER(check_buf);
	if (!r)
		tfw_mmap_buffer_read_commit(holder, size);
	EXPECT_EQ(r, expect_rd);

#undef WALK_BUFFER
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
}

TEST(tfw_mmap_buffer, write_read)
{
	TfwMmapBuffer *buf;
	char *p1, *p2;
	unsigned int s1, s2, i;

	holder = tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MIN_SIZE);
	EXPECT_NOT_NULL(holder);

	buf = *this_cpu_ptr(holder->buf);

#define MAX_SIZE (buf->size - 1)

	tfw_mmap_buffer_get_room(holder, &p1, &s1, &p2, &s2);
	EXPECT_ZERO(s1);
	EXPECT_ZERO(s2);
	atomic_set(&buf->is_ready, 1);
	tfw_mmap_buffer_get_room(holder, &p1, &s1, &p2, &s2);
	EXPECT_EQ(s1, MAX_SIZE);

	test_write_read(MAX_SIZE + 1, -ENOMEM, 0);
	test_write_read(0, 0, 0);
	test_write_read(256, 0, 0);

	/* Check all the possible head and tail offsets */
	for (i = 0; i < MAX_SIZE + 1; ++i)
		test_write_read(MAX_SIZE, 0, 0);

	tfw_mmap_buffer_free(holder);

#undef MAX_SIZE
}

TEST_SUITE(mmap_buffer)
{
	TEST_RUN(tfw_mmap_buffer, create);
	TEST_RUN(tfw_mmap_buffer, write_read);
}

