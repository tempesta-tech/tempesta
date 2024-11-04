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
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "mmap_buffer.h"
#include <iostream>
#include <cstring>
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <sys/mman.h>

#define WAIT_FOR_FILE		1  /* s */
#define WAIT_FOR_READINESS	10 /* ms */

TfwMmapBufferReader::TfwMmapBufferReader(string path, unsigned int cpu_cnt,
					 TfwMmapBufferReadCallback cb)
{
	unsigned int i;

	callback = cb;
	filepath = path;
	this->cpu_cnt = cpu_cnt;

	thrs = new TfwThread[cpu_cnt];
	for (i = 0; i < cpu_cnt; ++i)
		thrs[i].cpu = i;
}

TfwMmapBufferReader::~TfwMmapBufferReader()
{
	delete thrs;
}

void
TfwMmapBufferReader::run()
{
	unsigned int i;

	while (1) {
		while ((fd = open(filepath.c_str(), O_RDWR)) == -1) {
			if (errno != ENOENT)
				throw runtime_error(strerror(errno));
			sleep(WAIT_FOR_FILE);
		}

		get_buffer_size();

		for (i = 0; i < cpu_cnt; ++i)
			thrs[i].thr = new thread(&TfwMmapBufferReader::run_thread,
						 this, &thrs[i]);

		for (i = 0; i < cpu_cnt; ++i)
			thrs[i].thr->join();

		close(fd);
	}
}

void
TfwMmapBufferReader::run_thread(TfwThread *thr)
{
	cpu_set_t cpuset;
	pthread_t current_thread = pthread_self();
	unsigned int area_size;
	int r;

	area_size = TFW_MMAP_BUFFER_FULL_SIZE(size);

	thr->buf = (TfwMmapBuffer *)mmap(NULL, area_size, PROT_READ|PROT_WRITE,
					 MAP_SHARED, fd, area_size * thr->cpu);
	if (thr->buf == MAP_FAILED)
		throw runtime_error("Failed to map buffer");

	CPU_ZERO(&cpuset);
	CPU_SET(thr->buf->cpu, &cpuset);

	if (pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset) != 0)
		cerr << "Set affinity error\n";

	thr->is_running = false;

	while (1) {
		if (__atomic_load_n(&thr->buf->is_ready, __ATOMIC_ACQUIRE)) {
			thr->is_running = true;
			r = read(thr);
			if (r == 0)
				continue;
		} else {
			if (thr->is_running) {
				thr->is_running = false;
				break;
			}
		}

		this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_READINESS));
	}

	if (munmap(thr->buf, area_size) == -1)
		cerr << "Failed to unmap buffers\n";
}

void
TfwMmapBufferReader::get_buffer_size()
{
	TfwMmapBuffer *buf;

	buf = (TfwMmapBuffer *)mmap(NULL, TFW_MMAP_BUFFER_DATA_OFFSET,
				    PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		throw runtime_error("Failed to get buffers info");

	size = buf->size;

	munmap(buf, TFW_MMAP_BUFFER_DATA_OFFSET);
}

int
TfwMmapBufferReader::read(TfwThread *thr)
{
	TfwMmapBuffer *buf = thr->buf;
	u64 head, tail;

	head = __atomic_load_n(&buf->head, __ATOMIC_ACQUIRE);
	tail = buf->tail;

	if (head - tail == 0)
		return -EAGAIN;

	callback(buf->data + (tail & buf->mask), head - tail, thr->cpu);

	__atomic_store_n(&buf->tail, head, __ATOMIC_RELEASE);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);

	return 0;
}
