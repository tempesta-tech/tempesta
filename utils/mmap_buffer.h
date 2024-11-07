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

#ifndef __TFW_MMAP_BUFFER_READER_H__
#define __TFW_MMAP_BUFFER_READER_H__

#include <string>
#include <thread>

#include "../fw/mmap_buffer.h"

typedef void (*TfwMmapBufferReadCallback)(const char *data, int size,
					  void *private_data);

/**
 * Tempesta user space ring buffer reader
 * TfwMmapBufferReader is a reader from a ring buffer mapped into user space.
 * It monitors the buffer for new data. When new data is available, it invokes
 * a specified callback, providing a pointer to the start of the data, its size
 * and CPU number.
 *
 * Constructor:
 *    @TfwMmapBufferReader - Initializes own fields, maps the buffer.
 *
 * Destructor:
 *    @~TfwMmapBufferReader - Unmaps the buffer.
 *
 * Other public methods:
 *    @run - Main reading loop. Continuously checks if new data is available by
 *        polling the `is_ready` flag in the shared buffer. Calls `read()` to
 *        process data if available and notifies the callback.
 *    @get_cpu_id - Returns the CPU ID from the shared buffer.
 *
 * Private methods:
 *    @get_buffer_size - Retrieves the size of the ring buffer for proper data
 *        management.
 *    @read - checks if there is a new data block and executes the callback when
 *        new data is detected.
 */
class TfwMmapBufferReader {
public:
	TfwMmapBufferReader(unsigned int cpu_cnt, int fd, void *private_data,
			    TfwMmapBufferReadCallback cb);
	TfwMmapBufferReader(const TfwMmapBufferReader &) = delete;
	TfwMmapBufferReader &operator=(const TfwMmapBufferReader &) = delete;
	~TfwMmapBufferReader();

	void run(std::atomic<bool> *stop_flag);
	unsigned int get_cpu_id();

private:
	TfwMmapBuffer	*buf_;
	unsigned int	size_;
	bool		is_running_;
	void		*private_data_;
	TfwMmapBufferReadCallback	callback_;

	void get_buffer_size(int fd);
	int read();
};

#endif /* __TFW_MMAP_BUFFER_READER_H__ */
