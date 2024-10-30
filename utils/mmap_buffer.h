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

#include "../fw/mmap_buffer.h"
#include <string>
#include <thread>

using namespace std;

typedef void (*TfwMmapBufferReadCallback)(const char *data, int size,
					  unsigned int cpu);

/**
 * Tempesta user space ring buffer reader
 * TfwMmapBufferReader is a reader from a ring buffer mapped into user space.
 * It spawns a separate thread for each CPU core, which monitors the buffer for
 * new data. When new data is available, it invokes a specified callback,
 * providing a pointer to the start of the data and its size.
 *
 * Constructor:
 *    @TfwMmapBufferReader - Initializes the buffer reader with a path to the
 *        memory-mapped file, the number of CPUs to allocate threads for, and
 *        a callback function to process the data.
 *
 * Destructor:
 *    @~TfwMmapBufferReader - Ensures that all threads are properly terminated
 *        and resources are released.
 *
 * Other public methods:
 *    @run - Opens file in /dev, gets the buffer size and starts threads that
 *        read from the buffer for each CPU.
 *
 * Private struct:
 *    @TfwThread - Holds information for each thread, including a pointer to the
 *        thread object, the ring buffer for the thread's CPU, CPU ID and a flag
 *        indicating that the cycle of reading is started.
 *
 * Private methods:
 *    @run_thread - Executes a thread reading loop. It maps the buffer, attaches
 *        to the appropriate CPU and reads in a loop.
 *    @get_buffer_size - Retrieves the size of the ring buffer for proper data
 *        management.
 *    @read - checks if there is a new data block and executes the callback when
 *        new data is detected.
 */
class TfwMmapBufferReader {
public:
	TfwMmapBufferReader(string path, unsigned int cpu_cnt,
			    TfwMmapBufferReadCallback cb);
	~TfwMmapBufferReader();
	void run();

private:
	struct TfwThread {
		thread		*thr;
		TfwMmapBuffer	*buf;
		int		cpu;
		bool		is_running;
	};

	TfwThread		*thrs;
	int			fd;
	string			filepath;
	unsigned int		size;
	unsigned int		cpu_cnt;
	TfwMmapBuffer		**bufs;
	TfwMmapBufferReadCallback	callback;

	void run_thread(TfwThread *thr);
	void get_buffer_size();
	int read(TfwThread *thr);
};

#endif /* __TFW_MMAP_BUFFER_READER_H__ */
