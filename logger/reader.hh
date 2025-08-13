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

#pragma once

#include "../fw/mmap_buffer.h"
#include "sender.hh"

class Reader {
public:
	Reader(unsigned int ncpu, int fd, Sender sender);

	Reader(const Reader &) = delete;
	Reader &
	operator=(const Reader &) = delete;

	Reader(Reader &&) noexcept;
	Reader &
	operator=(Reader &&) = delete;

	~Reader();

	bool
	run();

private:
	enum class ProcessResult {
		Success,
		NoData,
		FailedToProcess,
	};

	ProcessResult
	process_batch();

private:
	unsigned int ncpu_;
	TfwMmapBuffer *buf_;
	size_t size_;
	bool waiting_for_readyness_;
	Sender sender_;
};

std::optional<int>
open_mmap_device(const char *dev_path);
