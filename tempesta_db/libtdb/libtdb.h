/**
 *		Tempesta DB User-space Library Definitions
 *
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
#ifndef __LIBTDB_H__
#define __LIBTDB_H__

#include <linux/netlink.h>

#include <functional>

#include <tdb_if.h>
#include "exception.h"

class TdbHndl {
public:
	static const size_t MMSZ;

public:
	TdbHndl(size_t mm_sz);
	~TdbHndl() noexcept;

	void get_info(std::function<void (TdbMsg *)> data_cb);
	void open_table(std::string &db_path, std::string &tbl_name,
			size_t pages, unsigned int rec_size);
	void close_table(std::string &tbl_name);

private:
	void advance_frame_offset(unsigned int &off) noexcept;
	void lazy_buffer_alloc();

	void msg_recv(std::function<bool (nlmsghdr *)> msg_cb);
	void msg_send(std::function<void (nlmsghdr *)> msg_build_cb);

private:
	int fd_;
	size_t ring_sz_;
	char *rx_ring_, *tx_ring_;
	unsigned int rx_fr_off_, tx_fr_off_;
	char *buf_;
};

#endif // __LIBTDB_H__
