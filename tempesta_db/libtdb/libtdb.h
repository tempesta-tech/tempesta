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
#include <iostream>

#include <tdb_if.h>
#include "exception.h"

class TdbHndl {
public:
	static const size_t MMSZ;

private:
	// Transaction handling helper.
	struct Trx {
		void init() noexcept
		{
			off = 0;
			fr_hdr = nullptr;
			msg_hdr = nullptr;
			tdb_hdr = nullptr;
		}

		Trx() noexcept
		{
			init();
		}

		operator bool() const noexcept
		{
			return !!fr_hdr;
		}

		size_t		off;
		nl_mmap_hdr	*fr_hdr;
		nlmsghdr	*msg_hdr;
		TdbMsg		*tdb_hdr;
	};

	struct LastOpStatus {
		LastOpStatus()
			: rec_n(0)
		{}

		void
		set_copying(bool c) noexcept
		{
			copy = c ? "copied" : "zero-copy";
		}

		void update(const TdbMsg *m) noexcept;

		std::string	op;
		std::string	ret;
		std::string	copy;
		size_t		rec_n;
	};

	friend std::ostream &
	operator<<(std::ostream &os, const LastOpStatus &los);

public:
	TdbHndl(size_t mm_sz);
	~TdbHndl() noexcept;

	void trx_begin();
	void trx_commit();

	void get_info(std::function<void (char *)> data_cb);
	void open_table(std::string &db_path, std::string &tbl_name,
			size_t pages, unsigned int rec_size);
	void close_table(std::string &tbl_name);
	void insert(std::string &tbl_name, size_t klen, size_t vlen,
		    std::function<void (char *, char *)> placement_cb);
	void query(std::string &tbl_name, std::string &key,
		   std::function<void (char *, size_t, char *, size_t)>
			process_cb);

	std::string last_status() noexcept;

private:
	void advance_frame_offset(unsigned int &off) noexcept;
	void lazy_buffer_alloc();
	void alloc_trx_frame() noexcept;
	void send_to_kernel();

	void msg_recv(std::function<bool (nlmsghdr *)> msg_cb);
	void msg_send(std::function<void (nlmsghdr *)> msg_build_cb);

private:
	int fd_;
	size_t ring_sz_;
	unsigned int rx_fr_off_, tx_fr_off_;
	char *rx_ring_, *tx_ring_;
	char *buf_;
	Trx trx_;
	LastOpStatus last_status_;
};

#endif // __LIBTDB_H__
