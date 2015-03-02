/**
 *		Tempesta DB User-space Libabry
 *
 * Handler for database operations.
 *
 * TODO At this time libnl doesn't support netlink mmap interface.
 * Update the code when the library support the feature,
 * track status of https://github.com/thom311/libnl/issues/33.
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
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream> // AK_DBG

#include "libtdb.h"

bool debug = false;

const size_t TdbHndl::MMSZ = 256 * 1024;

/*
 * ------------------------------------------------------------------------
 *	Private helpers
 * ------------------------------------------------------------------------
 */
void
TdbHndl::advance_frame_offset(unsigned int &off) noexcept
{
	off = (off + NL_FR_SZ) % ring_sz_;
}

/**
 * Allocate copy buffer only if we need to fallback to copying.
 */
void
TdbHndl::lazy_buffer_alloc()
{
	if (buf_)
		return;

	if (posix_memalign((void **)&buf_, getpagesize(), NL_FR_SZ))
		throw TdbExcept("cannot allocate copy buffer");
}

void
TdbHndl::msg_recv(std::function<bool (nlmsghdr *)> msg_cb)
{
	// Call poll(2) just for internal netlink mmap flow control.
	pollfd pfds[1];
	do {
		pfds[0].fd	= fd_;
		pfds[0].events	= POLLIN | POLLERR;
		pfds[0].revents	= 0;
		if ((poll(pfds, 1, -1) < 0 && errno != -EINTR)
		    || pfds[0].revents & POLLERR)
			throw TdbExcept("poll failure");
	} while (!(pfds[0].revents & POLLIN));

	for (bool read_more = true; read_more; ) {
		nlmsghdr *nlh;

		// Get next frame header.
		nl_mmap_hdr *hdr = (nl_mmap_hdr *)(rx_ring_ + rx_fr_off_);

		if (hdr->nm_status == NL_MMAP_STATUS_VALID) {
			std::cout << "AK_DBG: zero-copy" << std::endl;
			// Regular memory mapped frame.
			nlh = (nlmsghdr *)((char *)hdr + NL_MMAP_HDRLEN);
			if (!hdr->nm_len) {
				// Release empty message immediately.
				// May happen on error during message
				// construction.
				hdr->nm_status = NL_MMAP_STATUS_UNUSED;
				throw TdbExcept("cannot recv msg");
			}
		}
		else if (hdr->nm_status == NL_MMAP_STATUS_COPY) {
			std::cout << "AK_DBG: copying" << std::endl;
			lazy_buffer_alloc();

			// Frame is queued to socket receive queue.
			ssize_t r = recv(fd_, buf_, NL_FR_SZ, MSG_DONTWAIT);
			if (r <= 0)
				throw TdbExcept("cannot copy msg");
			nlh = (nlmsghdr *)buf_;
		} else
			throw TdbExcept("cannot read expected msg");

		read_more = msg_cb(nlh);

		// Release frame back to the kernel.
		hdr->nm_status = NL_MMAP_STATUS_UNUSED;

		advance_frame_offset(rx_fr_off_);
	}
}

void
TdbHndl::msg_send(std::function<void (nlmsghdr *)> msg_build_cb)
{
	nl_mmap_hdr *hdr = (nl_mmap_hdr *)(tx_ring_ + tx_fr_off_);
	if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		throw TdbExcept("no tx frame available");

	nlmsghdr *nlh = (nlmsghdr *)((char *)hdr + NL_MMAP_HDRLEN);

	msg_build_cb(nlh);

	// Fill frame header: length and status need to be set.
	hdr->nm_len = nlh->nlmsg_len;
	hdr->nm_status = NL_MMAP_STATUS_VALID;

	sockaddr_nl addr = {
		.nl_family	= AF_NETLINK,
	};
	if (sendto(fd_, NULL, 0, 0, (const sockaddr *)&addr, sizeof(addr)) < 0)
		throw TdbExcept("cannot send msg to kernel");

	advance_frame_offset(tx_fr_off_);
}

/*
 * ------------------------------------------------------------------------
 *	Public members
 * ------------------------------------------------------------------------
 */
void
TdbHndl::get_info(std::function<void (TdbMsg *)> data_cb)
{
	msg_send([=](nlmsghdr *nlh) {
		nlh->nlmsg_len = sizeof(*nlh) + sizeof(TdbMsg);
		nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;
		nlh->nlmsg_flags |= NLM_F_REQUEST;

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		memset(m, 0, sizeof(*m));
		m->type = TDB_MSG_INFO;
		m->t_name[0] = '*'; // show all tables
	});

	msg_recv([&data_cb](nlmsghdr *nlh) -> bool {
		// Consistency checking.
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg)
				     + sizeof(TdbMsgRec))
			throw TdbExcept("bad info msg len %u", nlh->nlmsg_len);

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (m->type != TDB_MSG_INFO || m->rec_n != 1)
			throw TdbExcept("malformed info msg type=%u rec_n=%u",
					m->type, m->rec_n);
		if (m->recs[0].klen || !m->recs[0].dlen)
			throw TdbExcept("malformed info msg record"
					" klen=%u dlen=%u",
					m->recs[0].klen, m->recs[0].dlen);

		data_cb(m);

		return false; // info is single-frame message
	});
}

void
TdbHndl::open_table(std::string &db_path, std::string &tbl_name,
		    size_t pages, unsigned int rec_size)
{
	size_t tbl_size = pages * getpagesize();

	if (tbl_name.length() > TDB_TBLNAME_LEN)
		throw TdbExcept("too long table name");
	if (tbl_size & ~TDB_EXT_MASK)
		throw TdbExcept("table size must be multiple of extent size");

	msg_send([&db_path, &tbl_name, tbl_size, rec_size](nlmsghdr *nlh) {
		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		m->type = TDB_MSG_OPEN;
		m->rec_n = 1;
		db_path.copy(m->t_name, TDB_TBLNAME_LEN);

		std::string p = db_path + "/" + tbl_name + TDB_SUFFIX;

		TdbCrTblRec *ct = (TdbCrTblRec *)(m->recs + 1);
		ct->tbl_size = tbl_size;
		ct->rec_size = rec_size;
		ct->path_len = p.length();
		p.copy(ct->path, ct->path_len);

		m->recs[0].klen = 0;
		m->recs[0].dlen = sizeof(*ct) + ct->path_len;

		nlh->nlmsg_len = sizeof(*nlh) + sizeof(*m) + sizeof(TdbMsgRec)
				 + m->recs[0].dlen;
		nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;
		nlh->nlmsg_flags |= NLM_F_REQUEST;
	});

	// Just check for status message.
	msg_recv([=](nlmsghdr *nlh) -> bool {
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg))
			throw TdbExcept("bad create table status msg");

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (m->type != (TDB_MSG_OPEN | TDB_NLF_RESP_OK))
			throw TdbExcept("cannot create table, see dmesg");

		return false;
	});
}

void
TdbHndl::close_table(std::string &tbl_name)
{
	if (tbl_name.length() > TDB_TBLNAME_LEN)
		throw TdbExcept("too long table name");

	msg_send([&tbl_name](nlmsghdr *nlh) {
		nlh->nlmsg_len = sizeof(*nlh) + sizeof(TdbMsg);
		nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;
		nlh->nlmsg_flags |= NLM_F_REQUEST;

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		memset(m, 0, sizeof(*m));
		m->type = TDB_MSG_CLOSE;
		tbl_name.copy(m->t_name, TDB_TBLNAME_LEN);
	});

	// Just check for status message.
	msg_recv([=](nlmsghdr *nlh) -> bool {
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg))
			throw TdbExcept("bad close table status msg");

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (m->type != (TDB_MSG_CLOSE | TDB_NLF_RESP_OK))
			throw TdbExcept("cannot close table, see dmesg");

		return false;
	});
}

TdbHndl::TdbHndl(size_t mm_sz)
	: ring_sz_(mm_sz / 2),
	rx_fr_off_(0),
	tx_fr_off_(0),
	buf_(NULL)
{
	fd_ = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_TEMPESTA);
	if (fd_ < 0)
		throw TdbExcept("cannot create netlink socket");

	sockaddr_nl addr = {
		.nl_family	= AF_NETLINK,
	};
	addr.nl_pid = getpid();
	if (bind(fd_, (const sockaddr *)&addr, sizeof(addr)))
		throw TdbExcept("cannot bind netlink socket");

	unsigned int blk_sz = 16 * getpagesize();
	nl_mmap_req req = {
		.nm_block_size	= blk_sz,
		.nm_block_nr	= (unsigned int)(ring_sz_ / blk_sz),
		.nm_frame_size	= NL_FR_SZ,
		.nm_frame_nr	= (unsigned int)(ring_sz_ / NL_FR_SZ),
	};

	// Configure ring parameters.
	if (setsockopt(fd_, SOL_NETLINK, NETLINK_RX_RING,
		       &req, sizeof(req)) < 0)
		throw TdbExcept("cannot setup netlink rx ring");
	if (setsockopt(fd_, SOL_NETLINK, NETLINK_TX_RING,
		       &req, sizeof(req)) < 0)
		throw TdbExcept("cannot setup netlink tx ring");

	// Map RX/TX rings. The TX ring is located after the RX ring.
	rx_ring_ = (char *)mmap(NULL, mm_sz, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd_, 0);
	if ((long)rx_ring_ == -1L)
		throw TdbExcept("cannot mmap() netlink rings");

	tx_ring_ = rx_ring_ + ring_sz_;
}

TdbHndl::~TdbHndl() noexcept
{
	free(buf_);

	munmap(rx_ring_, ring_sz_ * 2);
	close(fd_);
}
