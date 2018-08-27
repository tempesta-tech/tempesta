/**
 *		Tempesta DB User-space Library
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

#include <sstream>

#include "libtdb.h"

bool debug = false;

const size_t TdbHndl::MMSZ = 256 * 1024;

/*
 * ------------------------------------------------------------------------
 *	Private helpers
 * ------------------------------------------------------------------------
 */
void
TdbHndl::LastOpStatus::update(const TdbMsg *m) noexcept
{
	switch (m->type & TDB_NLF_TYPE_MASK) {
	case TDB_MSG_INFO:
		op = "INFO";
		break;
	case TDB_MSG_OPEN:
		op = "OPEN";
		break;
	case TDB_MSG_CLOSE:
		op = "CLOSE";
		break;
	case TDB_MSG_INSERT:
		op = "INSERT";
		break;
	case TDB_MSG_SELECT:
		op = "SELECT";
		break;
	default:
		op = "[unspecified]";
	}
	ret = (m->type & TDB_NLF_RESP_OK) ? "OK" : "FAILED";
	if (m->type & TDB_NLF_RESP_TRUNC)
		ret += ",Truncated";
	rec_n = m->rec_n;
}

std::ostream &
operator<<(std::ostream &os, const TdbHndl::LastOpStatus &los)
{
	os << los.op << ": records=" << los.rec_n << " status=" << los.ret
	   << " " << los.copy;

	return os;
}

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
			last_status_.set_copying(false);
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
			last_status_.set_copying(true);
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
TdbHndl::send_to_kernel()
{
	sockaddr_nl addr = {
		.nl_family	= AF_NETLINK,
	};
	if (sendto(fd_, NULL, 0, 0, (const sockaddr *)&addr, sizeof(addr)) < 0)
		throw TdbExcept("cannot send msg to kernel");

	advance_frame_offset(tx_fr_off_);
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

	send_to_kernel();
}

/*
 * ------------------------------------------------------------------------
 *	Public members
 * ------------------------------------------------------------------------
 */
void
TdbHndl::alloc_trx_frame() noexcept
{
	trx_.init();

	trx_.fr_hdr = (nl_mmap_hdr *)(tx_ring_ + tx_fr_off_);
	if (trx_.fr_hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		throw TdbExcept("no tx frame available");

	// Pack only one message per frame.
	trx_.msg_hdr = (nlmsghdr *)((char *)trx_.fr_hdr + NL_MMAP_HDRLEN);
	trx_.msg_hdr->nlmsg_type = NLMSG_MIN_TYPE + 1;
	trx_.msg_hdr->nlmsg_flags |= NLM_F_REQUEST;

	trx_.tdb_hdr = (TdbMsg *)NLMSG_DATA(trx_.msg_hdr);
	memset(trx_.tdb_hdr, 0, sizeof(TdbMsg));
}

void
TdbHndl::trx_begin()
{
	if (trx_)
		throw TdbExcept("nested trx!");

	alloc_trx_frame();
}

/**
 * Send all pending frames.
 */
void
TdbHndl::trx_commit()
{
	trx_.msg_hdr->nlmsg_len = sizeof(*trx_.msg_hdr) + sizeof(*trx_.tdb_hdr)
				  + trx_.off;
	trx_.fr_hdr->nm_len = trx_.msg_hdr->nlmsg_len;
	trx_.fr_hdr->nm_status = NL_MMAP_STATUS_VALID;

	send_to_kernel();

	trx_.init();

	// Check trx status.
	msg_recv([this](nlmsghdr *nlh) -> bool {
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg))
			throw TdbExcept("bad transaction status msg");

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (!(m->type & TDB_NLF_RESP_OK))
			throw TdbExcept("transaction failed, see dmesg");

		last_status_.update(m);

		return false;
	});
}

void
TdbHndl::get_info(std::function<void (char *)> data_cb)
{
	if (trx_)
		throw TdbExcept("cannot run the action inside transaction");

	msg_send([=](nlmsghdr *nlh) {
		nlh->nlmsg_len = sizeof(*nlh) + sizeof(TdbMsg);
		nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;
		nlh->nlmsg_flags |= NLM_F_REQUEST;

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		memset(m, 0, sizeof(*m));
		m->type = TDB_MSG_INFO;
		m->t_name[0] = '*'; // show all tables
	});

	msg_recv([this, &data_cb](nlmsghdr *nlh) -> bool {
		// Consistency checking.
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg)
				     + sizeof(TdbMsgRec))
			throw TdbExcept("bad info msg len %u", nlh->nlmsg_len);

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (m->type != (TDB_MSG_INFO | TDB_NLF_RESP_OK)
		    || m->rec_n != 1)
			throw TdbExcept("malformed info msg type=%u rec_n=%u",
					m->type, m->rec_n);
		if (m->recs[0].klen || !m->recs[0].dlen)
			throw TdbExcept("malformed info msg record"
					" klen=%u dlen=%u",
					m->recs[0].klen, m->recs[0].dlen);

		data_cb(m->recs[0].data);

		last_status_.update(m);

		return false; // info is single-frame message
	});
}

void
TdbHndl::open_table(std::string &db_path, std::string &tbl_name,
		    size_t pages, unsigned int rec_size)
{
	if (trx_)
		throw TdbExcept("cannot run the action inside transaction");

	size_t tbl_size = pages * getpagesize();

	if (tbl_name.length() > TDB_TBLNAME_LEN)
		throw TdbExcept("too long table name");
	if (tbl_size & ~TDB_EXT_MASK)
		throw TdbExcept("table size must be multiple of extent size");

	msg_send([&db_path, &tbl_name, tbl_size, rec_size](nlmsghdr *nlh) {
		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		m->type = TDB_MSG_OPEN;
		m->rec_n = 1;
		tbl_name.copy(m->t_name, TDB_TBLNAME_LEN);
		m->t_name[tbl_name.length()] = 0;

		std::string p = db_path + "/" + tbl_name + TDB_SUFFIX;

		TdbCrTblRec *ct = (TdbCrTblRec *)(m->recs + 1);
		ct->tbl_size = tbl_size;
		ct->rec_size = rec_size;
		ct->path_len = p.length() + 1;
		p.copy(ct->path, p.length());
		ct->path[p.length()] = 0;

		m->recs[0].klen = 0;
		m->recs[0].dlen = sizeof(*ct) + ct->path_len;

		nlh->nlmsg_len = sizeof(*nlh) + sizeof(*m)
				 + TDB_MSGREC_LEN(&m->recs[0]);
		nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;
		nlh->nlmsg_flags |= NLM_F_REQUEST;
	});

	// Just check for status message.
	msg_recv([=](nlmsghdr *nlh) -> bool {
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg))
			throw TdbExcept("bad open table status msg");

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (m->type != (TDB_MSG_OPEN | TDB_NLF_RESP_OK))
			throw TdbExcept("cannot open table, see dmesg");

		last_status_.update(m);

		return false;
	});
}

void
TdbHndl::close_table(std::string &tbl_name)
{
	if (trx_)
		throw TdbExcept("cannot run the action inside transaction");

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
		m->t_name[tbl_name.length()] = 0;
	});

	// Just check for status message.
	msg_recv([=](nlmsghdr *nlh) -> bool {
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg))
			throw TdbExcept("bad close table status msg");

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if (m->type != (TDB_MSG_CLOSE | TDB_NLF_RESP_OK))
			throw TdbExcept("cannot close table, see dmesg");

		last_status_.update(m);

		return false;
	});
}

void
TdbHndl::insert(std::string &tbl_name, size_t klen, size_t vlen,
		std::function<void (char *, char *)> placement_cb)
{
	static const size_t HDRS_LEN = sizeof(nl_mmap_hdr) + sizeof(TdbMsg)
				       + sizeof(TdbMsgRec);
	bool in_trx = trx_;

	if (!in_trx)
		trx_begin();

	if (trx_.off + sizeof(nlmsghdr) + sizeof(TdbMsgRec) + klen + vlen
	    > NL_FR_SZ)
	{
		// Not enough space in current frame, allocate a new one.
		advance_frame_offset(tx_fr_off_);
		alloc_trx_frame();
	}
	if (klen + vlen + HDRS_LEN > NL_FR_SZ)
		throw TdbExcept("too large data for one insertion");

	if (!trx_.tdb_hdr->type || !trx_.tdb_hdr->t_name[0]) {
		// New transaction.
		trx_.tdb_hdr->type = TDB_MSG_INSERT;
		tbl_name.copy(trx_.tdb_hdr->t_name, TDB_TBLNAME_LEN);
		trx_.tdb_hdr->t_name[tbl_name.length()] = 0;
	}

	TdbMsgRec *r = (TdbMsgRec *)((char *)trx_.tdb_hdr->recs + trx_.off);
	r->klen = klen;
	r->dlen = vlen;

	placement_cb(r->data, TDB_MSGREC_DATA(r));

	++trx_.tdb_hdr->rec_n;
	trx_.off += TDB_MSGREC_LEN(r);

	if (!in_trx)
		trx_commit();
}

void
TdbHndl::query(std::string &tbl_name, std::string &key,
	       std::function<void (char *, size_t, char *, size_t)> process_cb)
{
	if (trx_)
		throw TdbExcept("cannot run the action inside transaction");

	if (tbl_name.length() > TDB_TBLNAME_LEN)
		throw TdbExcept("too long table name");

	msg_send([&tbl_name, &key](nlmsghdr *nlh) {
		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		m->type = TDB_MSG_SELECT;
		m->rec_n = 1;
		tbl_name.copy(m->t_name, tbl_name.length());
		m->t_name[tbl_name.length()] = 0;

		m->recs[0].klen = key.length();
		m->recs[0].dlen = 0;
		key.copy(m->recs[0].data, m->recs[0].klen);

		nlh->nlmsg_len = sizeof(*nlh) + sizeof(*m) + sizeof(TdbMsgRec)
				 + m->recs[0].klen;
		nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;
		nlh->nlmsg_flags |= NLM_F_REQUEST;
	});

	// Read results.
	msg_recv([this, &process_cb](nlmsghdr *nlh) -> bool {
		if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg))
			throw TdbExcept("bad info msg len %u", nlh->nlmsg_len);

		TdbMsg *m = (TdbMsg *)NLMSG_DATA(nlh);
		if ((m->type & TDB_MSG_SELECT) != TDB_MSG_SELECT
		    || nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg)
					+ m->rec_n * sizeof(TdbMsgRec))
			throw TdbExcept("malformed query results type=%u rec_n=%u",
					m->type, m->rec_n);
		if (!(m->type & TDB_NLF_RESP_OK))
			throw TdbExcept("cannot execute query, see dmesg");

		for (unsigned int i = 0, off = 0; i < m->rec_n; ++i) {
			TdbMsgRec *r = (TdbMsgRec *)((char *)m->recs + off);
			process_cb(r->data, r->klen,
				   TDB_MSGREC_DATA(r), r->dlen);
			off += TDB_MSGREC_LEN(r);
		}

		if (m->type & TDB_NLF_RESP_END)
			last_status_.update(m);

		return !(m->type & TDB_NLF_RESP_END);
	});

}

std::string
TdbHndl::last_status() noexcept
{
	std::stringstream ss;

	ss << last_status_;

	return ss.str();
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
