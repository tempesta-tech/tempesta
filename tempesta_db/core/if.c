/**
 *		Tempesta DB
 *
 * User-space communication routines.
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
#include <linux/ctype.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#include "htrie.h"
#include "table.h"
#include "tdb_if.h"

static struct sock *nls;
static DEFINE_MUTEX(tdb_if_mtx);

#define TDB_NLMSG_MAXSZ		(NL_FR_SZ / 2 - NLMSG_HDRLEN - sizeof(TdbMsg) \
				 - sizeof(TdbMsgRec))

static int
tdb_if_info(struct sk_buff *skb, struct netlink_callback *cb)
{
	TdbMsg *m;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, TDB_NLMSG_MAXSZ, 0);
	if (!nlh)
		return -EMSGSIZE;

	m = nlmsg_data(nlh);

	/* Fill in response. */
	memcpy(m, cb->data, sizeof(*m));
	m->type |= TDB_NLF_RESP_OK;
	m->rec_n = 1;
	m->recs[0].klen = 0;
	m->recs[0].dlen = tdb_info(m->recs[0].data, TDB_NLMSG_MAXSZ);
	if (m->recs[0].dlen <= 0) {
		nlmsg_cancel(skb, nlh);
		return m->recs[0].dlen;
	}

	return 0; /* end transfer */
}

static int
tdb_if_open_close(struct sk_buff *skb, struct netlink_callback *cb)
{
	TdbMsg *resp_m, *m = cb->data;
	TdbCrTblRec *ct = (TdbCrTblRec *)(m->recs + 1);
	struct nlmsghdr *nlh;

	/* Create status response. */
	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, sizeof(TdbMsg), 0);
	if (!nlh)
		return -EMSGSIZE;

	resp_m = nlmsg_data(nlh);
	resp_m->rec_n = 0;

	if (m->type == TDB_MSG_OPEN) {
		resp_m->type = TDB_MSG_OPEN;
		if (tdb_open(ct->path, ct->tbl_size, ct->rec_size, numa_node_id()))
			resp_m->type |= TDB_NLF_RESP_OK;
	} else {
		TDB *db;

		resp_m->type = TDB_MSG_CLOSE;

		db = tdb_tbl_lookup(m->t_name, TDB_TBLNAME_LEN);
		if (db) {
			tdb_put(db);
			tdb_close(db);
			resp_m->type |= TDB_NLF_RESP_OK;
		} else {
			TDB_WARN("Tried to close non existent table '%s'\n",
				 m->t_name);
		}
	}

	return 0;
}

static int
tdb_if_insert(struct sk_buff *skb, struct netlink_callback *cb)
{
	unsigned int i, off;
	unsigned long key, len;
	TdbMsg *resp_m, *m = cb->data;
	TdbMsgRec *r;
	TdbVRec *vr;
	TdbFRec *fr;
	struct nlmsghdr *nlh;
	TDB *db;

	/* Create status response. */
	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, sizeof(TdbMsg), 0);
	if (!nlh)
		return -EMSGSIZE;

	resp_m = nlmsg_data(nlh);
	resp_m->rec_n = 0;
	resp_m->type = TDB_MSG_INSERT;

	db = tdb_tbl_lookup(m->t_name, TDB_TBLNAME_LEN);
	if (!db) {
		TDB_WARN("Tried to insert into non existent table '%s'\n",
			 m->t_name);
		return 0;
	}

	if (TDB_HTRIE_VARLENRECS(db->hdr)) {
		for (i = 0, off = 0; i < m->rec_n; ++i) {
			r = (TdbMsgRec *)((char *)m->recs + off);
			key = tdb_hash_calc(r->data, r->klen);
			len = TDB_MSGREC_LEN(r);
			vr = (TdbVRec *)tdb_entry_create(db, key, r, &len);
			if (!vr) {
				TDB_ERR("Cannot create variable-size record\n");
				break;
			}
			for ( ; len < TDB_MSGREC_LEN(r); ) {
				vr = tdb_entry_add(db, vr,
						   TDB_MSGREC_LEN(r) - len);
				if (!vr) {
					TDB_ERR("Cannot extend variable-size"
						" record\n");
					break;
				}
				memcpy(vr + 1, r->data + len, vr->len);
				len += vr->len;
			}
			off += TDB_MSGREC_LEN(r);
		}
	} else {
		for (i = 0, off = 0; i < m->rec_n; ++i) {
			r = (TdbMsgRec *)((char *)m->recs + off);
			key = tdb_hash_calc(r->data, r->klen);
			len = TDB_MSGREC_LEN(r);
			fr = (TdbFRec *)tdb_entry_create(db, key, r, &len);
			if (!fr || len != r->dlen) {
				TDB_ERR("Cannot create fixed-size record\n");
				break;
			}
			off += TDB_MSGREC_LEN(r);
		}
	}

	tdb_put(db);
	if (i == m->rec_n)
		resp_m->type |= TDB_NLF_RESP_OK;
	resp_m->rec_n = i;

	return 0;
}

static int
tdb_if_select(struct sk_buff *skb, struct netlink_callback *cb)
{
	TdbIter iter;
	unsigned long key;
	TdbMsg *resp_m, *m = cb->data;
	TdbRec *res;
	struct nlmsghdr *nlh;
	TDB *db;

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, TDB_NLMSG_MAXSZ, 0);
	if (!nlh)
		return -EMSGSIZE;

	resp_m = nlmsg_data(nlh);
	resp_m->rec_n = 0;
	resp_m->type = TDB_MSG_SELECT;

	db = tdb_tbl_lookup(m->t_name, TDB_TBLNAME_LEN);
	if (!db) {
		TDB_WARN("Tried to select from non existent table '%s'\n",
			 m->t_name);
		return 0;
	}

	/*
	 * FIXME implement select of all records:
	 * 1. full HTrie iterator is required;
	 * 2. use many netlink frames to send probably large data set.
	 */
	key = tdb_hash_calc(m->recs[0].data, m->recs[0].klen);
	iter = tdb_rec_get(db, key);
	res = iter.rec;
	if (res) {
		resp_m->rec_n = 1;
		if (TDB_HTRIE_VARLENRECS(db->hdr)) {
			TdbVRec *vr = (TdbVRec *)res;
			size_t off = vr->len;
			memcpy(resp_m->recs, vr->data, vr->len);
			while (1) {
				size_t n = vr->len;
				if (n + off > TDB_NLMSG_MAXSZ) {
					n = TDB_NLMSG_MAXSZ - off;
					resp_m->type |= TDB_NLF_RESP_TRUNC;
				}
				memcpy((char *)resp_m->recs + off, vr->data, n);
				if (n < vr->len || !vr->chunk_next)
					break;
				vr = TDB_PTR(db->hdr, TDB_DI2O(vr->chunk_next));
				off += n;
			}
		}
		else {
			memcpy(resp_m->recs, res->data, db->hdr->rec_len);
		}
		tdb_rec_put(res);
	}

	tdb_put(db);
	/* Only one record is fetched for now. */
	resp_m->type |= TDB_NLF_RESP_OK | TDB_NLF_RESP_END;

	return 0;
}

static const struct {
	int (*dump)(struct sk_buff *, struct netlink_callback *);
} tdb_if_call_tbl[__TDB_MSG_TYPE_MAX] = {
	[TDB_MSG_INFO - __TDB_MSG_BASE]		= { .dump = tdb_if_info },
	[TDB_MSG_OPEN - __TDB_MSG_BASE]		= { .dump = tdb_if_open_close },
	[TDB_MSG_CLOSE - __TDB_MSG_BASE]	= { .dump = tdb_if_open_close },
	[TDB_MSG_INSERT - __TDB_MSG_BASE]	= { .dump = tdb_if_insert },
	[TDB_MSG_SELECT - __TDB_MSG_BASE]	= { .dump = tdb_if_select },
};

static int
tdb_if_check_tblname(const TdbMsg *m)
{
	int i, ret;

	for (i = 0; m->t_name[i] && i < TDB_TBLNAME_LEN; ++i)
		if (!isalnum(m->t_name[i]))
			return false;
	ret = !m->t_name[i];

	if (!ret)
		TDB_ERR("Bad table name %.*s\n", i, m->t_name);

	return ret;
}

static int
tdb_if_proc_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct netlink_ext_ack *extack)
{
	TdbMsg *m;

	if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(TdbMsg)) {
		TDB_ERR("too short netlink msg\n");
		return -EINVAL;
	}

	m = nlmsg_data(nlh);

	/* Check the message type and do consistency checking for each type. */
	switch (m->type) {
	case TDB_MSG_INFO:
		if (m->rec_n || m->t_name[0] != '*' || m->t_name[1] != 0) {
			TDB_ERR("Bad info netlink msg: rec_n=%u t_name=%x%x\n",
				m->rec_n, m->t_name[0], m->t_name[1]);
			return -EINVAL;
		}
		break;
	case TDB_MSG_OPEN:
		if (m->rec_n != 1) {
			TDB_ERR("empty create table msg\n");
			return -EINVAL;
		}
		if (!tdb_if_check_tblname(m))
			return -EINVAL;
		if (m->recs[0].dlen < sizeof(TdbCrTblRec)) {
			TDB_ERR("empty record in create table msg\n");
			return -EINVAL;
		}
		{
			TdbCrTblRec *ct = (TdbCrTblRec *)(m->recs + 1);
			if (!ct->tbl_size || ct->path_len < sizeof(TDB_SUFFIX))
			{
				TDB_ERR("malformed create table msg:"
					" tbl_size=%lu path_len=%u\n",
					ct->tbl_size, ct->path_len);
				return -EINVAL;
			}
		}
		break;
	case TDB_MSG_CLOSE:
		if (m->rec_n) {
			TDB_ERR("Bad close table msg: rec_n=%u\n", m->rec_n);
			return -EINVAL;
		}
		if (!tdb_if_check_tblname(m))
			return -EINVAL;
		break;
	case TDB_MSG_INSERT:
		if (m->rec_n < 1) {
			TDB_ERR("empty insert msg\n");
			return -EINVAL;
		}
		if (!tdb_if_check_tblname(m))
			return -EINVAL;
		break;
	case TDB_MSG_SELECT:
		if (m->rec_n != 1) {
			TDB_ERR("empty select msg\n");
			return -EINVAL;
		}
		if (!tdb_if_check_tblname(m))
			return -EINVAL;
		break;
	default:
		TDB_ERR("bad netlink msg type %u\n", m->type);
		return -EINVAL;
	}

	{
		struct netlink_dump_control c = {
			.dump = tdb_if_call_tbl[m->type - __TDB_MSG_BASE].dump,
			.data = m,
			.min_dump_alloc = NL_FR_SZ / 2,
		};
		return netlink_dump_start(nls, skb, nlh, &c);
	}
}

static void
tdb_if_rcv(struct sk_buff *skb)
{
	/* TODO remove the mutex for concurrent user-space updates. */
	mutex_lock(&tdb_if_mtx);

	netlink_rcv_skb(skb, &tdb_if_proc_msg);

	mutex_unlock(&tdb_if_mtx);
}

static struct netlink_kernel_cfg tdb_if_nlcfg = {
	.input	= tdb_if_rcv,
};

int __init
tdb_if_init(void)
{
	nls = netlink_kernel_create(&init_net, NETLINK_TEMPESTA, &tdb_if_nlcfg);
	if (!nls) {
		TDB_ERR("Failed to create netlink socket\n");
		return -ENOMEM;
	}

	return 0;
}

void __exit
tdb_if_exit(void)
{
	netlink_kernel_release(nls);
}
