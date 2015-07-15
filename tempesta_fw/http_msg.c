/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include "gfsm.h"
#include "http.h"
#include "http_msg.h"
#include "lib.h"

/**
 * The function does not free @m->skb_list, the caller is responsible for that.
 */
void
tfw_http_msg_free(TfwHttpMsg *m)
{
	TFW_DBG("Free msg: %p\n", m);

	if (!m)
		return;

	if (m->conn && m->conn->msg == (TfwMsg *)m)
		m->conn->msg = NULL;

	while (1) {
		/*
		 * The skbs are passed to us by put_skb_to_msg() call,
		 * so we're responsible to free them.
		 */
		struct sk_buff *skb = ss_skb_dequeue(&m->msg.skb_list);
		if (!skb)
			break;
		TFW_DBG("free skb %p: truesize=%d sk=%p, destructor=%p"
			" users=%d type=%s\n",
			skb, skb->truesize, skb->sk, skb->destructor,
			atomic_read(&skb->users),
			m->conn && TFW_CONN_TYPE(m->conn) & Conn_Clnt
			? "Conn_Clnt"
			: m->conn && TFW_CONN_TYPE(m->conn) & Conn_Srv
			  ? "Conn_Srv" : "Unknown");
		kfree_skb(skb);
	}
	tfw_pool_free(m->pool);
}
DEBUG_EXPORT_SYMBOL(tfw_http_msg_free);

TfwHttpMsg *
tfw_http_msg_alloc(int type)
{
	TfwHttpMsg *hm = (type & Conn_Clnt)
			 ? (TfwHttpMsg *)tfw_pool_new(TfwHttpReq,
						      TFW_POOL_ZERO)
			 : (TfwHttpMsg *)tfw_pool_new(TfwHttpResp,
						      TFW_POOL_ZERO);
	if (!hm)
		return NULL;

	ss_skb_queue_head_init(&hm->msg.skb_list);

	hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool, TFW_HHTBL_SZ(1));
	hm->h_tbl->size = __HHTBL_SZ(1);
	hm->h_tbl->off = TFW_HTTP_HDR_RAW;
	memset(hm->h_tbl->tbl, 0, __HHTBL_SZ(1) * sizeof(TfwHttpHdr));

	INIT_LIST_HEAD(&hm->msg.msg_list);

	return hm;
}
DEBUG_EXPORT_SYMBOL(tfw_http_msg_alloc);
