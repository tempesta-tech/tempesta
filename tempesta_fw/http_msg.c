/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

TfwHttpMsg *
tfw_http_msg_alloc(int type)
{
	TfwHttpMsg *hm = (type & Conn_Clnt)
			 ? (TfwHttpMsg *)tfw_pool_new(TfwHttpReq, TFW_POOL_ZERO)
			 : (TfwHttpMsg *)tfw_pool_new(TfwHttpResp, TFW_POOL_ZERO);
	if (!hm)
		return NULL;

	skb_queue_head_init(&hm->msg.skb_list);
	hm->msg.prev = NULL;
	hm->msg.len = 0;

	hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool, TFW_HHTBL_SZ(1));
	hm->h_tbl->size = __HHTBL_SZ(1);
	hm->h_tbl->off = 0;
	memset(hm->h_tbl->tbl, 0, __HHTBL_SZ(1) * sizeof(TfwHttpHdr));

	return hm;
}

/**
 * The function does not free @m->skb_list, the caller is responsible for that.
 */
void
tfw_http_msg_free(TfwHttpMsg *m)
{
	while (1) {
		struct sk_buff *skb = skb_dequeue(&m->msg.skb_list);
		if (!skb)
			break;
		kfree_skb(skb);
	}
	tfw_pool_free(m->pool);
}


