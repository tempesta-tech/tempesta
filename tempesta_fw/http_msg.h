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
#ifndef __TFW_HTTP_MSG_H__
#define __TFW_HTTP_MSG_H__

#include "http.h"

typedef struct {
	unsigned int	frag;
	struct sk_buff	*skb;
} TfwMsgIter;

static inline void
tfw_http_msg_set_data(TfwHttpMsg *hm, TfwStr *str, void *data)
{
	str->ptr = data;
	str->skb = ss_skb_peek_tail(&hm->msg.skb_list);
}

void tfw_http_msg_hdr_val(TfwStr *hdr, int id, TfwStr *val);

int tfw_http_msg_add_data_ptr(TfwHttpMsg *hm, TfwStr *str, void *data,
			      size_t len);

int tfw_http_msg_hdr_add(TfwHttpMsg *hm, TfwStr *hdr);
int tfw_http_msg_hdr_xfrm(TfwHttpMsg *hm, char *name, size_t n_len,
			  char *val, size_t v_len, int hid, bool append);

#define TFW_HTTP_MSG_HDR_XFRM(hm, name, val, hid, append)		\
	tfw_http_msg_hdr_xfrm(hm, name, sizeof(name) - 1, val,		\
			      sizeof(val) -1, hid, append)
#define TFW_HTTP_MSG_HDR_DEL(hm, name, hid)				\
	tfw_http_msg_hdr_xfrm(hm, name, sizeof(name) - 1, NULL, 0, hid, 0)

TfwHttpMsg *tfw_http_msg_create(TfwMsgIter *it, int type, size_t data_len);
int tfw_http_msg_write(TfwMsgIter *it, TfwHttpMsg *hm, const TfwStr *data);

void tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start);
void tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len);
void tfw_http_msg_field_chunk_fixup(TfwHttpMsg *hm, TfwStr *field,
				    char *data, int len);
int tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id);
int tfw_http_msg_grow_hdr_tbl(TfwHttpMsg *hm);

TfwHttpMsg *tfw_http_msg_alloc(int type);
void tfw_http_msg_free(TfwHttpMsg *m);
void tfw_http_conn_msg_unlink(TfwHttpMsg *m);

#endif /* __TFW_HTTP_MSG_H__ */
