/**
 *              Tempesta FW
 *
 * Kernel trace support library.
 *
 * Copyright (C) 2015-2023 Tempesta Technologies, Inc.
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
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tfw
#define TRACE_INCLUDE_FILE trace

#if !defined(__LIB_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __LIB_TRACE_H__

#include <linux/tracepoint.h>
#include <linux/skbuff.h>

TRACE_EVENT(tfw_prepare_xmit_fail,
        TP_PROTO(const struct sk_buff *skb, int r),
        TP_ARGS(skb, r),
        TP_STRUCT__entry(
                __field(unsigned int, skb_len)
                __field(__u8, skb_tls_type)
                __field(__u16, skb_flags)
                __field(int, r)
        ),
        TP_fast_assign(
                __entry->skb_len = skb->len;
                __entry->skb_tls_type = skb->tfw_cb.tls_type;
                __entry->skb_flags = skb->tfw_cb.flags;
                __entry->r  = r;
        ),
        TP_printk("Failed to prepare skb (len(%u) tls_type(%d), flags(%x))"
                  " for xmit[%d]", __entry->skb_len, __entry->skb_tls_type,
                  __entry->skb_flags, __entry->r)
);

#endif /* __LIB_TRACE_H__ */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH TFW_LIB_PWD
#include <trace/define_trace.h>
