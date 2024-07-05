/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* SPDX-FileCopyrightText: Copyright 2022 G-Core Labs S.A. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rex

#if !defined(_TRACE_REX_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_REX_H

#include <linux/tracepoint.h>
#include "rex.h"

TRACE_EVENT(rex_match, TP_PROTO(struct rex_scan_attr *ctx),

	    TP_ARGS(ctx),

	    TP_STRUCT__entry(__field(__u32, database_id) __field(__u32,
								 event_index)
				     __field_struct(struct rex_event, event)),

	    TP_fast_assign(__entry->database_id = ctx->database_id;
			   __entry->event_index = ctx->nr_events;
			   __entry->event = ctx->last_event;),

	    TP_printk("regex=%u/%u at [%llu, %llu]", __entry->database_id,
		      __entry->event.expression, __entry->event.from,
		      __entry->event.to));

#endif /* _TRACE_REX_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE rex_trace

/* This part must be outside protection */
#include <trace/define_trace.h>
