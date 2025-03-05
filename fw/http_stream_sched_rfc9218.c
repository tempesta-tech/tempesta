/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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
#ifndef __HTTP_STREAM_SCHED_RFC9218__
#define __HTTP_STREAM_SCHED_RFC9218__

#include "http_stream_sched.h"
#include "http_stream.h"

void
tfw_h2_add_stream_rfc9218_dep(TfwStreamSched *sched, TfwStream *stream)
{
        unsigned urgency = stream->prio.rfc9218_prio.urgency;

        list_add_tail(&stream->prio.rfc9218_prio.node, &sched->array[urgency]);
}

void
tfw_h2_remove_stream_rfc9218_dep(TfwStream *stream)
{
        list_del_init(&stream->prio.rfc9218_prio.node);
}

TfwStream *
tfw_h2_sched_stream_rfc9218_dequeue(TfwStreamSched *sched)
{
        unsigned int i;

        for (i = 0; i <= RFC9218_URGENCY_MAX; i++) {
                if (!list_empty(&sched->array[i])) {
                        struct list_head *first = sched->array[i].next;                         

                        list_del_init(first);
                        return list_entry(first, TfwStream, prio.rfc9218_prio.node);
                }
        }

        return NULL;
}

void
tfw_h2_sched_stream_rfc9218_enqueue(TfwStreamSched *sched, TfwStream *stream)
{
        unsigned urgency = stream->prio.rfc9218_prio.urgency;
        bool incremental = stream->prio.rfc9218_prio.incremental;

        if (!incremental)
                list_add(&stream->prio.rfc9218_prio.node, &sched->array[urgency]);
        else
                list_add_tail(&stream->prio.rfc9218_prio.node, &sched->array[urgency]);
}

#endif /* __HTTP_STREAM_SCHED_RFC9218__ */
