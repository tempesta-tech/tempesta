/**
 *		Tempesta FW
 *
 * Copyright (C) 2023 Tempesta Technologies, Inc.
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
#ifndef __HTTP_STREAM_SCHED__
#define __HTTP_STREAM_SCHED__

#include <linux/rbtree.h>
#include <linux/list.h>

#include "lib/eb64tree.h"
#include "http_types.h"

/**
 * @total_weight - total weight of the streams for this scheduler;
 * @active_cnt	 - count of active child streams for this scheduler;
 * @parent	 - parent scheduler;
 * @active	 - root of the active streams scheduler ebtree;
 * @blocked	 - root of the blocked streams scheduler ebtree;
 */ 
typedef struct tfw_stream_sched_entry_t {
	u64				total_weight;
	long int			active_cnt;
	struct tfw_stream_sched_entry_t	*parent;
	struct eb_root			active;
	struct eb_root			blocked;
} TfwStreamSchedEntry;

/**
 * Scheduler for stream's processing distribution based on dependency/priority
 * values.
 *
 * @streams		- root red-black tree entry for per-connection streams storage;
 * @root		- root scheduler of per-connection priority tree;
 * @blocked_streams	- count of blocked streams;
 */
typedef struct tfw_stream_sched_t {
	struct rb_root		streams;
	TfwStreamSchedEntry	root;
	long int		blocked_streams;
} TfwStreamSched;

TfwStreamSchedEntry *tfw_h2_find_stream_dep(TfwStreamSched *sched,
					    unsigned int id);
void tfw_h2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream,
			   TfwStreamSchedEntry *dep, bool excl);
void tfw_h2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream);
void tfw_h2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			      unsigned int new_dep, unsigned short new_weight,
			      bool excl);

void tfw_h2_stream_sched_remove(TfwStreamSched *sched, TfwStream *stream);
void tfw_h2_sched_stream_enqueue(TfwStreamSched *sched, TfwStream *stream,
				 TfwStreamSchedEntry *parent, u64 deficit);
TfwStream *tfw_h2_sched_stream_dequeue(TfwStreamSched *sched,
				       TfwStreamSchedEntry **parent);
void tfw_h2_sched_activate_stream(TfwStreamSched *sched, TfwStream *stream);

static inline bool
tfw_h2_stream_sched_is_active(TfwStreamSchedEntry *sched)
{
	return sched->active_cnt;
}

static inline void
tfw_h2_init_stream_sched_entry(TfwStreamSchedEntry *entry)
{
	entry->total_weight = entry->active_cnt = 0;
	entry->parent = NULL;
	entry->blocked = entry->active = EB_ROOT;
}

static inline void
tfw_h2_init_stream_sched(TfwStreamSched *sched)
{
	sched->streams = RB_ROOT;
	tfw_h2_init_stream_sched_entry(&sched->root);
}

#endif /* __HTTP_STREAM_SCHED__ */
