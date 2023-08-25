/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2023 Tempesta Technologies, Inc.
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

#include "http_types.h"

#define TFW_STREAM_SCHED_ENTRY_COUNT 64

/**
 * @node	- entry in appropriate scheduler anchor;
 * @deficit	- value which used in calculation of the offset of
 *		  the stream in the priority array;
 * @offset	- offset of the stream in the priority array;
 */
typedef struct tfw_stream_sched_entry_link_t {
	struct list_head node;
	size_t deficit;
	size_t offset;
} TfwStreamSchedEntryLink;

/**
 * @active_cnt	- count of active streams for this anchor;
 * @head	- list head of the streams
 */
typedef struct tfw_stream_sched_entry_anchor_t {
	long int active_cnt;
	struct list_head head;
} TfwStreamSchedEntryAnchor;

/**
 * @bits	 - bitfield for fast determination of the first
 *		   active anchor;
 * @total_weight - total weight of the streams for this scheduler;
 * @active_cnt	 - count of active child streams for this scheduler;
 * @parent	 - parent scheduler;
 * @anchors	 - array of the list of streams;
 */ 
typedef struct tfw_stream_sched_entry_t {
	unsigned long bits;
	size_t total_weight;
	long int active_cnt;
	struct tfw_stream_sched_entry_t *parent;
	TfwStreamSchedEntryAnchor anchors[TFW_STREAM_SCHED_ENTRY_COUNT];
} TfwStreamSchedEntry;

/**
 * Scheduler for stream's processing distribution based on dependency/priority
 * values.
 *
 * @streams	- root red-black tree entry for per-connection streams storage;
 * @root	- root scheduler of per-connection priority tree;
 */
typedef struct tfw_stream_sched_t {
	struct rb_root streams;
	TfwStreamSchedEntry root;
} TfwStreamSched;

void tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id,
			    TfwStreamSchedEntry **dep);
void tfw_h2_add_stream_dep(TfwStream *stream, TfwStreamSchedEntry *dep, bool excl);
void tfw_h2_remove_stream_dep(TfwStream *stream);
void tfw_h2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			      unsigned int new_dep, unsigned short new_weight,
			      bool excl);

void tfw_h2_stream_schred_remove(TfwStream *stream);
void tfw_h2_sched_stream_enqueue(TfwStream *stream,
				 TfwStreamSchedEntry *parent);
TfwStream *tfw_h2_sched_stream_dequeue(TfwStreamSchedEntry *entry,
				       TfwStreamSchedEntry **parent);
void tfw_h2_sched_activate_stream(TfwStream *stream);

static inline bool
tfw_h2_stream_sched_is_active(TfwStreamSchedEntry *sched)
{
	return sched->active_cnt;
}

static inline void
tfw_h2_init_stream_sched_link(TfwStreamSchedEntryLink *link)
{
	link->deficit = link->offset = 0;
	INIT_LIST_HEAD(&link->node);
}

static inline void
tfw_h2_init_stream_sched_entry_anchor(TfwStreamSchedEntryAnchor *anchor)
{
	anchor->active_cnt = 0;
	INIT_LIST_HEAD(&anchor->head);
}

static inline void
tfw_h2_init_stream_sched_entry(TfwStreamSchedEntry *entry)
{
	size_t i;

	entry->bits = entry->total_weight = entry->active_cnt = 0;
	entry->parent = NULL;
	for (i = 0; i < TFW_STREAM_SCHED_ENTRY_COUNT; i++)
		tfw_h2_init_stream_sched_entry_anchor(&entry->anchors[i]);
}

static inline void
tfw_h2_init_stream_sched(TfwStreamSched *sched)
{
	sched->streams = RB_ROOT;
	tfw_h2_init_stream_sched_entry(&sched->root);
}

#endif /* __HTTP_STREAM_SCHED__ */
