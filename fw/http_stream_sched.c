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
#include "http_stream_sched.h"
#include "http_stream.h"

static void
tfw_h2_stream_sched_add_active_cnt(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt = stream->sched.active_cnt + (stream_is_active ? 1 : 0);

	while (parent) {
		TfwStreamSchedEntryAnchor *anchor =
			parent->anchors + stream->link.offset;
		TfwStream *next = container_of(parent, TfwStream, sched);

		list_del_init(&stream->link.node);

		if (tfw_h2_stream_is_active(stream)
		    || tfw_h2_stream_sched_is_active(&stream->sched))
			list_add(&stream->link.node, &anchor->head);
		else
			list_add_tail(&stream->link.node, &anchor->head);

		parent->active_cnt += active_cnt;
		anchor->active_cnt += active_cnt;

		if (anchor->active_cnt) {
			parent->bits |=
				1ULL << (sizeof(parent->bits) * 8 -
				1 - stream->link.offset);
		}

		stream = next;
		parent = stream->sched.parent;
	}
}

static void
tfw_h2_stream_sched_dec_active_cnt(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt = stream->sched.active_cnt + (stream_is_active ? 1 : 0);

	while (parent) {
		TfwStreamSchedEntryAnchor *anchor =
			parent->anchors + stream->link.offset;
		TfwStream *next = container_of(parent, TfwStream, sched);

		parent->active_cnt -= active_cnt;
		anchor->active_cnt -= active_cnt;

		BUG_ON(parent->active_cnt < 0 || anchor->active_cnt < 0);

		if (!anchor->active_cnt) {
			parent->bits &=
				~(1ULL << (sizeof(parent->bits) * 8 -
				  1 - stream->link.offset));
		}

		stream = next;
		parent = stream->sched.parent;
	}
}

void
tfw_h2_stream_schred_remove(TfwStream *stream)
{
	TfwStreamSchedEntry *sched = stream->sched.parent;

	tfw_h2_stream_sched_dec_active_cnt(stream);
	list_del_init(&stream->link.node);
	stream->sched.parent = NULL;
	sched->total_weight -= stream->weight;
}

void
tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id, TfwStreamSchedEntry **dep)
{
	*dep = NULL;

	if (id) {
		TfwStream *stream = tfw_h2_find_stream(sched, id);
		if (stream)
			*dep = &stream->sched;
	}
	/*
	 * RFC 7540 5.3.1:
	 * A dependency on a stream that is not currently in the tree -- such
	 * as a stream in the "idle" state -- results in that stream being
	 * given a default priority.
	 */
	if (!(*dep))
		*dep = &sched->root;
}

void
tfw_h2_add_stream_dep(TfwStream *stream, TfwStreamSchedEntry *dep, bool excl)
{
	unsigned int i;

	if (!excl)
		return tfw_h2_sched_stream_enqueue(stream, dep);

	for (i = 0; i < TFW_STREAM_SCHED_ENTRY_COUNT; i++) {
		struct list_head *cur, *tmp;

		list_for_each_safe(cur, tmp, &dep->anchors[i].head) {
			TfwStreamSchedEntryLink *link = container_of(cur, TfwStreamSchedEntryLink, node);
			TfwStream *child = container_of(link, TfwStream, link);

			tfw_h2_stream_schred_remove(child);
			tfw_h2_sched_stream_enqueue(child, &stream->sched);
		}
	}

	return tfw_h2_sched_stream_enqueue(stream, dep);
}

void
tfw_h2_remove_stream_dep(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	size_t total_weight = stream->sched.total_weight;
	unsigned int i = 0;

	/* Remove stream from the parent scheduler. */
	tfw_h2_stream_schred_remove(stream);

	/*
	 * According to RFC 7540 section 5.3.4:
	 * If the parent stream is removed from the tree, the weight of the
	 * parent stream is divided between it's childs according to there
	 * weights.
	 */ 
	for (i = 0; i < TFW_STREAM_SCHED_ENTRY_COUNT; i++) {
		struct list_head *cur, *tmp;

		list_for_each_safe(cur, tmp, &stream->sched.anchors[i].head) {
			TfwStreamSchedEntryLink *link =
				container_of(cur, TfwStreamSchedEntryLink, node);
			TfwStream *child = container_of(link, TfwStream, link);
			unsigned short new_weight;

			/*
			 * Remove childs of the removed stream, recalculate there
			 * weights and add them to the scheduler of the parent of
			 * the removed stream. 
			 */
			tfw_h2_stream_schred_remove(child);

			new_weight = child->weight *
				stream->weight / total_weight;

			child->weight = new_weight > 0 ? new_weight : 1;
			tfw_h2_sched_stream_enqueue(child, parent);
		}
	} 
}

/**
 * Check if the stream is now depends from it's child.
 */
static bool
tfw_h2_is_stream_depend_from_child(TfwStream *stream, TfwStream *new_parent)
{
	TfwStreamSchedEntry *parent = new_parent->sched.parent;

	while (parent) {
		TfwStream *next = container_of(parent, TfwStream, sched);

		if (next == stream)
			return true;

		new_parent = next;
		parent = new_parent->sched.parent;
	}

	return false;
}

/**
 * Function wrapper to chnge stream weight. Should be called
 * only when stream and it's scheduler is unlinked from the
 * dependency tree.
 */
static void
tfw_h2_change_stream_weight(TfwStream *stream, unsigned short new_weight)
{
	stream->weight = new_weight;
	BUG_ON(stream->sched.parent || !list_empty(&stream->link.node));
	tfw_h2_init_stream_sched_link(&stream->link);
}

void
tfw_h2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			 unsigned int new_dep, unsigned short new_weight,
			 bool excl)
{
	TfwStreamSchedEntry *old_parent, *new_parent;
	TfwStream *stream, *np;
	bool is_stream_depends_from_child;

	stream = tfw_h2_find_stream(sched, stream_id);
	BUG_ON(!stream);
	old_parent = stream->sched.parent;
	BUG_ON(!old_parent);

	tfw_h2_find_stream_dep(sched, new_dep, &new_parent);

	is_stream_depends_from_child =
		tfw_h2_is_stream_depend_from_child(stream,
						   container_of(new_parent,
						   		TfwStream,
						   		sched));

	if (!is_stream_depends_from_child) {
		/*
		 * If stream is not dependent from it's child, just remove
		 * this stream change it's weight and add stream to the
		 * new parent.
		 * The order of calling next functions is important:
		 * 1. First we should remove current stream from the
		 *    dependency tree (with recalculation of total
		 *    weight of parent schedulers).
		 * 2. Change stream weight with reinition of the
		 *    stream link.
		 * 3. Insert stream in the dependency tree as a
		 *    child of the new parent.
		 */
		tfw_h2_stream_schred_remove(stream);
		tfw_h2_change_stream_weight(stream, new_weight);
		tfw_h2_add_stream_dep(stream, new_parent, excl);
	} else {
		/*
		 * If stream is dependent from it's child, remove this
		 * child from the dependency tree, put it to the location
		 * of the current stream and then add stream to this stream.
		 * (See RFC 7540 section 5.3.3).
		 * The order of calling next functions is important:
		 * 1. Remove new parent, which is a child of current stream.
		 *    (with recalculation of weight and active count of current
		 *    stream scheduler).
		 * 2. Remove current stream from the dependency tree.
		 * 3. Change stream weight and insert new parent and stream
		 *    according RFC 7540.
		 */
		BUG_ON(new_parent == &sched->root);
		np = container_of(new_parent, TfwStream, sched);

		tfw_h2_stream_schred_remove(np);
		tfw_h2_stream_schred_remove(stream);
		tfw_h2_change_stream_weight(stream, new_weight);
		tfw_h2_add_stream_dep(np, old_parent, false);
		tfw_h2_add_stream_dep(stream, new_parent, excl);
	}

}

void
tfw_h2_sched_stream_enqueue(TfwStream *stream, TfwStreamSchedEntry *parent)
{
	/*
	 * Holds 256 entries of offsets (multiplied by 65536) where nodes
	 * with weights between 1..256 should go into each entry (except
	 * for weight=256) is calculated as: round(N / weight), where N
	 * is adjusted so that the value would become 63*65536 for weight=0.
	 */
	static const unsigned offset_tbl[] = {
		4128768, 2064384, 1376256, 1032192, 825754, 688128, 589824,
		516096, 458752, 412877, 375343, 344064, 317598, 294912,
		275251, 258048, 242869, 229376, 217304, 206438, 196608,
		187671, 179512, 172032, 165151, 158799, 152917, 147456,
		142371, 137626, 133186, 129024, 125114, 121434, 117965,
		114688, 111588, 108652, 105866, 103219, 100702, 98304,
		96018, 93836, 91750, 89756, 87846, 86016, 84261, 82575,
		80956, 79399, 77901, 76459, 75069, 73728, 72435, 71186,
		69979, 68813, 67685, 66593, 65536, 64512, 63520, 62557,
		61623, 60717, 59837, 58982, 58152, 57344, 56558, 55794,
		55050, 54326, 53620, 52933, 52263, 51610, 50972, 50351,
		49744, 49152, 48574, 48009, 47457, 46918, 46391, 45875,
		45371, 44878, 44395, 43923, 43461, 43008, 42565, 42130,
		41705, 41288, 40879, 40478, 40085, 39700, 39322, 38951,
		38587, 38229, 37879, 37534, 37196, 36864, 36538, 36217,
		35902, 35593, 35289, 34990, 34696, 34406, 34122, 33842,
		33567, 33297, 33030, 32768, 32510, 32256, 32006, 31760,
		31517, 31279, 31043, 30812, 30583, 30359, 30137, 29919,
		29703, 29491, 29282, 29076, 28873, 28672, 28474, 28279,
		28087, 27897, 27710, 27525, 27343, 27163, 26985, 26810,
		26637, 26466, 26298, 26131, 25967, 25805, 25645, 25486,
		25330, 25175, 25023, 24872, 24723, 24576, 24431, 24287,
		24145, 24004, 23866, 23729, 23593, 23459, 23326, 23195,
		23066, 22938, 22811, 22686, 22562, 22439, 22318, 22198,
		22079, 21962, 21845, 21730, 21617, 21504, 21393, 21282,
		21173, 21065, 20958, 20852, 20748, 20644, 20541, 20439,
		20339, 20239, 20140, 20043, 19946, 19850, 19755, 19661,
		19568, 19475, 19384, 19293, 19204, 19115, 19027, 18939,
		18853, 18767, 18682, 18598, 18515, 18432, 18350, 18269,
		18188, 18109, 18030, 17951, 17873, 17796, 17720, 17644,
		17569, 17495, 17421, 17348, 17275, 17203, 17132, 17061,
		16991, 16921, 16852, 16784, 16716, 16648, 16581, 16515,
		16449, 16384, 16319, 16255, 16191, 16128
	};
	TfwStreamSchedEntryAnchor *anchor;

	stream->link.offset = offset_tbl[stream->weight - 1] + stream->link.deficit;
	stream->link.deficit = stream->link.offset % 4128768;
	stream->link.offset = ((stream->link.offset / 65536) % TFW_STREAM_SCHED_ENTRY_COUNT);

	anchor = parent->anchors + stream->link.offset;
	parent->total_weight += stream->weight;
	stream->sched.parent = parent;

	tfw_h2_stream_sched_add_active_cnt(stream);
}

TfwStream *
tfw_h2_sched_stream_dequeue(TfwStreamSchedEntry *entry,
			    TfwStreamSchedEntry **parent)
{
	TfwStreamSchedEntryAnchor *anchor;
	TfwStreamSchedEntryLink *link;
	TfwStream *stream;
	int zeroes;

	BUG_ON(!entry->bits);

	while (true) {
		zeroes =  __builtin_clzll(entry->bits);
		anchor = entry->anchors + zeroes;

		/*
		 * This function should be called only after checking that
		 * entry scheduler is active.
		 */
		BUG_ON(!anchor->active_cnt || list_empty(&anchor->head));

		link = list_entry(anchor->head.next, TfwStreamSchedEntryLink,
				  node);
		stream = container_of(link, TfwStream, link);

		if (tfw_h2_stream_is_active(stream)) {
			*parent = entry;
			tfw_h2_stream_schred_remove(stream);
			return stream;
		} else if (tfw_h2_stream_sched_is_active(&stream->sched)) {
			/*
			 * This stream is blocked, but have active childs, try
			 * to use on of them.
			 */
			*parent = stream->sched.parent;
			tfw_h2_stream_schred_remove(stream);
			tfw_h2_sched_stream_enqueue(stream, *parent);
			entry = &stream->sched;
		} else {
			break;
		}
	}

	return NULL;
}

void
tfw_h2_sched_activate_stream(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;

	BUG_ON(!tfw_h2_stream_is_active(stream));

	while (parent) {
		TfwStreamSchedEntryAnchor *anchor =
			parent->anchors + stream->link.offset;
		TfwStream *next = container_of(parent, TfwStream, sched);

		/*
		 * If the new added stream is active, increment count of
		 * active streams for all parents until root stream and
		 * add new stream to the head of appropriate queue.
		 */ 
		list_del_init(&stream->link.node);
		list_add(&stream->link.node, &anchor->head);

		parent->active_cnt += 1;
		anchor->active_cnt += 1;
		parent->bits |= 1ULL << (sizeof(parent->bits) * 8 -
			1 - stream->link.offset);

		stream = next;
		parent = stream->sched.parent;
	}
}
