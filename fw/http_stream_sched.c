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
	long int active_cnt =
		stream->sched.active_cnt + (stream_is_active ? 1 : 0);

	while (parent) {
		if (tfw_h2_stream_is_active(stream)
		    || tfw_h2_stream_sched_is_active(&stream->sched)) {
		    	if (!list_empty(&stream->inactive))
				list_del_init(&stream->inactive);
			if (stream->active.node.leaf_p == NULL)
				eb64_insert(&parent->root, &stream->active);
		} else {
			if (list_empty(&stream->inactive)) {
				eb64_delete(&stream->active);
				list_add(&stream->inactive, &parent->inactive);
			} else {
				BUG_ON(stream->active.node.leaf_p);
			}
		}

		parent->active_cnt += active_cnt;
		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
	}
}

static void
tfw_h2_stream_sched_dec_active_cnt(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt =
		stream->sched.active_cnt + (stream_is_active ? 1 : 0);
	bool first = true;

	while (parent) {
		if (!first && !tfw_h2_stream_is_active(stream)
		    && !tfw_h2_stream_sched_is_active(&stream->sched)) {
			if (list_empty(&stream->inactive)) {
				eb64_delete(&stream->active);
				list_add(&stream->inactive, &parent->inactive);
			} else {
				BUG_ON(stream->active.node.leaf_p);
			}
		}

		first = false;
		parent->active_cnt -= active_cnt;
		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
	}
}

void
tfw_h2_stream_sched_remove(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	
	eb64_delete(&stream->active);
	list_del_init(&stream->inactive);
	tfw_h2_stream_sched_dec_active_cnt(stream);
	stream->sched.parent = NULL;
	parent->total_weight -= stream->weight;
}

void
tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id,
		       TfwStreamSchedEntry **dep)
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
	struct list_head *cur, *tmp;

	if (!excl) {
		return tfw_h2_sched_stream_enqueue(stream, dep,
						   dep->deficit + 65536 / stream->weight);
	}

	list_for_each_safe(cur, tmp, &dep->inactive) {
		TfwStream *child = container_of(cur, TfwStream, inactive);

		tfw_h2_stream_sched_remove(child);
		tfw_h2_sched_stream_enqueue(child, &stream->sched,
					    stream->sched.deficit + 65536 / child->weight);
	}

	while (!eb_is_empty(&dep->root)) {
		struct eb64_node *node = eb64_first(&stream->sched.root);
		TfwStream *child = eb64_entry(node, TfwStream, active);

		tfw_h2_stream_sched_remove(child);
		tfw_h2_sched_stream_enqueue(child, &stream->sched,
					    stream->sched.deficit + 65536 / child->weight);
	}

	dep->deficit = 0;
	return tfw_h2_sched_stream_enqueue(stream, dep,
					   65536 / stream->weight);
}

void
tfw_h2_remove_stream_dep(TfwStream *stream)
{
	struct list_head *cur, *tmp;
	TfwStreamSchedEntry *parent = stream->sched.parent;
	size_t total_weight = stream->sched.total_weight;
	unsigned short new_weight;

	/* Remove stream from the parent scheduler. */
	tfw_h2_stream_sched_remove(stream);

	list_for_each_safe(cur, tmp, &stream->sched.inactive) {
		TfwStream *child = container_of(cur, TfwStream, inactive);

		tfw_h2_stream_sched_remove(child);
		new_weight = child->weight *
			stream->weight / total_weight;
		child->weight = new_weight > 0 ? new_weight : 1;
		tfw_h2_sched_stream_enqueue(child, parent,
					    parent->deficit + 65536 / child->weight);
	}

	/*
	 * According to RFC 7540 section 5.3.4:
	 * If the parent stream is removed from the tree, the weight of the
	 * parent stream is divided between it's childs according to there
	 * weights.
	 */
	while (!eb_is_empty(&stream->sched.root)) {
		struct eb64_node *node = eb64_first(&stream->sched.root);
		TfwStream *child = eb64_entry(node, TfwStream, active);

		/*
		 * Remove childs of the removed stream, recalculate there
		 * weights and add them to the scheduler of the parent of
		 * the removed stream. 
		 */
		tfw_h2_stream_sched_remove(child);
		new_weight = child->weight *
			stream->weight / total_weight;
		child->weight = new_weight > 0 ? new_weight : 1;
		tfw_h2_sched_stream_enqueue(child, parent, parent->deficit + 65536 / child->weight);
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
		 * 2. Change stream weight.
		 * 3. Insert stream in the dependency tree as a
		 *    child of the new parent.
		 */
		tfw_h2_stream_sched_remove(stream);
		stream->weight = new_weight;
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

		tfw_h2_stream_sched_remove(np);
		tfw_h2_stream_sched_remove(stream);
		stream->weight = new_weight;
		tfw_h2_add_stream_dep(np, old_parent, false);
		tfw_h2_add_stream_dep(stream, new_parent, excl);
	}

}

void
tfw_h2_sched_stream_enqueue(TfwStream *stream, TfwStreamSchedEntry *parent,
			    u64 deficit)
{
	parent->total_weight += stream->weight;
	stream->active.key = deficit;
	stream->sched.parent = parent;
	tfw_h2_stream_sched_add_active_cnt(stream);
}

TfwStream *
tfw_h2_sched_stream_dequeue(TfwStreamSchedEntry *entry,
			    TfwStreamSchedEntry **parent)
{
	struct eb64_node *node = eb64_first(&entry->root);

	while (node) {
		TfwStream *stream = eb64_entry(node, TfwStream, active);

		if (tfw_h2_stream_is_active(stream)) {
			*parent = entry;
			tfw_h2_stream_sched_remove(stream);
			return stream;
		} else if (tfw_h2_stream_sched_is_active(&stream->sched)) {
			/*
			 * This stream is blocked, but have active childs, try
			 * to use on of them.
			 */
			*parent = stream->sched.parent;
			tfw_h2_stream_sched_remove(stream);
			tfw_h2_sched_stream_enqueue(stream, *parent, stream->active.key + 65536 / stream->weight);
			entry = &stream->sched;
			node = eb64_first(&entry->root);
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
	    	if (!list_empty(&stream->inactive))
			list_del_init(&stream->inactive);
		if (stream->active.node.leaf_p == NULL)
			eb64_insert(&parent->root, &stream->active);		

		parent->active_cnt += 1;
		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
	}
}
