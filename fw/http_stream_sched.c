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
#include "http_stream_sched.h"
#include "http_stream.h"

/**
 * Remove stream from the list of the list of the blocked streams
 * and insert it in the ebtree of active streams. Should be called
 * only for active streams or the streams with active childs, which
 * is not already in the ebtree of active streams.
 */
static void
tfw_h2_stream_sched_insert_active(TfwStream *stream, u64 deficit)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;

	BUG_ON(!parent || (!tfw_h2_stream_is_active(stream) &&
	       !tfw_h2_stream_sched_is_active(&stream->sched)));
	BUG_ON(stream->active.node.leaf_p);
	
	list_del_init(&stream->blocked);
	stream->active.key = deficit;
	eb64_insert(&parent->root, &stream->active);
}

/**
 * Remove stream from the ebtree of active streams and insert
 * it in the list of the blocked streams. Should be called
 * only for the blocked streams and the streams without active
 * childs, which is not already in the blocked list.
 */
static void
tfw_h2_stream_sched_insert_blocked(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;

	BUG_ON(!parent || tfw_h2_stream_is_active(stream)
	       || tfw_h2_stream_sched_is_active(&stream->sched));
	BUG_ON(!list_empty(&stream->blocked));

	eb64_delete(&stream->active);
	list_add(&stream->blocked, &parent->blocked);
}

static u64
tfw_h2_stream_sched_calc_new_deficit(TfwStreamSched *sched, TfwStream *stream)
{
	u64 min_deficit = eb_is_empty(&sched->root.root) ?
		0 : eb64_first(&sched->root.root)->key;
	return min_deficit + 65536 / stream->weight;
}

static void
tfw_h2_stream_sched_propagate_add_active_cnt(TfwStreamSched *sched,
					     TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt =
		stream->sched.active_cnt + (stream_is_active ? 1 : 0);


	BUG_ON(!parent);

	T_WARN("parent sched %px root sched %px", parent, &sched->root);
	while (true) {
		parent->active_cnt += active_cnt;
		if (parent == &sched->root)
			break;

		T_WARN("tfw_h2_stream_sched_propagate_add_active_cnt 111");
		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
		if (!parent)
			break;

		T_WARN("tfw_h2_stream_sched_propagate_add_active_cnt 222 stream %px id %u parent sched %px", stream, stream->id, parent);

		if (tfw_h2_stream_is_active(stream)
		    || tfw_h2_stream_sched_is_active(&stream->sched)) {
		    	if (!stream->active.node.leaf_p) {
				u64 deficit;
				BUG_ON(list_empty(&stream->blocked));
				/*
				 * Insert new activated stream to the ebtree.
				 * deficit = min_deficit + constant / weight.
				 */
				deficit = tfw_h2_stream_sched_calc_new_deficit(sched, stream);
				tfw_h2_stream_sched_insert_active(stream,
								  deficit);
		    	}
		}
	}
}

static void
tfw_h2_stream_sched_propagate_dec_active_cnt(TfwStreamSched *sched,
					     TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt =
		stream->sched.active_cnt + (stream_is_active ? 1 : 0);

	/*
	 * Each stream has parent, it can be other strean or
	 * the scheduler itself.
	 */
	BUG_ON(!parent);

	while (true) {
		parent->active_cnt -= active_cnt;
		if (parent == &sched->root)
			break;

		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
		if (!parent)
			break;

		if (!tfw_h2_stream_is_active(stream)
		    && !tfw_h2_stream_sched_is_active(&stream->sched)) {
			if (stream->active.node.leaf_p) {
				BUG_ON(!list_empty(&stream->blocked));
				/*
				 * If stream is not active and have no active
				 * childs move it to the blocked list.
				 */
				tfw_h2_stream_sched_insert_blocked(stream);
			}
		}
	}
}

/**
 * Remove stream from the scheduler. Since this function is
 * used when we delete stream also we should explicitly remove
 * stream both from active tree and blocked list. It is a caller
 * responsibility to add stream again to the scheduler if it is
 * necessary with appropriate deficite.
 */
void
tfw_h2_stream_sched_remove(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	
	eb64_delete(&stream->active);
	list_del_init(&stream->blocked);
	tfw_h2_stream_sched_propagate_dec_active_cnt(sched, stream);
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

static inline void
tfw_h2_stream_sched_move_child(TfwStreamSched *sched, TfwStream *child,
			       TfwStreamSchedEntry *parent)
{
	u64 deficit;

	tfw_h2_stream_sched_remove(sched, child);
	deficit = tfw_h2_stream_sched_calc_new_deficit(sched, child);
	tfw_h2_sched_stream_enqueue(sched, child, parent, deficit);
}

void
tfw_h2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream,
		      TfwStreamSchedEntry *dep, bool excl)
{
	struct list_head *cur, *tmp;
	u64 deficit = tfw_h2_stream_sched_calc_new_deficit(sched, stream);

	T_WARN("tfw_h2_add_stream_dep id %u dep %px excl %d", stream->id, dep, excl);
	if (!excl) {
		tfw_h2_sched_stream_enqueue(sched, stream, dep, deficit);
		return;
	}

	/*
	 * RFC 7540 5.3.1:
	 * An exclusive flag allows for the insertion of a new level of
	 * dependencies. The exclusive flag causes the stream to become the
	 * sole dependency of its parent stream, causing other dependencies
	 * to become dependent on the exclusive stream.
	 */
	list_for_each_safe(cur, tmp, &dep->blocked) {
		TfwStream *child = container_of(cur, TfwStream, blocked);
		T_WARN("tfw_h2_add_stream_dep child id %u parent id %u sched %px parent %px dep %px dep parent %px", child->id, stream->id, &stream->sched, stream->sched.parent, dep, dep->parent);
		tfw_h2_stream_sched_move_child(sched, child, &stream->sched);
	}

	while (!eb_is_empty(&dep->root)) {
		struct eb64_node *node = eb64_first(&stream->sched.root);
		TfwStream *child = eb64_entry(node, TfwStream, active);
		T_WARN("tfw_h2_add_stream_dep child id %u parent id %u sched %px parent %px dep %px dep parent %px", child->id, stream->id, &stream->sched, stream->sched.parent, dep, dep->parent);
		tfw_h2_stream_sched_move_child(sched, child, &stream->sched);
	}

	tfw_h2_sched_stream_enqueue(sched, stream, dep, deficit);
}

void
tfw_h2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream)
{
	struct list_head *cur, *tmp;
	TfwStreamSchedEntry *parent = stream->sched.parent;
	size_t total_weight = stream->sched.total_weight;
	unsigned short new_weight;

	T_WARN("tfw_h2_remove_stream_dep !!! %u %px %px", stream->id, parent, parent->parent);
	/* Remove stream from the parent scheduler. */
	tfw_h2_stream_sched_remove(sched, stream);

	T_WARN("tfw_h2_remove_stream_dep !!! %u AAA", stream->id);
	/*
	 * According to RFC 7540 section 5.3.4:
	 * If the parent stream is removed from the tree, the weight of the
	 * parent stream is divided between it's childs according to there
	 * weights.
	 */
	list_for_each_safe(cur, tmp, &stream->sched.blocked) {
		TfwStream *child = container_of(cur, TfwStream, blocked);

		/*
		 * Remove childs of the removed stream, recalculate there
		 * weights and add them to the scheduler of the parent of
		 * the removed stream.
		 */
		new_weight = child->weight *
			stream->weight / total_weight;
		child->weight = new_weight > 0 ? new_weight : 1;
		T_WARN("tfw_h2_remove_stream_dep !!! child id %u BBB parent %px %px", child->id, parent, parent->parent);
		tfw_h2_stream_sched_move_child(sched, child, parent);
		T_WARN("tfw_h2_remove_stream_dep !!! child id %u BBB parent %px %px ZZZ", child->id, parent, parent->parent);
	}

	while (!eb_is_empty(&stream->sched.root)) {
		struct eb64_node *node = eb64_first(&stream->sched.root);
		TfwStream *child = eb64_entry(node, TfwStream, active);

		/*
		 * Remove childs of the removed stream, recalculate there
		 * weights and add them to the scheduler of the parent of
		 * the removed stream.
		 */
		new_weight = child->weight *
			stream->weight / total_weight;
		child->weight = new_weight > 0 ? new_weight : 1;
		T_WARN("tfw_h2_remove_stream_dep !!! child id %u BBB parent %px %px", child->id, parent, parent->parent);
		tfw_h2_stream_sched_move_child(sched, child, parent);
		T_WARN("tfw_h2_remove_stream_dep !!! child id %u BBB parent %px %px ZZZ 111", child->id, parent, parent->parent);
	}

	BUG_ON(stream->sched.active_cnt);
}

/**
 * Check if the stream is now depends from it's child.
 */
static bool
tfw_h2_is_stream_depend_on_child(TfwStreamSched *sched, TfwStream *stream,
				 TfwStreamSchedEntry *new_parent)
{
	TfwStreamSchedEntry *parent = new_parent->parent;
	TfwStream *next;

	while (parent && parent != &sched->root) {
		next = container_of(parent, TfwStream, sched);
		if (next == stream)
			return true;
		parent = parent->parent;
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
	bool is_stream_depends_on_child;

	stream = tfw_h2_find_stream(sched, stream_id);
	BUG_ON(!stream);
	old_parent = stream->sched.parent;
	BUG_ON(!old_parent);

	tfw_h2_find_stream_dep(sched, new_dep, &new_parent);

	is_stream_depends_on_child =
		tfw_h2_is_stream_depend_on_child(sched, stream, new_parent);

	if (!is_stream_depends_on_child) {
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
		tfw_h2_stream_sched_remove(sched, stream);
		stream->weight = new_weight;
		tfw_h2_add_stream_dep(sched, stream, new_parent, excl);
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

		tfw_h2_stream_sched_remove(sched, np);
		tfw_h2_stream_sched_remove(sched, stream);
		stream->weight = new_weight;
		tfw_h2_add_stream_dep(sched, np, old_parent, false);
		tfw_h2_add_stream_dep(sched, stream, new_parent, excl);
	}

}

void
tfw_h2_sched_stream_enqueue(TfwStreamSched *sched, TfwStream *stream,
			    TfwStreamSchedEntry *parent, u64 deficit)
{
	parent->total_weight += stream->weight;
	stream->sched.parent = parent;

	T_WARN("tfw_h2_sched_stream_enqueue id %u deficit %llu", stream->id, deficit);

	/*
	 * This function should be called only for new created streams or
	 * streams which were previously removed from the scheduler.
	 */
	BUG_ON(stream->active.node.leaf_p);
	BUG_ON(!list_empty(&stream->blocked));

	T_WARN("tfw_h2_sched_stream_enqueue id %u deficit %llu 111", stream->id, deficit);

	if (tfw_h2_stream_is_active(stream)
	    || tfw_h2_stream_sched_is_active(&stream->sched)) {
		tfw_h2_stream_sched_insert_active(stream, deficit);
	} else {
		list_add(&stream->blocked, &parent->blocked);
	}

	T_WARN("tfw_h2_sched_stream_enqueue id %u deficit %llu 222", stream->id, deficit);

	tfw_h2_stream_sched_propagate_add_active_cnt(sched, stream);

	T_WARN("tfw_h2_sched_stream_enqueue id %u deficit %llu 333", stream->id, deficit);
}

TfwStream *
tfw_h2_sched_stream_dequeue(TfwStreamSched *sched, TfwStreamSchedEntry **parent)
{
	TfwStreamSchedEntry *entry = &sched->root;
	struct eb64_node *node = eb64_first(&entry->root);
	u64 deficit;

	while (node) {
		TfwStream *stream = eb64_entry(node, TfwStream, active);

		if (tfw_h2_stream_is_active(stream)) {
			*parent = entry;
			tfw_h2_stream_sched_remove(sched, stream);
			return stream;
		} else if (tfw_h2_stream_sched_is_active(&stream->sched)) {
			/*
			 * This stream is blocked, but have active childs, try
			 * to use one of them.
			 */
			*parent = stream->sched.parent;
			tfw_h2_stream_sched_remove(sched, stream);
			deficit = tfw_h2_stream_recalc_deficit(stream);
			tfw_h2_sched_stream_enqueue(sched, stream, *parent,
						    deficit);
			entry = &stream->sched;
			node = eb64_first(&entry->root);
		} else {
			break;
		}
	}

	return NULL;
}

void
tfw_h2_sched_activate_stream(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	u64 deficit;

	BUG_ON(!tfw_h2_stream_is_active(stream));
	BUG_ON(!parent);

	T_WARN("tfw_h2_sched_activate_stream id %u", stream->id);

	if (!stream->active.node.leaf_p) {
		/*
		 * If stream was not activated early insert it to
		 * the ebtree.
		 * deficit = min_deficit + constant / weight.
		 */
		deficit = tfw_h2_stream_sched_calc_new_deficit(sched, stream);
		tfw_h2_stream_sched_insert_active(stream, deficit);
	}

	while (true) {
		parent->active_cnt += 1;
		if (parent == &sched->root)
			break;	

		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
		BUG_ON(!parent);

		if (!stream->active.node.leaf_p) {
			BUG_ON(list_empty(&stream->blocked));
			/*
			 * Insert new activated stream to the ebtree.
			 * deficit = min_deficit + constant / weight.
			 */
			deficit = tfw_h2_stream_sched_calc_new_deficit(sched,
								       stream);
		    	tfw_h2_stream_sched_insert_active(stream, deficit);
		}
	}
}
