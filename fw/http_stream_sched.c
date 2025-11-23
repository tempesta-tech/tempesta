/**
 *		Tempesta FW
 *
 * HTTP2 stream scheduler which implements stream prioritization
 * accoring RFC 7540 5.3.
 *
 * There are two algorithm of stream prioritization which are described
 * in RFC 7540 5.3 and RFC 9218. RFC 7540 5.3 is deprecated, but we
 * implement our scheduler according to RFC 7540, because all modern
 * browsers use RFC 7540 for HTTP2 stream prioritization and use modern
 * RFC 9218 only for HTTP3.
 *
 * Before developing of our own HTTP streams scheduling logic, we analyzed
 * how other open source HTTP servers implement this.
 * Nginx not fully support RFC 7540. A frame is inserted into the sending list
 * according to the rank (the level in the priority tree) of the stream and
 * weight. But it does not correspond to the RFC: a server should not send data
 * for a stream which depends on other streams. Also the algorithm can lead to
 * O(n) complexity (linear scan) if each next frame has higher priority than
 * the previous one.
 * H20 uses an O(1) approach described as an Array of Queue. This is the very
 * fast scheduler but it has two main disadvantages - it consumes a lot of
 * memory and is not fair.
 * We take into accout that sharing bandwidth for sibling streams has sence
 * only for progressive JPEGs. Moreover all browsers expect Firefox use
 * exclusive flag so the priority tree degenerates into a list and resources
 * are requested sequentially. Progressive JPEGS (only for Firefox browser)
 * is a very rare case, so we decide to process requests from streams from
 * larger to smaller weight.
 * 
 * When we search for the most priority stream we iterate over the levels of
 * the priority tree. For exanple:
 *                     1 (256)
 *          3 (256)              5 (1)
 *     7 (256)   9 (1)    11 (256)     13 (1)
 *
 * In this example we have streams 3 and 5 which depend on  to stream 1,
 * streams 7 and 9 which depend on stream 3, and streams 11 and 13, which
 * depend on stream 5. We start from stream 1 and if it is active (has data
 * to send and not blocked by HTTP window exceeding) we return it. If is not
 * active but has active children we move to the next level of the tree
 * (streams 3 and 5) and choose the stream (which is active) with the greatest
 * weight.
 *
 * Copyright (C) 2024 - 2025 Tempesta Technologies, Inc.
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
#undef DEBUG
#if DBG_HTTP_STREAM_SCHED > 0
#define DEBUG DBG_HTTP_STREAM_SCHED
#endif

#include "lib/log.h"
#include "http_stream_sched.h"
#include "http_stream.h"
#include "connection.h"

#define SCHED_PARENT_STREAM(sched, dep)			\
	(dep != &sched->root ? dep->owner->id : 0)

static inline void
tfw_h2_stream_sched_spin_lock_assert(TfwStreamSched *sched)
{
	TfwH2Ctx *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwH2Conn *conn = ctx->conn;

	/*
	 * All scheduler functions schould be called under the
	 * socket lock.
	 */
	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);
}

static void
tfw_h2_stream_sched_insert_by_weight(struct list_head *head,
				     TfwStream *stream)
{
	TfwStream *pos = NULL;
	int found = false;

	list_for_each_entry_reverse(pos, head, sched_node) {
		if (pos->weight < stream->weight
		    || (pos->weight == stream->weight
		        && pos->id > stream->id))
		{
			found = true;
			break;
		}
	}

	if (found)
		list_add(&stream->sched_node, &pos->sched_node);
	else
		list_add(&stream->sched_node, head);
}

/**
 * Remove stream from the list of the blocked streams and insert
 * it in the list of active streams. Should be called only for
 * active streams or the streams with active children, which is
 * not already in the list of active streams.
 */
static void
tfw_h2_stream_sched_insert_active(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;

	BUG_ON(!parent || (!tfw_h2_stream_is_active(stream) &&
	       !stream->sched->active_cnt));
	BUG_ON(stream->sched_state == HTTP2_STREAM_SCHED_STATE_ACTIVE);

	list_del_init(&stream->sched_node);
	tfw_h2_stream_sched_insert_by_weight(&parent->active, stream);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_ACTIVE;
}

/**
 * Remove stream from the list of active streams and insert
 * it in the list of the blocked streams. Should be called
 * only for the blocked streams and the streams without active
 * children, which are not already in the list of the blocked
 * streams.
 */
static void
tfw_h2_stream_sched_insert_blocked(TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;

	BUG_ON(!parent || tfw_h2_stream_is_active(stream)
	       || stream->sched->active_cnt);
	BUG_ON(stream->sched_state == HTTP2_STREAM_SCHED_STATE_BLOCKED);

	list_del_init(&stream->sched_node);
	list_add(&stream->sched_node, &parent->blocked);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_BLOCKED;
}

static void
__tfw_h2_stream_sched_propagate_add_active_cnt(TfwStreamSched *sched,
					       TfwStreamSchedEntry *parent,
					       long int active_cnt)
{
	while (true) {
		TfwStream *stream;
		bool need_activate = !parent->active_cnt;

		parent->active_cnt += active_cnt;
		if (parent == &sched->root)
			break;

		stream = parent->owner;
		parent = stream->sched->parent;
		/*
		 * Stream can have no parent if it is removed from
		 * the scheduler due to priority tree rebuilding.
		 */
		if (!parent)
			break;

		if (!need_activate || tfw_h2_stream_is_active(stream))
			continue;

		BUG_ON(stream->sched_state != HTTP2_STREAM_SCHED_STATE_BLOCKED);
		tfw_h2_stream_sched_insert_active(stream);
	}
}

/**
 * Recalculate count of active streams for parent schedulers, when
 * new stream is added to the priority tree. If parent scheduler
 * is activated in this function, insert appropriate parent stream
 * in the tree of active streams.
 */
static void
tfw_h2_stream_sched_propagate_add_active_cnt(TfwStreamSched *sched,
					     TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt =
		stream->sched->active_cnt + (stream_is_active ? 1 : 0);

	if (!active_cnt)
		return;

	__tfw_h2_stream_sched_propagate_add_active_cnt(sched, parent,
						       active_cnt);
}

static void
__tfw_h2_stream_sched_propagate_dec_active_cnt(TfwStreamSched *sched,
					       TfwStreamSchedEntry *parent,
					       long int active_cnt)
{
	while (true) {
		TfwStream *stream;

		parent->active_cnt -= active_cnt;
		if (parent == &sched->root)
			break;

		stream = parent->owner;
		parent = stream->sched->parent;
		/*
		 * Stream can have no parent if it is removed from
		 * the scheduler due to priority tree rebuilding.
		 */
		if (!parent)
			break;

		if (tfw_h2_stream_is_active(stream)
		    || stream->sched->active_cnt)
			continue;

		BUG_ON(stream->sched_state != HTTP2_STREAM_SCHED_STATE_ACTIVE);
		tfw_h2_stream_sched_insert_blocked(stream);
	}
}

static void
__tfw_h2_stream_sched_remove(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;
	
	tfw_h2_stream_sched_spin_lock_assert(sched);
	list_del_init(&stream->sched_node);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_UNKNOWN;
	stream->sched->parent = NULL;
	parent->total_weight -= stream->weight;
}

/**
 * Remove stream from the scheduler and recalculate count of active streams for
 * parent schedulers, when new stream is removed from the priority tree.
 * If parent scheduler is deactivated in this function, remove appropriate
 * parent stream from the tree of active streams.
 * Since this function is used when we delete stream, we also should explicitly
 * remove stream from the tree. It is a caller responsibility to add stream
 * again to the scheduler if it is necessary.
 */
static void
tfw_h2_stream_sched_remove(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt = stream->sched->active_cnt
			      + (stream_is_active ? 1 : 0);

	__tfw_h2_stream_sched_remove(sched, stream);

	if (!active_cnt)
		return;

	__tfw_h2_stream_sched_propagate_dec_active_cnt(sched, parent,
						       active_cnt);
}

/**
 * Find parent scheduler by id of the parent stream. If id == 0 or
 * we can't find parent stream return root scheduler according to
 * RFC 7540 5.3.1.
 */
TfwStreamSchedEntry *
tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id)
{
	tfw_h2_stream_sched_spin_lock_assert(sched);

	if (id) {
		TfwStream *stream = tfw_h2_find_stream(sched, id);
		if (stream)
			return stream->sched;
	}
	/*
	 * RFC 7540 5.3.1:
	 * A dependency on a stream that is not currently in the tree -- such
	 * as a stream in the "idle" state -- results in that stream being
	 * given a default priority.
	 */
	return &sched->root;
}

static inline bool
tfw_h2_stream_sched_has_children(TfwStreamSchedEntry *entry)
{
	return !list_empty(&entry->active) || !list_empty(&entry->blocked);
}

static void
__tfw_h2_stream_sched_enqueue(TfwStreamSched *sched, TfwStream *stream,
			      TfwStreamSchedEntry *parent)
{
	tfw_h2_stream_sched_spin_lock_assert(sched);

	parent->total_weight += stream->weight;
	stream->sched->parent = parent;

	/*
	 * This function should be called only for new created streams or
	 * streams which were previously removed from the scheduler.
	 */
	BUG_ON(!list_empty(&stream->sched_node));

	if (tfw_h2_stream_is_active(stream)
	    || stream->sched->active_cnt)
		tfw_h2_stream_sched_insert_active(stream);
	else
		tfw_h2_stream_sched_insert_blocked(stream);
}

static void
tfw_h2_stream_sched_enqueue(TfwStreamSched *sched, TfwStream *stream,
			    TfwStreamSchedEntry *parent)
{
	__tfw_h2_stream_sched_enqueue(sched, stream, parent);
	tfw_h2_stream_sched_propagate_add_active_cnt(sched, stream);
}

/**
 * Add stream to the scheduler tree. @dep is a parent of new
 * added stream.
 */
void
tfw_h2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream,
		      TfwStreamSchedEntry *dep, bool excl)
{
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);

	tfw_h2_stream_sched_spin_lock_assert(sched);

	if (!excl) {
		T_DBG3("Add new stream dependency: stream (id %u excl %d)"
		       " depends from stream with id %d, ctx %px\n",
	       	       stream->id, excl, SCHED_PARENT_STREAM(sched, dep),
	       	       ctx);
		tfw_h2_stream_sched_enqueue(sched, stream, dep);
		return;
	}

	T_DBG3("Add new stream dependency: stream (id %u excl %d)"
	       " depends from stream with id %d, ctx %px\n",
	       stream->id, excl, SCHED_PARENT_STREAM(sched, dep),
	       ctx);

	/*
	 * RFC 7540 5.3.1:
	 * An exclusive flag allows for the insertion of a new level of
	 * dependencies. The exclusive flag causes the stream to become the
	 * sole dependency of its parent stream, causing other dependencies
	 * to become dependent on the exclusive stream.
	 */
	while (!list_empty(&dep->blocked)) {
		TfwStream *child = list_first_entry(&dep->blocked, TfwStream, sched_node);

		T_DBG3("During adding new stream dependency, move blocked child"
		       " (id %u) of stream with id (%u) to the new exclusively"
		       " added strean with id (%u), ctx %px\n", child->id,
		       SCHED_PARENT_STREAM(sched, dep), stream->id, ctx);
		tfw_h2_stream_sched_remove(sched, child);
		tfw_h2_stream_sched_enqueue(sched, child, stream->sched);
	}

	while (!list_empty(&dep->active)) {
		TfwStream *child = list_first_entry(&dep->active, TfwStream, sched_node);

		T_DBG3("During adding new stream dependency, move active child"
		       " (id %u) of stream with id (%u) to the new exclusively"
		       " added strean with id (%u), ctx %px\n", child->id,
		       SCHED_PARENT_STREAM(sched, dep), stream->id, ctx);
		tfw_h2_stream_sched_remove(sched, child);
		tfw_h2_stream_sched_enqueue(sched, child, stream->sched);
	}

	BUG_ON(tfw_h2_stream_sched_has_children(dep));
	tfw_h2_stream_sched_enqueue(sched, stream, dep);
}

static void
tfw_h2_stream_sched_move_children(TfwStreamSched *sched, TfwStream *stream,
				  TfwStreamSchedEntry *parent,
				  struct list_head *head,
				  bool parent_has_children)
{
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	size_t total_weight = stream->sched->total_weight;

	/*
	 * According to RFC 7540 section 5.3.4:
	 * If the parent stream is removed from the tree, the weight of the
	 * parent stream is divided between it's children according to there
	 * weights. Since weigts are always integer this can lead to the
	 * situation when two clildren with different weights (1 and 256 for
	 * example) have the same weight after recalculation: if parent stream
	 * weight is equal to 1 it can't be devided to small values.
	 */
	while (!list_empty(head)) {
		TfwStream *child = list_first_entry(head, TfwStream, sched_node);

		/*
		 * Remove children of the removed stream, recalculate there
		 * weights and add them to the scheduler of the parent of
		 * the removed stream.
		 */
		if (parent_has_children) {
			unsigned short new_weight = child->weight *
				stream->weight / total_weight;
			child->weight = new_weight > 0 ? new_weight : 1;
		}
		T_DBG3("During removing stream with id (%u) from dependency"
		       " tree, move its child (id %u) to the new parent stream"
		       " with id (%u), ctx %px\n", stream->id, child->id,
		       SCHED_PARENT_STREAM(sched, parent), ctx);
		tfw_h2_stream_sched_reinsert(sched, child, parent);
	}
}

/**
 * Remove stream from the dependency tree. Move it's children to its
 * parent scheduler according RFC 7540.
 */
void
tfw_h2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream)
{
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwStreamSchedEntry *parent = stream->sched->parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	bool parent_has_children;

	BUG_ON(!parent);
	T_DBG3("Stream (id %u parent id %u removed from dependency tree,"
	       " ctx %px\n", stream->id, SCHED_PARENT_STREAM(sched, parent),
	       ctx);

	tfw_h2_stream_sched_spin_lock_assert(sched);

	/* Remove stream from the parent scheduler. */
	__tfw_h2_stream_sched_remove(sched, stream);
	stream->sched->active_cnt = 0;

	/*
	 * Here we move children of the removed stream to the parent
	 * scheduler. If parent scheduler has no children we move
	 * current removed stream children as is (saving their weight)
	 * Otherwise we recalculate their weight according RFC. 
	 */
	parent_has_children = tfw_h2_stream_sched_has_children(parent);

	tfw_h2_stream_sched_move_children(sched, stream, parent,
					  &stream->sched->blocked,
					  parent_has_children);
	tfw_h2_stream_sched_move_children(sched, stream, parent,
					  &stream->sched->active,
					  parent_has_children);

	if (!stream_is_active)
		return;

	__tfw_h2_stream_sched_propagate_dec_active_cnt(sched, parent, 1);
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
		next = parent->owner;
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
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwStreamSchedEntry *old_parent, *new_parent;
	TfwStream *stream, *np;
	bool is_stream_depends_on_child;

	tfw_h2_stream_sched_spin_lock_assert(sched);

	stream = tfw_h2_find_stream(sched, stream_id);
	BUG_ON(!stream);
	old_parent = stream->sched->parent;
	BUG_ON(!old_parent);

	T_DBG3("Change stream dependency: stream with id (%u), which previously"
	       " depends from stream with id (%u) now depends from stream with"
	       " id (%u). New weight (%hu) of the stream (id %u) excl %d,"
	       " ctx %px\n", stream_id, SCHED_PARENT_STREAM(sched, old_parent),
	       new_dep, new_weight, stream_id, excl, ctx);

	new_parent = tfw_h2_find_stream_dep(sched, new_dep);

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
		 * child from the dependency tree, put this child to the
		 * location of the current stream and then add current
		 * stream as a child of the new parent (which was a child
		 * of current stream).
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
		np = new_parent->owner;

		tfw_h2_stream_sched_remove(sched, np);
		tfw_h2_stream_sched_remove(sched, stream);
		stream->weight = new_weight;
		tfw_h2_add_stream_dep(sched, np, old_parent, false);
		tfw_h2_add_stream_dep(sched, stream, new_parent, excl);
	}

}

TfwStream *
tfw_h2_sched_get_most_prio_stream(TfwStreamSched *sched)
{
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	struct list_head *node = &sched->root.active;

	while (!list_empty(node)) {
		TfwStream *stream = list_last_entry(node, TfwStream, sched_node);

		if (tfw_h2_stream_is_active(stream)) {
			return stream;
		} else if (stream->sched->active_cnt) {
			node = &stream->sched->active;
		} else {
			/*
			 * Since node is in active tree it should be active or
			 * has active children.
			 */
			BUG();
		}
	}

	return NULL;
}

void
tfw_h2_sched_activate_stream(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;

	tfw_h2_stream_sched_spin_lock_assert(sched);
	BUG_ON(!tfw_h2_stream_is_active(stream));
	BUG_ON(!parent);

	if (!stream->sched->active_cnt)
		tfw_h2_stream_sched_insert_active(stream);

	__tfw_h2_stream_sched_propagate_add_active_cnt(sched, parent, 1);
}

void
tfw_h2_sched_deactivate_stream(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched->parent;

	tfw_h2_stream_sched_spin_lock_assert(sched);
	BUG_ON(tfw_h2_stream_is_active(stream));
	BUG_ON(!parent);

	if (!stream->sched->active_cnt)
		tfw_h2_stream_sched_insert_blocked(stream);

	__tfw_h2_stream_sched_propagate_dec_active_cnt(sched, parent, 1);
}

void
tfw_h2_init_stream_sched_entry(TfwStreamSchedEntry *entry, TfwStream *owner)
{
	if (owner)
		owner->sched = entry;
	entry->total_weight = entry->active_cnt = 0;
	entry->owner = owner;
	entry->parent = NULL;
	entry->next_free = NULL;
	INIT_LIST_HEAD(&entry->blocked);
	INIT_LIST_HEAD(&entry->active);
}

/*
 * This function can be used only if `stream->parent` is the
 * same as `parent` or was removed from sheduler.
 */
void
tfw_h2_stream_sched_reinsert(TfwStreamSched *sched, TfwStream *stream,
			     TfwStreamSchedEntry *parent)
{
	__tfw_h2_stream_sched_remove(sched, stream);
	__tfw_h2_stream_sched_enqueue(sched, stream, parent);
}

#undef SCHED_PARENT_STREAM
