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
 * We decide to implement WFQ algorithm. There are a lot of data structures
 * which can be used for this purpose (list, different type of heaps and
 * different types of trees). We analyzed some of them (e.g. Fibonacci heap,
 * RB-tree, insertion sorted array etc) and found that the HAproxy’s ebtree
 * provides the best performance (at least x2 faster than the closest in
 * performance Fibonacci heap) on small data (about 100 to 1000 streams in a
 * queue) to pick a minimum item and reinsert it.
 *
 * We use deficit as a key in our priority ebtree. Deficit of the stream
 * calculated as decribed below:
 * new: deficit = min_deficit_in_heap + constant / weight
 * exist: deficit = last_deficit + constant / weight
 * 
 * When we search for the most priority stream we iterate over the levels of
 * the priority tree. For exanple:
 *                     1 (256)
 *          3 (256)              5 (1)
 *     7 (256)   9 (1)    11 (256)     13 (1)
 *
 * In this example we have streams 3 and 5 which depend on stream 1,
 * streams 7 and 9 which depend on stream 3, and streams 11 and 13, which
 * depend on stream 5. We start from stream 1 and if it is active (has data
 * to send and not blocked by HTTP window exceeding) we return it. If is not
 * active but has active children we move to the next level of the tree
 * (streams 3 and 5) and choose the stream (which is active or has active
 * children) with the lowest deficit. We remove it from the tree and if it
 * is active return it. Later after sending data for this stream we recalculate
 * its deficit (deficit = deficit + constant / weight) and insert it back to
 * the tree.
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
#undef DEBUG
#if DBG_HTTP_STREAM_SCHED > 0
#define DEBUG DBG_HTTP_STREAM_SCHED
#endif

#include "lib/log.h"
#include "http_stream_sched.h"
#include "http_stream.h"
#include "connection.h"

static inline void
tfw_h2_stream_sched_spin_lock_assert(TfwStreamSched *sched)
{
	TfwH2Ctx *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	/*
	 * All scheduler functions schould be called under the
	 * socket lock.
	 */
	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);
}

/**
 * Remove stream from the ebtree of the blocked streams and insert
 * it in the ebtree of active streams. Should be called only for
 * active streams or the streams with active children, which is
 * not already in the ebtree of active streams.
 */
static void
tfw_h2_stream_sched_insert_active(TfwStream *stream, u64 deficit)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;

	BUG_ON(!parent || (!tfw_h2_stream_is_active(stream) &&
	       !tfw_h2_stream_sched_is_active(&stream->sched)));
	BUG_ON(stream->sched_state == HTTP2_STREAM_SCHED_STATE_ACTIVE);

	eb64_delete(&stream->sched_node);
	stream->sched_node.key = deficit;
	eb64_insert(&parent->active, &stream->sched_node);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_ACTIVE;
}

/**
 * Remove stream from the ebtree of active streams and insert
 * it in the ebtree of the blocked streams. Should be called
 * only for the blocked streams and the streams without active
 * children, which are not already in the ebtree of the blocked
 * streams.
 */
static void
tfw_h2_stream_sched_insert_blocked(TfwStream *stream, u64 deficit)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;

	BUG_ON(!parent || tfw_h2_stream_is_active(stream)
	       || tfw_h2_stream_sched_is_active(&stream->sched));
	BUG_ON(stream->sched_state == HTTP2_STREAM_SCHED_STATE_BLOCKED);

	eb64_delete(&stream->sched_node);
	stream->sched_node.key = deficit;
	eb64_insert(&parent->blocked, &stream->sched_node);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_BLOCKED;
}

/**
 * Calculate minimum deficit for the current scheduler.
 * New stream is inserted in the scheduler with
 * deficit =  min_deficit + 65536 / stream->weight.
 */
static u64
tfw_h2_stream_sched_min_deficit(TfwStreamSchedEntry *parent)
{
	TfwStream *prio;

	/*
	 * First of all check active streams in the scheduler.
	 * If there are any active streams new stream is inserted
	 * with deficit = min_deficit + 65536 / stream->weight.
	 * Where min_deficit is a deficit of a most prio stream,
	 * if it was scheduled at least one time.
	 */
	prio = !eb_is_empty(&parent->active) ?
		eb64_entry(eb64_first(&parent->active), TfwStream, sched_node) :
		NULL;
	if (prio) {
		return tfw_h2_stream_has_default_deficit(prio) ?
			0 : prio->sched_node.key;
	}

	/* Same for blocked streams. */
	prio = !eb_is_empty(&parent->blocked) ?
		eb64_entry(eb64_first(&parent->blocked), TfwStream, sched_node) :
		NULL;
	if (prio) {
		return tfw_h2_stream_has_default_deficit(prio) ?
			0 : prio->sched_node.key;
	}

	return 0;
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
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt =
		stream->sched.active_cnt + (stream_is_active ? 1 : 0);

	if (!active_cnt)
		return;

	while (true) {
		bool need_activate = !tfw_h2_stream_sched_is_active(parent);
		parent->active_cnt += active_cnt;
		if (parent == &sched->root)
			break;

		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
		/*
		 * Stream can have no parent if it is removed from
		 * the scheduler due to priority tree rebuilding.
		 */
		if (!parent)
			break;

		if (need_activate && !tfw_h2_stream_is_active(stream)) {
			BUG_ON(stream->sched_state != HTTP2_STREAM_SCHED_STATE_BLOCKED);
			tfw_h2_stream_sched_insert_active(stream,
							  stream->sched_node.key);
		}
	}
}

/**
 * Recalculate count of active streams for parent schedulers, when
 * new stream is removed from the priority tree. If parent scheduler
 * is deactivated in this function, remove appropriate parent stream
 * from the tree of active streams.
 */
static void
tfw_h2_stream_sched_propagate_dec_active_cnt(TfwStreamSched *sched,
					     TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	bool stream_is_active = tfw_h2_stream_is_active(stream);
	long int active_cnt =
		stream->sched.active_cnt + (stream_is_active ? 1 : 0);

	if (!active_cnt)
		return;

	while (true) {
		parent->active_cnt -= active_cnt;
		if (parent == &sched->root)
			break;

		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
		/*
		 * Stream can have no parent if it is removed from
		 * the scheduler due to priority tree rebuilding.
		 */
		if (!parent)
			break;

		if (tfw_h2_stream_is_active(stream)
		    || tfw_h2_stream_sched_is_active(&stream->sched))
			continue;

		BUG_ON(stream->sched_state != HTTP2_STREAM_SCHED_STATE_ACTIVE);
		tfw_h2_stream_sched_insert_blocked(stream, stream->sched_node.key);
	}
}

/**
 * Remove stream from the scheduler. Since this function is
 * used when we delete stream also we should explicitly remove
 * stream both from the tree. It is a caller responsibility
 * to add stream again to the scheduler if it is necessary
 * with appropriate deficite.
 */
void
tfw_h2_stream_sched_remove(TfwStreamSched *sched, TfwStream *stream)
{
	TfwStreamSchedEntry *parent = stream->sched.parent;
	
	tfw_h2_stream_sched_spin_lock_assert(sched);

	eb64_delete(&stream->sched_node);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_UNKNOWN;
	tfw_h2_stream_sched_propagate_dec_active_cnt(sched, stream);
	stream->sched.parent = NULL;
	parent->total_weight -= stream->weight;
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
			return &stream->sched;
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
	return !eb_is_empty(&entry->active) || !eb_is_empty(&entry->blocked);
}

static inline void
tfw_h2_stream_sched_move_child(TfwStreamSched *sched, TfwStream *child,
			       TfwStreamSchedEntry *parent, u64 deficit)
{
	tfw_h2_stream_sched_remove(sched, child);
	tfw_h2_sched_stream_enqueue(sched, child, parent, deficit);
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
	u64 deficit, min_deficit;
	bool stream_has_children;

	tfw_h2_stream_sched_spin_lock_assert(sched);

	T_DBG3("%s: ctx [%px] (stream id %u excl %d)\n",
	       __func__, ctx, stream->id, excl);

	if (!excl) {
		deficit = tfw_h2_stream_sched_min_deficit(dep) +
			tfw_h2_stream_default_deficit(stream);
		tfw_h2_sched_stream_enqueue(sched, stream, dep, deficit);
		return;
	}

	/*
	 * Here we move children of dep scheduler to the current stream
	 * scheduler. If current stream scheduler has no children we move
	 * dep children as is (saving there deficit in the priority WFQ).
	 * Otherwise we calculate minimal deficit of the scheduler and use
	 * it as a base of new children deficit.
	 */
	stream_has_children = tfw_h2_stream_sched_has_children(&stream->sched);
	min_deficit = !stream_has_children ? 0 :
		tfw_h2_stream_sched_min_deficit(&stream->sched);

	/*
	 * RFC 7540 5.3.1:
	 * An exclusive flag allows for the insertion of a new level of
	 * dependencies. The exclusive flag causes the stream to become the
	 * sole dependency of its parent stream, causing other dependencies
	 * to become dependent on the exclusive stream.
	 */
	while (!eb_is_empty(&dep->blocked)) {
		struct eb64_node *node = eb64_first(&dep->blocked);
		TfwStream *child = eb64_entry(node, TfwStream, sched_node);

		T_DBG3("%s: ctx [%px] move blocked child stream with id %u to"
		       " new parent with id %u\n", __func__, ctx, child->id,
		       stream->id);

		deficit = !stream_has_children ? child->sched_node.key :
			min_deficit + tfw_h2_stream_default_deficit(child);
		tfw_h2_stream_sched_move_child(sched, child, &stream->sched,
					       deficit);
	}

	while (!eb_is_empty(&dep->active)) {
		struct eb64_node *node = eb64_first(&dep->active);
		TfwStream *child = eb64_entry(node, TfwStream, sched_node);

		T_DBG3("%s: ctx [%px] move active child stream with id %u to"
		       " new parent with id %u\n", __func__, ctx, child->id,
		       stream->id);

		deficit = !stream_has_children ? child->sched_node.key :
			min_deficit + tfw_h2_stream_default_deficit(child);
		tfw_h2_stream_sched_move_child(sched, child, &stream->sched,
					       deficit);
	}

	BUG_ON(tfw_h2_stream_sched_has_children(dep));
	/* Stream is the only one in dep scheduler, use default deficit. */
	tfw_h2_sched_stream_enqueue(sched, stream, dep,
				    tfw_h2_stream_default_deficit(stream));
}

/**
 * Remove stream from the dependency tree. Move it's children to its
 * parent scheduler according RFC 7540.
 */
void
tfw_h2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream)
{
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwStreamSchedEntry *parent = stream->sched.parent;
	size_t total_weight = stream->sched.total_weight;
	unsigned short new_weight;
	bool parent_has_children;
	u64 deficit;

	T_DBG3("%s: ctx [%px] removed stream id %u\n",
	       __func__, ctx, stream->id);

	tfw_h2_stream_sched_spin_lock_assert(sched);

	/* Remove stream from the parent scheduler. */
	tfw_h2_stream_sched_remove(sched, stream);

	/*
	 * Here we move children of the removed stream to the parent
	 * scheduler. If parent scheduler has no children we move
	 * current removed stream children as is (saving there deficit
	 * in the priority WFQ). Otherwise we put them in the parent
	 * scheduler with current removed stream deficit. We can't
	 * save children deficit, because it has no matter for the
	 * parent scheduler WFQ.
	 */
	parent_has_children = tfw_h2_stream_sched_has_children(parent);

	/*
	 * According to RFC 7540 section 5.3.4:
	 * If the parent stream is removed from the tree, the weight of the
	 * parent stream is divided between it's children according to there
	 * weights.
	 */
	while (!eb_is_empty(&stream->sched.blocked)) {
		struct eb64_node *node = eb64_first(&stream->sched.blocked);
		TfwStream *child = eb64_entry(node, TfwStream, sched_node);

		T_DBG3("%s: ctx [%px] move blocked child stream with id %u to"
		       " new parent\n", __func__, ctx, child->id);

		/*
		 * Remove children of the removed stream, recalculate there
		 * weights and add them to the scheduler of the parent of
		 * the removed stream.
		 */
		new_weight = child->weight *
			stream->weight / total_weight;
		child->weight = new_weight > 0 ? new_weight : 1;
		deficit = !parent_has_children ?
			child->sched_node.key : stream->sched_node.key;
		tfw_h2_stream_sched_move_child(sched, child, parent, deficit);
	}

	while (!eb_is_empty(&stream->sched.active)) {
		struct eb64_node *node = eb64_first(&stream->sched.active);
		TfwStream *child = eb64_entry(node, TfwStream, sched_node);

		T_DBG3("%s: ctx [%px] move active child stream with id %u to"
		       " new parent\n", __func__, ctx, child->id);

		/*
		 * Remove children of the removed stream, recalculate there
		 * weights and add them to the scheduler of the parent of
		 * the removed stream.
		 */
		new_weight = child->weight *
			stream->weight / total_weight;
		child->weight = new_weight > 0 ? new_weight : 1;
		deficit = !parent_has_children ?
			child->sched_node.key : stream->sched_node.key;
		tfw_h2_stream_sched_move_child(sched, child, parent, deficit);
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
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwStreamSchedEntry *old_parent, *new_parent;
	TfwStream *stream, *np;
	bool is_stream_depends_on_child;

	tfw_h2_stream_sched_spin_lock_assert(sched);

	stream = tfw_h2_find_stream(sched, stream_id);
	BUG_ON(!stream);
	old_parent = stream->sched.parent;
	BUG_ON(!old_parent);

	T_DBG3("%s: ctx [%px] (stream id %u, new dep stream id %u,"
	       "new weight %u excl %d)\n", __func__, ctx,
	       stream_id, new_dep, new_weight, excl);

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
	tfw_h2_stream_sched_spin_lock_assert(sched);

	parent->total_weight += stream->weight;
	stream->sched.parent = parent;

	/*
	 * This function should be called only for new created streams or
	 * streams which were previously removed from the scheduler.
	 */
	BUG_ON(stream->sched_node.node.leaf_p);

	if (tfw_h2_stream_is_active(stream)
	    || tfw_h2_stream_sched_is_active(&stream->sched))
		tfw_h2_stream_sched_insert_active(stream, deficit);
	else
		tfw_h2_stream_sched_insert_blocked(stream, deficit);

	tfw_h2_stream_sched_propagate_add_active_cnt(sched, stream);
}

TfwStream *
tfw_h2_sched_stream_dequeue(TfwStreamSched *sched, TfwStreamSchedEntry **parent)
{
	TfwH2Ctx __maybe_unused *ctx = container_of(sched, TfwH2Ctx, sched);
	TfwStreamSchedEntry *entry = &sched->root;
	struct eb64_node *node = eb64_first(&entry->active);
	u64 deficit;

	while (node) {
		TfwStream *stream = eb64_entry(node, TfwStream, sched_node);

		if (tfw_h2_stream_is_active(stream)) {
			*parent = entry;
			tfw_h2_stream_sched_remove(sched, stream);

			T_DBG4("%s: ctx [%px] stream with id %u\n",
			       __func__, ctx, stream->id);
			return stream;
		} else if (tfw_h2_stream_sched_is_active(&stream->sched)) {
			/*
			 * This stream is blocked, but have active children, try
			 * to use one of them.
			 */
			*parent = stream->sched.parent;
			tfw_h2_stream_sched_remove(sched, stream);
			deficit = tfw_h2_stream_recalc_deficit(stream);
			tfw_h2_sched_stream_enqueue(sched, stream, *parent,
						    deficit);
			entry = &stream->sched;
			node = eb64_first(&entry->active);
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
	TfwStreamSchedEntry *parent = stream->sched.parent;

	tfw_h2_stream_sched_spin_lock_assert(sched);
	BUG_ON(!tfw_h2_stream_is_active(stream));
	BUG_ON(!parent);

	if (!tfw_h2_stream_sched_is_active(&stream->sched))
		tfw_h2_stream_sched_insert_active(stream, stream->sched_node.key);

	while (true) {
		bool need_activate = !tfw_h2_stream_sched_is_active(parent);
		parent->active_cnt += 1;
		if (parent == &sched->root)
			break;	

		stream = container_of(parent, TfwStream, sched);
		parent = stream->sched.parent;
		BUG_ON(!parent);

		if (need_activate && !tfw_h2_stream_is_active(stream))
			tfw_h2_stream_sched_insert_active(stream, stream->sched_node.key);
	}
}
