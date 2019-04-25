/**
 *		Tempesta FW
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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

#include <linux/slab.h>

#include "http_stream.h"

TfwStream *
tfw_http2_find_stream(TfwStreamSched *sched, unsigned int id)
{
	struct rb_node *node = sched->streams.rb_node;

	while (node) {
		TfwStream *stream = rb_entry(node, TfwStream, node);

		if (id < stream->id)
			node = node->rb_left;
		else if (id > stream->id)
			node = node->rb_right;
		else
			return stream;
	}

	return NULL;
}

int
tfw_http2_add_stream(TfwStreamSched *sched, TfwStream *new_stream)
{
	unsigned int id = new_stream->id;
	struct rb_node **new = &sched->streams.rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		TfwStream *stream = rb_entry(*new, TfwStream, node);

		parent = *new;
		if (id < stream->id) {
			new = &parent->rb_left;
		} else if (id > stream->id) {
			new = &parent->rb_right;
		} else {
			WARN_ON_ONCE(1);
			return -EEXIST;
		}
	}

	rb_link_node(&new_stream->node, parent, new);
	rb_insert_color(&new_stream->node, &sched->streams);

	return 0;
}

void
tfw_http2_remove_stream(TfwStreamSched *sched, TfwStream *stream)
{
	rb_erase(&stream->node, &sched->streams);
}

void
tfw_http2_streams_cleanup(TfwStreamSched *sched)
{
	TfwStream *cur, *next;

	rbtree_postorder_for_each_entry_safe(cur, next, &sched->streams, node) {
		kfree(cur);
	}
}

int
tfw_http2_find_stream_dep(TfwStreamSched *sched, unsigned int id,
			  TfwStream **dep)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
	return 0;
}

void
tfw_http2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream,
			 TfwStream *dep, bool excl)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}

void
tfw_http2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			    unsigned int new_dep, unsigned short new_weight,
			    bool excl)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}

void
tfw_http2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}
