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
#include "lib/str.h"

#include <linux/bug.h>

#define TFW_HEAP_SIZE_MAX 1000

typedef struct tfw_heap_node_t {
	long key;
	struct tfw_heap_node_t *parent;
	struct tfw_heap_node_t *child;
	struct tfw_heap_node_t *left;
	struct tfw_heap_node_t *right;
	unsigned int degree;
	bool mark;
} TfwHeapNode;

typedef struct {
	unsigned int size;
	TfwHeapNode *min;
} TfwHeap;

static inline void
tfw_heap_node_init(TfwHeapNode *node, long key)
{
	node->key = key;
	node->parent = node->child = NULL;
	node->left = node->right = node;
	node->degree = 0;
	node->mark = false;
}

static inline void
tfw_heap_init(TfwHeap *heap)
{
	bzero_fast(heap, sizeof (*heap));
}

static inline long int
tfw_heap_min(TfwHeap *heap)
{
	BUG_ON(!heap->min);
	return heap->min->key;
}

void tfw_heap_insert(TfwHeap *heap, TfwHeapNode *node);
TfwHeapNode *tfw_heap_remove(TfwHeap *heap, TfwHeapNode *node);
void tfw_heap_merge(TfwHeap *dst, TfwHeap *src);
TfwHeapNode *tfw_heap_extract_min(TfwHeap *heap);
