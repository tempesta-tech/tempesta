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
#include "heap.h"
#include "log.h"

#include <linux/minmax.h>
#include <linux/slab.h>

static inline void
tfw_heap_list_uniom(TfwHeapNode *first, TfwHeapNode *second)
{
	TfwHeapNode *left = first->left;
	TfwHeapNode *right = second->right;
	
	second->right = first;
	first->left = second;
	left->right = right;
	right->left = left;
}

static inline void
tfw_heap_list_del(TfwHeapNode *node)
{
	TfwHeapNode *left = node->left;
	TfwHeapNode *right = node->right;

	left->right = right;
	right->left = left;
}

static inline void
tfw_heap_list_add(TfwHeapNode **head, TfwHeapNode *node)
{
	if (!(*head)) {
		node->left = node->right = node;
		*head = node;
	} else {
		TfwHeapNode *left = (*head)->left;

		left->right = node;
		node->left = left;
		(*head)->left = node;
		node->right = *head;
	}
}

void
tfw_heap_insert(TfwHeap *heap, TfwHeapNode *node)
{
	tfw_heap_list_add(&heap->min, node);
	if (node->key < heap->min->key)
		heap->min = node;

	heap->size++;
}

void
tfw_heap_merge(TfwHeap *dst, TfwHeap *src)
{
	if (!src->size)
		return;
	if (!dst->size) {
		dst->min = src->min;
		dst->size = src->size;
	} else {
		tfw_heap_list_uniom(dst->min, src->min);
		dst->size += src->size;
	}

	if (src->min->key < dst->min->key)
		dst->min = src->min;
	tfw_heap_init(src);
}

static void
tfw_heap_link(TfwHeap *heap, TfwHeapNode *node, TfwHeapNode *new_parent)
{
	tfw_heap_list_del(node);
	if (node == heap->min)
		heap->min = new_parent;
	tfw_heap_list_add(&new_parent->child, node);
	node->parent = new_parent;
	new_parent->degree++;
	node->mark = false;
}

static unsigned int
tfw_heap_calc_degree(TfwHeap *heap)
{
	unsigned int degree = 0;
	unsigned int sz = heap->size;

	while (sz) {
		sz /= 2;
		degree++;
	}

	return degree;
}

static void
tfw_heap_consolidate(TfwHeap *heap)
{
	TfwHeapNode *x, *y; 
	unsigned int i, d, degree = tfw_heap_calc_degree(heap);
	TfwHeapNode fake;
	TfwHeapNode *array[32];
	
	BUG_ON(degree + 1 > 32);
	tfw_heap_node_init(&fake, 0);
	tfw_heap_list_uniom(heap->min, &fake);
	bzero_fast(array, sizeof(TfwHeapNode *) * (degree + 1));

	x = heap->min;
	do {
		TfwHeapNode *next = x->right;

		d = x->degree;
		while (array[d] != NULL) {
			y = array[d];
			if (x->key > y->key)
				swap(x, y);
			tfw_heap_link(heap, y, x);
			array[d] = NULL;
			d++;
		}
		array[d] = x;
		x = next;
	} while (x != &fake);

	heap->min = NULL;
	for (i = 0; i <= degree; i++) {
		if (array[i]) {
			if (!heap->min) {
				array[i]->left = array[i]->right = array[i];
				heap->min = array[i];
			} else {
				tfw_heap_list_add(&heap->min, array[i]);
				if (array[i]->key < heap->min->key)
					heap->min = array[i];
			}

		}
	}
}

TfwHeapNode *
tfw_heap_extract_min(TfwHeap *heap)
{
	TfwHeapNode *pmin, *child;

	if (!heap->min)
		return NULL;

	pmin = heap->min;
	child = pmin->child;

	if (child) {
		TfwHeapNode *next, *x = child;
		do {
			next = x->right;
			tfw_heap_list_add(&heap->min, x);
			x->parent = NULL;
			x = next;
		} while (x != child);
	}

	pmin->child = NULL;
	tfw_heap_list_del(pmin);


	if (pmin == pmin->right) {
		heap->min = NULL;
	} else {
		heap->min = pmin->right;
		tfw_heap_consolidate(heap);
	}

	heap->size--;
	return pmin;
}

static inline void
tfw_heap_cut(TfwHeap *heap, TfwHeapNode *node)
{
	tfw_heap_list_del(node);
	
	node->parent->degree--;
	node->mark = false;
	if (node->parent->child == node) {
		if (node->right == node)
			node->parent->child = NULL;
		else
			node->parent->child = node->right;
	}

	tfw_heap_list_add(&heap->min, node);
	node->parent = NULL;
}

static inline void
tfw_heap_cascading_cut(TfwHeap *heap, TfwHeapNode *node)
{
	TfwHeapNode *parent;

	while (node->parent && node->mark) {
		parent = node->parent;
		tfw_heap_cut(heap, node);
		node = parent;
	}
	node->mark = true;
}

static void
tfw_heap_decrease_key(TfwHeap *heap, TfwHeapNode *node, long key)
{
	TfwHeapNode *parent;

	BUG_ON(key > node->key);
	
	node->key = key;
	parent = node->parent;

	if (parent && node->key < parent->key) {
		tfw_heap_cut(heap, node);
		tfw_heap_cascading_cut(heap, parent);
	}
	if (node->key < heap->min->key)
		heap->min = node;
}

TfwHeapNode *
tfw_heap_remove(TfwHeap *heap, TfwHeapNode *node)
{
	TfwHeapNode *tmp;

	tfw_heap_decrease_key(heap, node, LONG_MIN);
	tmp = tfw_heap_extract_min(heap);
	BUG_ON(tmp != node);

	return tmp;
}
