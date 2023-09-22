#include "heap.c"

#include "test.h"
#include "helpers.h"

#define TFW_HEAP_NODE_TEST_COUNT 10
#define TFW_HEAP_NODE_STRESS_TEST_COUNT 100

static TfwHeapNode stress[TFW_HEAP_NODE_STRESS_TEST_COUNT];

TEST(heap, insert)
{
	TfwHeap heap;
	TfwHeapNode nodes[TFW_HEAP_NODE_TEST_COUNT];
	int i;

	tfw_heap_init(&heap);
	for (i = 0; i < TFW_HEAP_NODE_TEST_COUNT; i++) {
		tfw_heap_node_init(&nodes[i], i);
		tfw_heap_insert(&heap, &nodes[i]);
	}

	EXPECT_EQ(heap.size, TFW_HEAP_NODE_TEST_COUNT);
	EXPECT_EQ(heap.min->key, 0);
}

TEST(heap, remove)
{
	TfwHeap heap;
	TfwHeapNode nodes[TFW_HEAP_NODE_TEST_COUNT];
	int i;

	tfw_heap_init(&heap);
	for (i = 0; i < TFW_HEAP_NODE_TEST_COUNT; i++) {
		tfw_heap_node_init(&nodes[i], i);
		tfw_heap_insert(&heap, &nodes[i]);
	}

	for (i = TFW_HEAP_NODE_TEST_COUNT - 1; i >= 0; i--) {
		EXPECT_EQ(heap.size, i + 1);
		EXPECT_EQ(heap.min->key, 0);
		tfw_heap_remove(&heap, &nodes[i]);
	}
}

TEST(heap, merge)
{
	TfwHeap heap1, heap2;
	TfwHeapNode nodes1[TFW_HEAP_NODE_TEST_COUNT];
	TfwHeapNode nodes2[TFW_HEAP_NODE_TEST_COUNT];
	int i;

	tfw_heap_init(&heap1);
	tfw_heap_init(&heap2);

	for (i = 0; i < TFW_HEAP_NODE_TEST_COUNT; i++) {
		tfw_heap_node_init(&nodes1[i], i);
		tfw_heap_insert(&heap1, &nodes1[i]);
	}

	for (i = 0; i < TFW_HEAP_NODE_TEST_COUNT; i++) {
		tfw_heap_node_init(&nodes2[i], i + TFW_HEAP_NODE_TEST_COUNT);
		tfw_heap_insert(&heap2, &nodes2[i]);
	}

	tfw_heap_merge(&heap1, &heap2);
	
	EXPECT_EQ(heap2.size, 0);
	EXPECT_EQ(heap1.size, 2 * TFW_HEAP_NODE_TEST_COUNT);
	EXPECT_EQ(heap1.min->key, 0);
}

TEST(heap, extract_min)
{
	TfwHeap heap;
	TfwHeapNode nodes[TFW_HEAP_NODE_TEST_COUNT];
	TfwHeapNode *node;
	int i;

	tfw_heap_init(&heap);
	for (i = 0; i < TFW_HEAP_NODE_TEST_COUNT; i++) {
		tfw_heap_node_init(&nodes[i], i);
		tfw_heap_insert(&heap, &nodes[i]);
	}

	i = 0;
	while ((node = tfw_heap_extract_min(&heap))) {
		EXPECT_EQ(heap.size, TFW_HEAP_NODE_TEST_COUNT - i - 1);
		EXPECT_EQ(node, &nodes[i]);
		EXPECT_EQ(node->key, i++);
	}

	EXPECT_EQ(i, TFW_HEAP_NODE_TEST_COUNT);
}

static long int
find_min_key(TfwHeapNode *nodes, int size)
{
	long int min = LONG_MAX;
	int i;
	
	for (i = 0; i < size; i++) {
		if (nodes[i].key < min)
			min = nodes[i].key;
	}

	return min;
}

TEST(heap, random_stress_extract_min)
{
	TfwHeap heap;
	TfwHeapNode *node;
	long int min;
	int i;

	tfw_heap_init(&heap);
	for (i = 0; i < TFW_HEAP_NODE_STRESS_TEST_COUNT; i++) {
		tfw_heap_node_init(&stress[i], get_random_int());
		tfw_heap_insert(&heap, &stress[i]);
	}

	for (i = 0; i < TFW_HEAP_NODE_STRESS_TEST_COUNT; i++) {
		/*
		 * Find minimal node using linear search and compare
		 * it with the minimal value from the heap.
		 */
		min = find_min_key(stress, TFW_HEAP_NODE_STRESS_TEST_COUNT);
		node = tfw_heap_extract_min(&heap);
		EXPECT_EQ(node->key, min);
		tfw_heap_node_init(node, get_random_int());
		tfw_heap_insert(&heap, node);
	}
}

TEST(heap, random_stress_remove)
{
	TfwHeap heap;
	TfwHeapNode *node;
	long int min;
	int i, to_remove;

	tfw_heap_init(&heap);
	for (i = 0; i < TFW_HEAP_NODE_STRESS_TEST_COUNT; i++) {
		tfw_heap_node_init(&stress[i], get_random_int());
		tfw_heap_insert(&heap, &stress[i]);
	}

	for (i = 0; i < TFW_HEAP_NODE_STRESS_TEST_COUNT; i++) {
		to_remove = get_random_int() % TFW_HEAP_NODE_STRESS_TEST_COUNT;
		/*
		 * Check that removing of the random node doesn't
		 * break heap.
		 */
		node = tfw_heap_remove(&heap, &stress[to_remove]);
		tfw_heap_node_init(node, get_random_int());
		tfw_heap_insert(&heap, node);
		/*
		 * Find minimal node using linear search and compare
		 * it with the minimal value from the heap.
		 */
		min = find_min_key(stress, TFW_HEAP_NODE_STRESS_TEST_COUNT);
		node = tfw_heap_extract_min(&heap);
		EXPECT_EQ(node->key, min);
		tfw_heap_node_init(node, get_random_int());
		tfw_heap_insert(&heap, node);
	}
}

TEST_SUITE(heap)
{
	TEST_RUN(heap, insert);
	TEST_RUN(heap, remove);
	TEST_RUN(heap, merge);
	TEST_RUN(heap, extract_min);
	TEST_RUN(heap, random_stress_extract_min);
	TEST_RUN(heap, random_stress_remove);
}