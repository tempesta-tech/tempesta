#include "test.h"
#include "helpers.h"

#define EB64_NODES_MAX 1000
static struct eb64_node nodes[EB64_NODES_MAX];

static long int
find_min_key(struct eb64_node *nodes, int size)
{
	long int min = nodes[0].key;
	unsigned int i;
	
	for (i = 1; i < size; i++) {
		if (nodes[i].key < min)
			min = nodes[i].key;
	}

	return min;
}

TEST(ebtree, extract_min)
{
	struct eb_root tree = EB_ROOT;
	struct eb64_node *root;
	long int min;
	unsigned int i;

	for (i = 0; i < EB64_NODES_MAX; i++) {
		nodes[i].key = get_random_int();
		eb64i_insert(&tree, &nodes[i]);
	}

	for (i = 0; i < EB64_NODES_MAX; i++) {
		/*
		 * Find minimal node using linear search and compare
		 * it with the minimal value from the tree.
		 */
		min = find_min_key(nodes, EB64_NODES_MAX);
		root = eb64_first(&tree);
		EXPECT_EQ(root->key, min);
		eb64_delete(root);
		root->key = get_random_int();
		eb64i_insert(&tree, root);
	}
}

TEST_SUITE(ebtree)
{
	TEST_RUN(ebtree, extract_min);
}