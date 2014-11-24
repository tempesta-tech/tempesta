/**
 *		Tempesta FW
 *
 *  TfwCfgNode implementation.
 *
 * The TfwCfgNode is a generic data structure that combines a list, a dictionary
 * and a tree (not a search tree, but a kind of graph).
 *
 * The idea is inspired by SDL - the Simple Declarative Language
 * (see http://www.ikayzo.org/display/SDL/Language+Guide).
 * We use similar, but still very own language which is more akin to Nginx
 * configuration than some ruby code.
 *
 * Nodes are linked into a tree which is created when the configuration text
 * is parsed. For better understanding, consider the following example:
 * (this is not a real Tempesta configuration, just a valid example of syntax)
 *    server mode=reverse_proxy {
 *        server_name         example.com;
 *        listen              192.168.0.1:8080;
 *        backends            10.1.1.1:80  10.1.1.2:80  10.1.1.3:80;
 *    }
 * The example above is parsed into the following tree (pseudocode):
 *  TfwCfgNode {
 *      .name = "server",
 *      .val = list [],
 *      .attr = dict { "mode" = "reverse_proxy" },
 *      .child = list [
 *          TfwCfgNode {
 *              .name = "server_name",
 *              .val = list [ "example.com" ],
 *              .attr = dict {},
 *              .child = list []
 *          },
 *          TfwCfgNode {
 *              .name = "listen",
 *              .val = list [ "192.168.0.1:8080" ],
 *              .attr = dict {},
 *              .child = list []
 *          },
 *          TfwCfgNode {
 *              .name = "backends",
 *              .val = list [ "10.1.1.1:80"  "10.1.1.2:80"  "10.1.1.3:80" ],
 *              .attr = dict {},
 *              .child = list []
 *          }
 *      ]
 *  }
 *
 * There is no difference between sections and directives, both are implemented
 * as nodes. A directive is simply a node without children nodes, and a section
 * is a node who has children.
 *
 * So each node has:
 *  1. A name that acts as a key when searching a node in a tree.
 *     The name is very similar to C identifier: it is a string that must start
 *     with a letter and consist of alpha-numeric characters and underscores.
 *  2. A list of values. Values are represented by the TfwCfgVal structure.
 *     Values are actually "dynamically" typed since we can't know what data
 *     user puts to the configuration file and what types higher-level modules
 *     expect to see. So the TfwCfgVal contains type information and the actual
 *     value.
 *  3. A dictionary of attributes. Each attribute is a name + TfwCfgVal pair.
 *     The attribute name has the same restrictions as the node name.
 *  4. A list of children TfwCfgNode objects that allows to link nodes into
 *     a tree (that is done by a parser that builds the tree).
 *
 * A name is required, and all other entities are optional (may be empty lists).
 *
 * Each entity has its own set of methods:
 *  - tfw_cfg_nname_*  - name
 *  - tfw_cfg_nval_*   - value list
 *  - tfw_cfg_nattr_*  - attributes
 *  - tfw_cfg_nchild_* - children nodes
 *
 * Also, there are tfw_cfg_node_* for more general methods and tfw_cfg_val_*
 * for working with TfwCfgVal.
 *
 * TODO:
 *   1. More efficient attribute implementation.
 *      Currently the attributes dictionary is implemented as a linked list.
 *      That may be slow if we are going to specify many attributes in the
 *      configuration. But if there are few attributes, the linked list is good,
 *      perhaps an array would be even better.
 *   2. Support for references in configuration files (implies shared nodes,
 *      cycles in the node graph (not a tree anymore), reference counters, etc).
 *   3. XPath-like syntax for querying tree of nodes.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "cfg_private.h"
#include "cfg_node.h"


/**
 * An element of a parsed configuration tree.
 * See the header comment at the top of this file.
 */
typedef struct TfwCfgNode {
	struct list_head siblings;	/* The element of @child_list. */

	/* The name is used as a key for searching children nodes.
	 * Must be an identifier (starts with a letter, no spaces, etc). */
	const char *name;

	struct list_head val_list;	/* Consists of TfwCfgVal. */
	struct list_head attr_list;	/* Consists of TfwCfgVal. */
	struct list_head child_list;	/* Consists of TfwCfgNode. */

	/* Used for debugging and error reporting. */
	struct {
		const char *src;
		const char *file;
		int line;
	} meta;
} TfwCfgNode;

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - validation routines
 * ------------------------------------------------------------------------
 *
 * There are two kinds of validation functions:
 *
 * 1. validate_name()/validate_val()/etc
 *    These functions produce BUG() if the object is not valid.
 *    We use them to validate objects created by us here, or to check input
 *    arguments when we are sure that argument values are specified in the
 *    source code and not taken from a configuration file.
 *
 * 1. name_is_valid()/val_is_valid()/etc
 *    They are used in routines like tfw_cfg_nval_add() and tfw_cfg_nattr_set().
 *    Arguments to these functions are coming from a configuration file.
 *    An invalid value in a configuration file should not crash anything, so we
 *    return -EINVAL instead of doing BUG() in this case.
 */

/**
 * Check that a node or attribute name is valid.
 *
 * A valid name is a string that satisfies the following constraints:
 *   - It is not empty and not longer than 64 characters.
 *   - It consists of only of letters, didgits and underscore characters (no
 *     spaces, punctuation marks and so on).
 *   - It doesn't start with a digit.
 */
static bool
name_is_valid(const char *str)
{
	size_t len;
	char c;

	if (!str)
		return false;

	c = str[0];
	if (!isalpha(c) && c != '_')
		return false;

	len = 1;
	while (*++str) {
		++len;
		c = *str;
		if (!isalnum(c) && c != '_')
			return false;
	}

	if (len == 0 || len > TFW_CFG_NAME_MAX_LEN)
		return false;

	return true;
}

static bool
val_is_valid(const TfwCfgVal *val)
{
	const char *s;
	size_t len;

	if (!val)
		return false;

	if (val->attr_name && !name_is_valid(val->attr_name))
		return false;

	if (val->mask & ~TFW_CFG_VAL_MASK)
		return false;

	s = val->val_str;
	len = 0;
	while (*s) {
		if (!isascii(*s))
			return false;
		++s;
		++len;
	}

	if (len > TFW_CFG_STR_MAX_LEN)
		return false;

	return true;
}

static void
validate_name(const char *name)
{
	BUG_ON(!name);

	IF_DEBUG {
		BUG_ON(!name_is_valid(name));
	}
}

static void
validate_path(const char *path)
{
	BUG_ON(!path);

	IF_DEBUG {
		char c;
		int len = 0;

		while ((c = *path++)) {
			++len;
			BUG_ON(!isalnum(c) && c != '_' && c != '.');
		}

		BUG_ON(len > TFW_CFG_PATH_MAX_LEN);
	}
}

static void
validate_val(const TfwCfgVal *val)
{
	BUG_ON(!val);

	IF_DEBUG {
		BUG_ON(!val_is_valid(val));
	}
}

static void
validate_node(const TfwCfgNode *node)
{
	BUG_ON(!node);

	IF_DEBUG {
		TfwCfgVal *val;
		TfwCfgVal *attr;
		TfwCfgNode *child;

		validate_name(node->name);

		list_for_each_entry(val, &node->val_list, siblings) {
			validate_val(val);
		}

		list_for_each_entry(attr, &node->attr_list, siblings) {
			validate_val(attr);
		}

		list_for_each_entry(child, &node->child_list, siblings) {
			validate_node(child);
		}
	}
}

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - general methods.
 * ------------------------------------------------------------------------
 */

static const char *
alloc_and_copy_str(const char *str)
{
	size_t len;
	char *new_str;

	len = strlen(str);
	new_str = kmalloc(len + 1, GFP_KERNEL);
	BUG_ON(!new_str);

	memcpy(new_str, str, len);
	new_str[len] = '\0';

	return new_str;

}

/**
 * Create a new node with given @name.
 *
 * The @name must be valid (non empty, consist of alpha-numeric characters and
 * so on, see name_is_valid()).
 *
 * The @name is copied and stored inside the node, so you don't need to care
 * about its lifetime.
 */
TfwCfgNode *
tfw_cfg_node_alloc(const char *name)
{
	TfwCfgNode *node;

	if (!name_is_valid(name))
		return NULL;

	node = kzalloc(sizeof(*node), GFP_KERNEL);

	INIT_LIST_HEAD(&node->siblings);
	INIT_LIST_HEAD(&node->val_list);
	INIT_LIST_HEAD(&node->attr_list);
	INIT_LIST_HEAD(&node->child_list);

	node->name = alloc_and_copy_str(name);

	validate_node(node);

	return node;
}

void
tfw_cfg_node_free(TfwCfgNode *node)
{
	TfwCfgVal *val, *attr, *tmp1;
	TfwCfgNode *child, *tmp2;

	if (!node)
		return;

	validate_node(node);

	list_del(&node->siblings);
	kfree(node->name);

	list_for_each_entry_safe(val, tmp1, &node->val_list, siblings) {
		tfw_cfg_val_free(val);
	}
	list_for_each_entry_safe(attr, tmp1, &node->attr_list, siblings) {
		tfw_cfg_val_free(attr);
	}
	list_for_each_entry_safe(child, tmp2, &node->child_list, siblings) {
		tfw_cfg_node_free(child);
	}

	kfree(node);
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_node_free);

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - name related methods.
 * ------------------------------------------------------------------------
 */

/**
 * Get node name.
 *
 * You don't need to free the returned string, it is attached to the @node and
 * freed together with it (so be careful to not use the string after the @node
 * is freed).
 */
const char *
tfw_cfg_nname_get(const TfwCfgNode *node)
{
	validate_node(node);

	return node->name;
}

/**
 * Return true if @node's name matches to the given @name.
 *
 * The function just does a case-insensitive comparison for you.
 * Useful when you are walking over a tree and want to select only needed nodes.
 */
bool
tfw_cfg_nname_eq(const TfwCfgNode *node, const char *name)
{
	return !strcasecmp(node->name, name);
}

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - value list.
 * ------------------------------------------------------------------------
 */

int
tfw_cfg_nval_count(const TfwCfgNode *node)
{
	int n = 0;
	struct list_head *pos;

	validate_node(node);

	list_for_each(pos, &node->val_list) {
		++n;
	}

	return n;
}

/**
 * Append an item to the tail of the @node's value list.
 */
int
tfw_cfg_nval_add(TfwCfgNode *node, const TfwCfgVal *v)
{
	TfwCfgVal *val = (TfwCfgVal *)v;

	validate_node(node);

	if (!val_is_valid(val))
		return -EINVAL;

	list_add_tail(&val->siblings, &node->val_list);

	return 0;
}

/**
 * Get an item from the @node's value list.
 * @index is a position in the list (counting from zero).
 *
 * The returned value is attached to the @node and freed together with it,
 * so you don't need to free it manually, but you must pay attention to not
 * reference it after the node is freed.
 */
const TfwCfgVal *
tfw_cfg_nval_get(const TfwCfgNode *node, int index)
{
	TfwCfgVal *vp;

	validate_node(node);
	BUG_ON(index < 0 || index > TFW_CFG_NODE_MAX_VALS);

	list_for_each_entry(vp, &node->val_list, siblings) {
		if (!index)
			return vp;
		--index;
	}

	return NULL;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_nval_get);

const TfwCfgVal *
tfw_cfg_nval_first(const TfwCfgNode *node)
{
	validate_node(node);

	return list_first_entry_or_null(&node->val_list, TfwCfgVal, siblings);
}

const TfwCfgVal *
tfw_cfg_nval_next(const TfwCfgNode *node, const TfwCfgVal *curr)
{
	validate_node(node);
	validate_val(curr);

	if (curr->siblings.next == &node->val_list)
		return NULL;

	return list_entry(curr->siblings.next, TfwCfgVal, siblings);
}

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - attributes.
 * ------------------------------------------------------------------------
 */

static TfwCfgVal *
find_node_attr(const TfwCfgNode *node, const char *name)
{
	TfwCfgVal *attr;

	list_for_each_entry(attr, &node->attr_list, siblings) {
		if (!strcasecmp(name, attr->attr_name))
			return attr;
	}

	return NULL;
}

/**
 * Set attribute (a key-value pair) of a node.
 *
 * @attr_name is copied and stored inside the node, you don't need to care
 * about its lifetime.
 *
 * @attr_val is not copied, you need to allocate it with tfw_cfg_val_alloc()
 * before calling this function. After setting the attribute, the pointer is
 * stored inside the @node and freed together with it.
 *
 * If an attribute with given @attr_name doesn't exist - it is created,
 * otherwise its value is replaced.
 */
int
tfw_cfg_nattr_set(TfwCfgNode *node, const char *attr_name,
		  const TfwCfgVal *attr_val)
{
	TfwCfgVal *val = (TfwCfgVal *)attr_val;
	TfwCfgVal *existing_attr;

	validate_node(node);

	if (!name_is_valid(attr_name) || !val_is_valid(val))
		return -EINVAL;

	existing_attr = find_node_attr(node, attr_name);
	tfw_cfg_val_free(existing_attr);

	val->attr_name = alloc_and_copy_str(attr_name);
	list_add_tail(&val->siblings, &node->attr_list);

	return 0;
}

/**
 * Get node attribute: a value by the given key - @attr_name.
 *
 * The returned value is attached to the @node and freed together with it.
 * You don't need to free it manually, but the pointer becomes invalid when
 * the @node is freed.
 */
const TfwCfgVal *
tfw_cfg_nattr_get(const TfwCfgNode *node, const char *attr_name)
{
	validate_node(node);
	validate_name(attr_name);

	return find_node_attr(node, attr_name);
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_nattr_get);

void tfw_cfg_nattr_first(const TfwCfgNode *node, const char **out_name,
			 const TfwCfgVal **out_val)
{
	validate_node(node);
	BUG_ON(!out_name || !out_val);

	*out_val =  list_first_entry_or_null(&node->attr_list, TfwCfgVal, siblings);
	*out_name = (*out_val) ? (*out_val)->attr_name : NULL;
}

void tfw_cfg_nattr_next(const TfwCfgNode *node, const char **inout_name,
		        const TfwCfgVal **inout_val)
{
	const TfwCfgVal *curr, *next;

	validate_node(node);
	BUG_ON(!inout_name || !inout_val);
	BUG_ON(*inout_name != (*inout_val)->attr_name);
	validate_name(*inout_name);
	validate_val(*inout_val);

	curr = *inout_val;
	if (curr->siblings.next == &node->attr_list) {
		*inout_name = NULL;
		*inout_val = NULL;
	} else {
		next = list_entry(curr->siblings.next, TfwCfgVal, siblings);
		*inout_name = next->attr_name;
		*inout_val = next;
	}

}

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - children node methods
 * ------------------------------------------------------------------------
 */

/**
 * Append @new_child to the tail of the @parent's children list.
 */
int
tfw_cfg_nchild_add(TfwCfgNode *parent, TfwCfgNode *new_child)
{
	validate_node(parent);
	validate_node(new_child);

	list_add_tail(&new_child->siblings, &parent->child_list);

	return 0;
}

/**
 * Get a @parent's child node by the given @child_name.
 *
 * When
 *
 * You don't need to free the returned node manually. The pointer lives as long
 * as the @parent lives. Nodes are freed recursively, so all the children are
 * freed automatically together with their parents.
 */
TfwCfgNode *
tfw_cfg_nchild_get(const TfwCfgNode *parent, const char *child_name)
{
	TfwCfgNode *child;

	validate_node(parent);
	validate_name(child_name);

	list_for_each_entry(child, &parent->child_list, siblings) {
		if (tfw_cfg_nname_eq(child, child_name))
			return child;
	}

	return NULL;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_nchild_get);

TfwCfgNode *
tfw_cfg_nchild_first(const TfwCfgNode *parent)
{
	return list_first_entry_or_null(&parent->child_list, TfwCfgNode, siblings);
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_nchild_first);

TfwCfgNode *
tfw_cfg_nchild_next(const TfwCfgNode *parent, const TfwCfgNode *curr)
{
	if (curr->siblings.next == &parent->child_list)
		return NULL;

	return list_entry(curr->siblings.next, TfwCfgNode, siblings);
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_nchild_next);

static int
do_walk(TfwCfgNode *node, const char *desired_path, tfw_cfg_node_walk_cb_t callback,
	void *arg, char *current_path)
{
	int r;
	char *dot;
	TfwCfgNode *child;

	/* Append current node ".name" to the current_path. */
	if (current_path[0])
		strlcat(current_path, ".", TFW_CFG_PATH_MAX_LEN);
	strlcat(current_path, tfw_cfg_nname_get(node), TFW_CFG_PATH_MAX_LEN);

	/* Apply callback to the current node if we are at a right path
	 * (or if desired_path is not set that means any path is good). */
	if (!desired_path || !strcasecmp(desired_path, current_path)) {
		r = callback(node, arg);
		if (r)
			return r;
	}

	/* Apply to all children recursively. */
	TFW_CFG_NCHILD_EACH(node, child) {
		r = do_walk(child, desired_path, callback, arg, current_path);
		if (r)
			return r;
	}

	/* Pop current node name from the current_path. */
	dot = strrchr(current_path, '.');
	if (dot)
		*dot = '\0';
	else
		current_path[0] = '\0';

	return 0;
}

/**
 * Visit all nodes in a tree, invoke @callback for nodes whose path is
 * equal to the given @path.
 *
 * Nodes are visited in in-order-traversal-like way:
 *  1. Visit parent.
 *  2. Visit all children recursively.
 * So a parent node is passed to the @callback before its children nodes.
 *
 * @path is a sequence of dot-separated node names that describes position
 * of the current_node in the tree (e.g. "grandparent.parent.node_name").
 * If the @path is NULL then then @callback is invoked for all nodes.
 * If the @path is empty, then the @callback is invoked only for the @root node.
 *
 * The @callback has the following signature:
 *    int callback(TfwCfgNode *current_node, void *arg);
 *
 * @arg is passed to the @callback as is.
 * Usually you put a custom structure there to maintain the state between calls.
 *
 * When the callback returns non-zero, the walking process stops and the whole
 * function returns the value returned by the callback.
 */
int
tfw_cfg_node_walk(TfwCfgNode *root, const char *path,
		  tfw_cfg_node_walk_cb_t callback, void *arg)
{
	int r;
	TfwCfgNode *child;

	char path_buf[TFW_CFG_PATH_MAX_LEN + 1];
	path_buf[0] = '\0';

	/* Have to handle root and children nodes separately because the root
	 * node has the empty path (and not its name which is pusshed to the
	 * path_buf when do_walk is invoked). */
	if (!path || !*path) {
		r = callback(root, arg);
		if (r)
			return r;
	}

	TFW_CFG_NCHILD_EACH(root, child) {
		r = do_walk(child, path, callback, arg, path_buf);
		if (r)
			return r;
	}

	return 0;
}

static int
put_first_matching_node_to_arg(TfwCfgNode *node, void *arg)
{
	TfwCfgNode **nodep = arg;
	*nodep = node;

	return 1;
}

/**
 * Get a single node by its path in a tree.
 *
 * @path is a string containing dot-separated node names (e.g. "foo.bar.baz").
 *       Node names must be valid (contain no spaces, punctuation marks, etc).
 *       The path may be empty, in which case the @root is returned.
 *
 * The root node name is not specified in the @path.
 * For example, having the following tree:
 *   TfwCfgNode *root = tfw_cfg_parse(
 *     root {
 *         child1 {
 *              child1_1;
 *              child1_2;
 *         }
 *         child2;
 *         child3;
 *     }
 *   );
 * The child1_2 may be obtained by the following code:
 *   TfwCfgNode *n = tfw_cfg_node_descend(root, "child1.child1_2");
 */
TfwCfgNode *
tfw_cfg_node_descend(const TfwCfgNode *r, const char *path)
{
	TfwCfgNode *root = (TfwCfgNode *)r;
	TfwCfgNode *node = NULL;
	void *arg = &node;

	validate_node(root);
	validate_path(path);

	tfw_cfg_node_walk(root, path, put_first_matching_node_to_arg, arg);

	return node;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_node_descend);

/*
 * ------------------------------------------------------------------------
 *	TfwCfgVal related methods
 * ------------------------------------------------------------------------
 *
 * Values are allocated, filled and attached to a node only by internal
 * functions: by a parser or by a routine that sets default values.
 * Since that point, they should remain immutable, and in most cases you don't
 * need to alter them in other Tempesta modules.
 *
 * So these functions are "private" to the configuration framework.
 */

TfwCfgVal *
tfw_cfg_val_alloc(size_t str_val_len)
{
	TfwCfgVal *val;
	size_t total_len;

	if (str_val_len > TFW_CFG_STR_MAX_LEN)
		return NULL;

	total_len = sizeof(*val) + str_val_len + 1;
	val = kzalloc(total_len, GFP_KERNEL);
	BUG_ON(!val);

	INIT_LIST_HEAD(&val->siblings);
	validate_val(val);

	return val;
}

TfwCfgVal *
tfw_cfg_val_clone(const TfwCfgVal *src)
{
	size_t len = strlen(src->val_str) + 1;
	TfwCfgVal *new_val = tfw_cfg_val_alloc(len);

	memcpy(new_val, src, sizeof(*new_val) + len);

	/* We are copying only the value, but not implementation details. */
	new_val->attr_name = NULL;
	INIT_LIST_HEAD(&new_val->siblings);

	validate_val(new_val);

	return new_val;
}

void
tfw_cfg_val_free(TfwCfgVal *val)
{
	if (!val)
		return;

	validate_val(val);

	list_del(&val->siblings);

	kfree(val->attr_name);
	kfree(val);
}
