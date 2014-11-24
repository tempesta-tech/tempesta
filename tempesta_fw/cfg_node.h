/**
 *		Tempesta FW
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
#ifndef __TFW_CFG_NODE_H__
#define __TFW_CFG_NODE_H__

#include "addr.h"

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode methods.
 * ------------------------------------------------------------------------
 */

/**
 * Node is an element of a parsed configuration tree.
 * See its definition for details.
 * Totally opaque here. Use the methods declared below.
 */
typedef struct TfwCfgNode TfwCfgNode;

TfwCfgNode *tfw_cfg_node_alloc(const char *name);
void tfw_cfg_node_free(TfwCfgNode *node);

/*
 * A node has:
 *  - name
 *  - values (a list of dynamically-typed values);
 *  - attributes (dictionary of key-value pairs);
 *  - children nodes (links to children TfwCfgNode objects forming a tree);
 *
 * The following declarations are methods for working for each kind of entities
 * listed above.
 */

/* Node name. */
const char *tfw_cfg_nname_get(const TfwCfgNode *node);
bool tfw_cfg_nname_eq(const TfwCfgNode *node, const char *name);


/* List of values. */

/* Values are "dynamically" typed. The actual value and its type is stored
 * in the TfwCfgVal structure (see definitions and casting macros below). */
typedef struct TfwCfgVal TfwCfgVal;

int tfw_cfg_nval_count(const TfwCfgNode *node);
int tfw_cfg_nval_add(TfwCfgNode *node, const TfwCfgVal *val);
const TfwCfgVal *tfw_cfg_nval_get(const TfwCfgNode *node, int index);

const TfwCfgVal *tfw_cfg_nval_first(const TfwCfgNode *node);
const TfwCfgVal *tfw_cfg_nval_next(const TfwCfgNode *node, const TfwCfgVal *curr);

/**
 * Iterate over values of TfwCfgNode.
 *
 * Example:
 *   TfwCfgNode *node = parse(...);
 *   const TfwCfgVal *current_value;
 *
 *   TFW_CFG_NVAL_EACH(node, current_value) {
 *          TfwCfgAddr *current_addr;
 *          tfw_cfg_val_cast_addr(current_value, &current_addr);
 *   }
 */
#define TFW_CFG_NVAL_EACH(node, val) \
	for ((val) = tfw_cfg_nval_first(node); \
	     (val); \
	     (val) = tfw_cfg_nval_next((node), (val)))


/* Node attributes. */

int tfw_cfg_nattr_set(TfwCfgNode *node, const char *name, const TfwCfgVal *val);
const TfwCfgVal *tfw_cfg_nattr_get(const TfwCfgNode *node, const char *name);

void tfw_cfg_nattr_first(const TfwCfgNode *node, const char **out_name,
			 const TfwCfgVal **out_val);
void tfw_cfg_nattr_next(const TfwCfgNode *node, const char **inout_name,
		        const TfwCfgVal **inout_val);

/**
 * Iterate over attributes of TfwCfgNode.
 *
 * Example:
 *   TfwCfgNode *node = parse(...);
 *   const char *attr_name;
 *   const TfwCfgVal *attr_value;
 *
 *   TFW_CFG_NATTR_EACH(node, attr_name, attr_value) {
 *           int integer_value;
 *           tfw_cfg_val_cast_int(attr_value, &integer_value);
 *           printk("%s = %d\n", attr_name, integer_value);
 *   }
 */
#define TFW_CFG_NATTR_EACH(node, name, val) \
	for (tfw_cfg_nattr_first(node, &name, &val); \
	     (name); \
	     tfw_cfg_nattr_next(node, &name, &val))


/* Children nodes. */

int tfw_cfg_nchild_add(TfwCfgNode *parent, TfwCfgNode *new_child);
TfwCfgNode *tfw_cfg_nchild_get(const TfwCfgNode *node, const char *name);

TfwCfgNode *tfw_cfg_nchild_first(const TfwCfgNode *parent);
TfwCfgNode *tfw_cfg_nchild_next(const TfwCfgNode *parent, const TfwCfgNode *curr);

/**
 * Iterate over children nodes of a TfwCfgNode.
 *
 * Example:
 *   TfwCfgNode *root = tfw_cfg_parse(...);
 *   TfwCfgNode *current_child;
 *
 *   TFW_CFG_NCHILD_EACH(root, current_child) {
 *           const char *child_name = tfw_cfg_nname_get(current_child);
 *           printk("child: %s\n", child_name);
 *   }
 */
#define TFW_CFG_NCHILD_EACH(parent, child) \
	for ((child) = tfw_cfg_nchild_first(parent); \
	     (child); \
	     (child) = tfw_cfg_nchild_next((parent), (child)))


/* Affects the root node as well, so has 'node' instead of 'nchild' in the name. */

typedef int (*tfw_cfg_node_walk_cb_t)(TfwCfgNode *curr, void *arg);

int tfw_cfg_node_walk(TfwCfgNode *root, const char *path,
			   tfw_cfg_node_walk_cb_t callback, void *arg);

TfwCfgNode *tfw_cfg_node_descend(const TfwCfgNode *root, const char *path);


/*
 * ------------------------------------------------------------------------
 *	Helpers for fetching values/attributes from TfwCfgNode.
 * ------------------------------------------------------------------------
 */

/*
 * We have to emulate dynamic typing here, because at this level we can't
 * determine value types. For example, how should the "1" be interpreted?
 * As a number or as a boolean or as a string?
 * What if we would like to be able to specify either "cache 8192" or
 * "cache auto"? What type should the value have then?
 *
 * Such decisions are made not here, but in higher-level modules that use
 * the data in their own way. Therefore, we store all parsed instances of
 * a value and let the higher level modules to decide on the type.
 *
 * NOTE:
 *  1. Fields in this structure are "private" to the configuration subsystem.
 *     Don't access them directly from outside. Use macros defined below.
 *  2. The structure is created and modified only by the parser and then
 *     remains immutable (except for prev/next pointers). Don't modify it.
 */
typedef struct TfwCfgVal {
	/* The structure may act both as a value and attribute (the @siblings
	 * is placed to either @val_list or @attr_list of TfwCfgNode).
	 * The @attr_name is not NULL only when it is an attribute.
	 * Actually we are cheating here and using the same structure and
	 * implement both values (list) and attribute (dictionary) with a
	 * linked list which is not efficient.This is a subject to change,
	 * so don't use these two fields outside of the cfg_node.c. */
	struct list_head siblings;
	const char *attr_name;

	/* The @mask determines which fields below are valid. */
	u8 mask;

	bool	val_bool;
	int	val_int;
	TfwAddr val_addr;
	char	val_str[];  /* Always available. */
} TfwCfgVal;

typedef enum {
	TFW_CFG_VAL_bool  = 1 << 0,
	TFW_CFG_VAL_int   = 1 << 1,
	TFW_CFG_VAL_addr  = 1 << 2,
	TFW_CFG_VAL_str	  = 1 << 3,
	TFW_CFG_VAL_MASK  = 0b1111ul,
} tfw_cfg_val_mask_t;

TfwCfgVal *tfw_cfg_val_alloc(size_t str_len);
TfwCfgVal *tfw_cfg_val_clone(const TfwCfgVal *src);
void tfw_cfg_val_free(TfwCfgVal *val);


/* Helper types for token pasting (e.g. #define foo(t) tfw_cfg_val_type_##t). */
typedef int tfw_cfg_val_type_int;
typedef bool tfw_cfg_val_type_bool;
typedef const char * tfw_cfg_val_type_str;
typedef const TfwAddr * tfw_cfg_val_type_addr;

/*
 * The dynamic-to-static conversion is always painful.
 * Every time we want to extract such a "dynamically-typed" value, we have to
 * handle each possible static C type separately. We can't avoid that, but
 * we can reduce the amount of duplicate code as much as possible by using
 * code generation like in this macro.
 */
#define TFW_CFG_VAL_DO_CAST(val, ref_op, type, out_ptr)		\
({								\
	int _r = -1;						\
	if (val) {						\
		if (val->mask & TFW_CFG_VAL_##type) {		\
			_r = 0;					\
			*out_ptr = ref_op val->val_##type;	\
		}						\
	}							\
	_r;							\
})

static inline int
tfw_cfg_val_cast_int(const TfwCfgVal *val, int *out)
{
	return TFW_CFG_VAL_DO_CAST(val,  , int, out);
}

static inline int
tfw_cfg_val_cast_bool(const TfwCfgVal *val, bool *out)
{
	return TFW_CFG_VAL_DO_CAST(val,  , bool, out);
}

static inline int
tfw_cfg_val_cast_addr(const TfwCfgVal *val, const TfwAddr **out)
{
	return TFW_CFG_VAL_DO_CAST(val, &, addr, out);
}

static inline int
tfw_cfg_val_cast_str(const TfwCfgVal *val, const char **out)
{
	return TFW_CFG_VAL_DO_CAST(val, , str, out);
}

/**
 * A special hack for TFW_CFG_GET().
 * Allows to fetch children nodes in addition to values and attributes.
 */
static inline int
tfw_cfg_val_cast_node(TfwCfgNode *in, TfwCfgNode **out)
{
	*out = in;
	return -(!in);
}

/**
 * Get @n'th value of a @node and cast it to a specified @type.
 *
 * Example:
 *    TfwCfgNode *node = parse("listen 127.0.0.1 80;");
 *    const char *addr;
 *    int port;
 *    TFW_CFG_NVAL_GET(node, 0, str, addr);
 *    TFW_CFG_NVAL_GET(node, 1, int, port);
 */
#define TFW_CFG_NVAL_GET(node, n, type, out_var)	\
({							\
	const TfwCfgVal *_v = tfw_cfg_nval_get(node, n);\
	tfw_cfg_val_cast_##type(_v, &(out_var));	\
})

#define TFW_CFG_NVAL(node, out_type, out_var) \
	TFW_CFG_NVAL_GET(node, 0, out_type, out_var)

/**
 * Get a value of node's attribute.
 *
 * Example:
 *   TfwCfgNode *node = parse("server 127.0.0.1 https=true weight=10;");
 *   bool https_is_enabled;
 *   int srv_weight;
 *   TFW_CFG_NATTR_GET(node, "https", bool, https_is_enabled);
 *   TFW_CFG_NATTR_GET(node, "weight", int, srv_weight);
 */
#define TFW_CFG_NATTR_GET(node, attr_name, type, out_var) 		\
({ 									\
	const TfwCfgVal *_v = tfw_cfg_nattr_get(node, attr_name); 	\
	tfw_cfg_val_cast_##type(_v, &(out_var));			\
})

/**
 * TFW_CFG_GET() - Given a node, get its value or attribute or a child node.
 *
 * Consider the following example node (already parsed and so on):
 *   server is_slave=true {
 *          name example.com;
 *          listen [::0]:80;
 *          backends 10.0.0.1:80 10.0.0.2:80  default=10.0.0.1:80;
 *
 *          cache {
 *                  size 65536;
 *          }
 *   }
 *
 * Here what you can do with the TFW_CFG_GET():
 *
 * 1. Get the server name:
 *   const char *name;
 *   TFW_CFG_GET(cfg, "server.name", val, 0, int, name);
 *
 * 2. Get the value of "is_slave" attribute:
 *   bool is_slave;
 *   TFW_CFG_GET(cfg, "server", attr, 0, bool, is_slave);
 *
 * 3. Get two backends (values) and the default backend (attribute):
 *   const TfwCfgAddr *be1, *be2, *be_default;
 *   TFW_CFG_GET(cfg, "server.backends", val, 0, be1);
 *   TFW_CFG_GET(cfg, "server.backends", val, 1, be2);
 *   TFW_CFG_GET(cfg, "server.backends", attr, "default", be_default);
 *
 * 4. Get a nested node:
 *   const TfwCfgNode *cache_cfg;
 *   TFW_CFG_GET(cfg, "server", child, "cache", node, cache_cfg);
 *
 * In general, the algorigthm is the following:
 *   1. Start with the given @root node.
 *   2. Descend across the children nodes recursively according to
 *      the given @path.
 *   3. When the destination node is reached, choose one of its fields
 *      (values, attributes, children) according to the given @field.
 *   4. The field is a collection, so select a value by the given @key.
 *   5. Convert the value to the given @out_type.
 *   6. Store it to the @out_var.
 *
 * @field is one of:
 *   - val   (and then @key is a position index in the value list).
 *   - attr  (and then @key is the name of an attribute).
 *   - child (and then @key is the name of a children node).
 *
 * @out_type is one of:
 *   - int  (no long/short/etc allowed)
 *   - bool
 *   - str  (means: const char *)
 *   - addr (means: const TfwCfgAddr)
 * The type of @out_var must correspond to the @out_type.
 *
 * When the value cannot be fetched, the macro returns -1 and leaves
 * the @out_var initialized to zero.
 */
#define TFW_CFG_GET(root, path, field, key, out_type, out_var)	\
({ 								\
	TfwCfgNode *_n = tfw_cfg_node_descend(root, path); 	\
	out_var = 0;						\
	!_n ? -1 :						\
		tfw_cfg_val_cast_##out_type(			\
			tfw_cfg_n ##field ##_get(_n, key),	\
			&(out_var));				\
})


#endif /* __TFW_CFG_NODE_H__ */
