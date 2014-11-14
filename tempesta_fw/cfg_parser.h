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
#ifndef __TFW_CFG_PARSER_H__
#define __TFW_CFG_PARSER_H__

#include <linux/types.h>
#include "addr.h"

/*
 * The node of a parsed configuration tree.
 * See the complete structure definition for details.
 */
typedef struct TfwCfgNode TfwCfgNode;
typedef struct TfwCfgVal TfwCfgVal;

void tfw_cfg_node_free(const TfwCfgNode *node);

int tfw_cfg_val_cast_int(const TfwCfgVal *val, int *out);
int tfw_cfg_val_cast_bool(const TfwCfgVal *val, bool *out);
int tfw_cfg_val_cast_addr(const TfwCfgVal *val, const TfwAddr **out);
int tfw_cfg_val_cast_str(const TfwCfgVal *val, const char **out);

int tfw_cfg_parse_int(const char *str, int *out_num);
int tfw_cfg_parse_bool(const char *str, bool *out_bool);
int tfw_cfg_parse_addr(const char *str, TfwAddr *out_addr);

const TfwCfgNode *tfw_cfg_parse(const char *cfg_text);
const TfwCfgNode *tfw_cfg_parse_single_node(const char *cfg_text);

const TfwCfgVal *tfw_cfg_node_get_val(const TfwCfgNode *node, int n);
const TfwCfgVal *tfw_cfg_node_get_attr(const TfwCfgNode *node, const char *name);
const TfwCfgNode *tfw_cfg_node_get_child(const TfwCfgNode *node, const char *name);

const TfwCfgNode *tfw_cfg_node_descend(const TfwCfgNode *root, const char *path);

#define TFW_CFG_NODE_VAL(node, out_type, out_var) \
	TFW_CFG_NODE_GET_VAL(node, 0, out_type, out_var)

#define TFW_CFG_NODE_GET_VAL(node, n, out_type, out_var)	\
({								\
	const TfwCfgVal *_v = tfw_cfg_node_get_val(node, n);	\
	tfw_cfg_val_cast_##out_type(_v, &(out_var));		\
})

#define TFW_CFG_NODE_ATTR_GET(node, attr_name, out_type, out_var) 	\
({ 									\
	const TfwCfgVal *_v = tfw_cfg_node_get_attr(node, attr_name); 	\
	tfw_cfg_val_cast_##out_type(_v, &(out_var));			\
})

/**
 * Fetch a value from a node parsed by tfw_cfg_parse().
 *
 * Consider the following example config text, parsed by tfw_cfg_parse():
 *   server is_slave=true {
 *          name example.com;
 *          listen [::0]:80;
 *          backends 10.0.0.1:80 10.0.0.2:80  default=10.0.0.1:80;
 *
 *          cache {
 *                  size 65536;
 *          }
 *   }
 *   TfwCfgNode *cfg = tfw_cfg_parse(the text above);
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
 * When the value cannot be fetched, the macro returns -1 and tries to leave
 * some "zero" object (NULL or 0 or something like that) in the @out_var.
 */
#define TFW_CFG_GET(root, path, field, key, out_type, out_var) \
({ 									\
	const TfwCfgNode *_n = tfw_cfg_node_descend(root, path); 	\
	!_n ? -1 :							\
		tfw_cfg_val_cast_##out_type(				\
			tfw_cfg_node_get_##field(_n, key),		\
			&(out_var));					\
})

static inline int
tfw_cfg_val_cast_node(const TfwCfgNode *in, const TfwCfgNode **out)
{
	/* This hack provides a kind of polymorphism for TFW_CFG_GET(). */
	*out = in;
	return -(!in);
}


#endif /* __TFW_CFG_PARSER_H__ */
