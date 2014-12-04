/**
 *		Tempesta FW
 *
 * The TfwCfgSpec is a little DSL for describing configuration rules
 * in a declarative manner.
 *
 * A spec looks like this:
 *  TfwCfgSpec s = {
 *          .path = "foo.bar.baz",       // path of a node
 *          .call_node = my_callback,    // what to do with this node
 *
 *          .attr = "is_enabled",        // name of an attribute within the node
 *          .set_bool = &my_variable,    // what to do with the attribute
 *   }
 *
 * Basically, each spec combines:
 *   1. Path to a node and a bunch of actions that are performed when such node
 *      is met in a parsed configuration tree.
 *   2. Attribute name or value position and a bunch of actions that performed
 *      on the value.
 *
 * There are various fields in the structure for specifying various actions:
 * set variable, call a callback, validate the value, set default value, etc.
 *
 * Nodes and values are different kinds of data and therefore have different
 * actions. Naturally they should be represented with different structures,
 * but that would be tricky in C, so we combine everything into the single
 * TfwCfgSpec structure and use an array of them to describe all the rules.
 *
 * For better understanding see the structure declaration, tests and usages in
 * real Tempesta FW modules.
 *
 * One final note is: why do we need the TfwCfgSpec and why just not query a
 * parsed configuration tree with functions from cfg_node.c?
 * The goals are:
 *   - Reduce amount of boilerplate code: ecach time you need to query the tree,
 *     check return codes, cast values (since they are dynamically typed), etc.
 *     Code in this unit does all this common function calls for you, and you
 *     just need to provide arguments via the spec.
 *   - The structure may be easily interpreted to build a default configuration
 *     file or documentation which is more tricky with C code.
 *   - Implicit validation: if you specify a callback that takes TfwAddr, then
 *     you likely expect only an IP address as a value, so we can check it and
 *     print an error message automatically.
 *   - Repetitive nodes (like a list of request matching rules in sched_http)
 *     are tricky to handle manually: you have to walk over the tree and compare
 *     the path manually. Code in this unit already does it for you.
 *   - A declarative set of rules is likely easier to read than imperative C
 *     code. Also the code style is likely to be more uniform across modules.
 *
 * TODO:
 *   - Validation (either implicit or explicit).
 *   - Generating documentation and default config file.
 *   - Spec fields that allow to add objects to collections like linked lists
 *     and remove them when the configuration is changed (collect garbage).
 *   - Better error messages: user should see some metadata: file/line/source
 *     when validation failed or a callback returned an error code.
 *   - Handle conflicts between specs of different modules: for example, what
 *     happens if two modules define different default values for the same node?
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

#include "cfg_private.h"
#include "cfg_parser.h"
#include "cfg_spec.h"


#define for_each_spec(pos, array) \
	for (spec = &array[0]; (spec->path != NULL); ++spec)

static void
create_default_node(const TfwCfgSpec *spec, TfwCfgNode *cfg_root)
{
	int r;
	TfwCfgNode *parent, *default_node;
	char *dot;
	char parent_path[TFW_CFG_PATH_MAX_LEN];

	BUG_ON(!spec->deflt || !*spec->deflt);  /* Empty default value? */
	BUG_ON(!*spec->path);			/* Default for a root node? */

	strlcpy(parent_path, spec->path, sizeof(parent_path));
	dot = strrchr(parent_path, '.');
	if (dot)
		*dot = '\0';
	else
		parent_path[0] = '\0';

	parent = tfw_cfg_node_descend(cfg_root, parent_path);
	BUG_ON(!parent);

	default_node = tfw_cfg_parse_single_node(spec->deflt);
	BUG_ON(!default_node);

	r = tfw_cfg_nchild_add(parent, default_node);
	BUG_ON(r);
}

static int
merge_in_defaults(TfwCfgNode *node, void *arg)
{
	TfwCfgNode *default_node = arg;
	const TfwCfgVal *val, *copied_val;
	const char *name;
	int r, node_val_count, default_val_nth;

	/* Just a sanity check. Actually we don't need the node name. */
	name = tfw_cfg_nname_get(default_node);
	BUG_ON(!tfw_cfg_nname_eq(node, name));

	/* Add default values starting at a position where @node's list ends. */
	node_val_count = tfw_cfg_nval_count(node);
	default_val_nth = 0;
	TFW_CFG_NVAL_EACH(default_node, val) {
		++default_val_nth;

		if (default_val_nth > node_val_count) {
			copied_val = tfw_cfg_val_clone(val);
			BUG_ON(!copied_val);

			r = tfw_cfg_nval_add(node, copied_val);
			BUG_ON(r);
		}
	}

	/* Set only attributes that are not present in the @node. */
	TFW_CFG_NATTR_EACH(default_node, name, val) {
		if (!tfw_cfg_nattr_get(node, name)) {
			copied_val = tfw_cfg_val_clone(val);
			BUG_ON(!copied_val);

			r = tfw_cfg_nattr_set(node, name, copied_val);
			BUG_ON(r);
		}
	}

	/* No support for merging subtrees yet. */
	BUG_ON(tfw_cfg_nchild_first(default_node));

	return 0;
}

void
tfw_cfg_spec_set_defaults(const TfwCfgSpec spec_arr[], TfwCfgNode *cfg_root)
{
	const TfwCfgSpec *spec;
	TfwCfgNode *node;

	for_each_spec(spec, spec_arr) {
		if (spec->deflt && spec->is_not_singleton) {
			node = tfw_cfg_parse_single_node(spec->deflt);
			BUG_ON(!node);

			tfw_cfg_node_walk(cfg_root, spec->path,
					  merge_in_defaults, node);

			tfw_cfg_node_free(node);
		}

		if (spec->deflt && !spec->is_not_singleton) {
			node = tfw_cfg_node_descend(cfg_root, spec->path);
			if (!node)
				create_default_node(spec, cfg_root);
		}
	}
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_spec_set_defaults);


int
tfw_cfg_spec_validate(const TfwCfgSpec spec_arr[], const TfwCfgNode *cfg_root)
{
	return 0;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_spec_validate);


static int
apply_val_fields(const TfwCfgSpec *spec, const TfwCfgVal *val)
{
#define DO_SET(type) \
	if (spec->set_##type) \
		tfw_cfg_val_cast_##type(val, spec->set_##type)

	DO_SET(int);
	DO_SET(bool);
	DO_SET(str);
	DO_SET(addr);

#undef DO_SET

#define DO_CB(type) 						\
	if (spec->call_##type) { 				\
		tfw_cfg_val_type_##type _val = 0;		\
		int ret = 0;					\
		if (!tfw_cfg_val_cast_##type(val, &_val))	\
			ret = spec->call_##type(_val);		\
		if (ret)					\
			return ret;				\
	}

	DO_CB(int);
	DO_CB(bool);
	DO_CB(str);
	DO_CB(addr);

#undef DO_CB

	return 0;
}

static int
apply_node_fields(const TfwCfgSpec *spec, TfwCfgNode *node)
{
	if (spec->call_node)
		return spec->call_node(node);

	return 0;
}

static int
apply_spec_to_node(TfwCfgNode *node, void *arg)
{
	const TfwCfgSpec *spec = arg;
	const TfwCfgVal *val;
	int ret;

	ret = apply_node_fields(spec, node);
	if (ret)
		return ret;

	if (spec->attr) {
		val = tfw_cfg_nattr_get(node, spec->attr);
		ret = apply_val_fields(spec, val);
	}
	else if (spec->val_each) {
		TFW_CFG_NVAL_EACH(node, val) {
			ret = apply_val_fields(spec, val);
			if (ret)
				break;
		}
	}
	else {
		val = tfw_cfg_nval_get(node, spec->val_pos);
		ret = apply_val_fields(spec, val);
	}

	return ret;
}

int
tfw_cfg_spec_apply(const TfwCfgSpec spec_arr[], const TfwCfgNode *cfg_root)
{
	TfwCfgNode *root;
	const TfwCfgSpec *spec;
	const char *path;
	void *arg;
	int ret;

	for_each_spec(spec, spec_arr) {
		root = (TfwCfgNode *)cfg_root;
		path = spec->path;
		arg = (void *)spec;

		ret = tfw_cfg_node_walk(root, path, apply_spec_to_node, arg);
		if (ret)
			return ret;
	}

	return 0;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_spec_apply);

