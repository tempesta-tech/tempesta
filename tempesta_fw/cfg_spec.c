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

#include "cfg_spec.h"

static void
handle_val_fields(const TfwCfgSpec *spec, const TfwCfgVal *val)
{
#define DO_SET(type) \
	if (spec->set_##type) \
		tfw_cfg_val_cast_##type(val, spec->set_##type)

	/* The dynamic-to-static conversion is always painful. We can't avoid
	 * that (since the configuration tree is dynamically-typed by nature),
	 * so we use such macros here to reduce amount of duplicate code. */
	DO_SET(int);
	DO_SET(bool);
	DO_SET(str);
	DO_SET(addr);

#undef DO_SET

#define DO_CB(type) 						\
	if (spec->call_##type) { 				\
		tfw_cfg_val_type_##type _val = 0;		\
		if (!tfw_cfg_val_cast_##type(val, &_val))	\
			spec->call_##type(_val);		\
	}

	DO_CB(int);
	DO_CB(bool);
	DO_CB(str);
	DO_CB(addr);

#undef DO_CB
}


static void
merge_in_defaults(TfwCfgNode *dest_node, const TfwCfgNode *default_node)
{
	const TfwCfgVal *val, *copied_val;
	const char *name;
	int default_val_nth;
	int node_val_count;
	int r;

	/* Just a sanity check. Actually we don't need the name. */
	name = tfw_cfg_nname_get(default_node);
	BUG_ON(!tfw_cfg_nname_eq(dest_node, name));

	/* Add only tail default values to the destination node. */
	node_val_count = tfw_cfg_nval_count(dest_node);
	default_val_nth = 0;
	TFW_CFG_NVAL_EACH(default_node, val) {
		++default_val_nth;


		if (default_val_nth > node_val_count) {
			copied_val = tfw_cfg_val_clone(val);
			BUG_ON(!copied_val);

			r = tfw_cfg_nval_add(dest_node, copied_val);
			BUG_ON(r);
		}
	}

	/* Set only attributes that are not set in the destination nodes. */
	TFW_CFG_NATTR_EACH(default_node, name, val) {
		if (!tfw_cfg_nattr_get(dest_node, name)) {
			copied_val = tfw_cfg_val_clone(val);
			BUG_ON(!copied_val);

			r = tfw_cfg_nattr_set(dest_node, name, val);
			BUG_ON(r);
		}
	}

	/* No support for merging subtrees yet. */
	BUG_ON(tfw_cfg_nchild_first(default_node));
}

static void
handle_node_fields(const TfwCfgSpec *spec, TfwCfgNode *node)
{
	if (spec->deflt) {
		TfwCfgNode *default_node;

		default_node = tfw_cfg_parse_single_node(spec->deflt);
		BUG_ON(!default_node);

		merge_in_defaults(node, default_node);
		tfw_cfg_node_free(default_node);
	}

	if (spec->call_node)
		spec->call_node(node);
}

static void
apply_single_spec_item(const TfwCfgSpec *spec, TfwCfgNode *node)
{
	const TfwCfgVal *val;

	handle_node_fields(spec, node);

	if (spec->attr) {
		val = tfw_cfg_nattr_get(node, spec->attr);
		handle_val_fields(spec, val);
	}
	else if (spec->val_each) {
		TFW_CFG_NVAL_EACH(node, val) {
			handle_val_fields(spec, val);
		}
	}
	else {
		val = tfw_cfg_nval_get(node, spec->val_pos);
		handle_val_fields(spec, val);
	}
}


#define PATH_BUF_SIZE 255

static void
apply_spec_recursively(const TfwCfgSpec spec_arr[], TfwCfgNode *node, char *path)
{
	char *dot;
	const TfwCfgSpec *spec;
	TfwCfgNode *child;

	/* Push current node to the path. */
	if (path[0])
		strlcat(path, ".", PATH_BUF_SIZE);
	strlcat(path, tfw_cfg_nname_get(node), PATH_BUF_SIZE);

	/* Apply the spec rules to the current node. */
	for (spec = spec_arr; spec->path; ++spec) {
		if (!strcasecmp(path, spec->path)) {
			apply_single_spec_item(spec, node);
		}
	}

	/* Apply to all children recursively. */
	TFW_CFG_NCHILD_EACH(node, child) {
		apply_spec_recursively(spec_arr, child, path);
	}

	/* Pop current node from the path. */
	dot = strrchr(path, '.');
	if (dot)
		*dot = '\0';
	else
		path[0] = '\0';
}

static void
create_default_nodes(const TfwCfgSpec spec_arr[], TfwCfgNode *root)
{
	TfwCfgNode *child;
	const TfwCfgSpec *spec;

	for (spec = spec_arr; spec->path; ++spec) {
		child = tfw_cfg_nchild_descend(root, spec->path);

		if (!child && spec->deflt) {
			child = tfw_cfg_nchild_descend_create(root, spec->path);
			BUG_ON(!child);
		}
	}
}

int
tfw_cfg_spec_apply(const TfwCfgSpec spec_arr[], TfwCfgNode *node)
{
	TfwCfgNode *child;

	char path_buf[PATH_BUF_SIZE + 1];
	path_buf[0] = '\0';

	create_default_nodes(spec_arr, node);

	TFW_CFG_NCHILD_EACH(node, child) {
		apply_spec_recursively(spec_arr, child, path_buf);
	}

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_spec_apply);
