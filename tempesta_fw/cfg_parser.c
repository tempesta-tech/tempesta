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

#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "cfg_private_log.h"
#include "cfg_parser.h"


/* Maximum length of an attribute or node name. */
#define TFW_CFG_NAME_MAX_LEN (1 << 6)

/* Maximum length of a string literal value. */
#define TFW_CFG_STR_MAX_LEN (1 << 16)

/* Maximum length of a whole configuration file. */
#define TFW_CFG_TEXT_MAX_LEN (1 << 24)

/* FSM's debug messages are very verbose, so they are turned off by default. */
#ifdef DEBUG_CFG_FSM
#define FSM_DBG(...) DBG(__VA_ARGS__)
#else
#define FSM_DBG(...)
#endif

/* TFSM is even more verbose, it prints a message for every single character,
 * so it is turned on separately. */
#ifdef DEBUG_CFG_TFSM
#define TFSM_DBG(...) DBG(__VA_ARGS__)
#else
#define TFSM_DBG(...)
#endif

#ifndef IF_DEBUG
#ifdef DEBUG
#define IF_DEBUG if (1)
#else
#define IF_DEBUG if (0)
#endif
#endif

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - private declarations and methods
 * ------------------------------------------------------------------------
 */

/**
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
 * We have to emulate dynamic typing here, because at this level we can't
 * determine value types. For example, how should the "1" be interpreted?
 * As a number or as a boolean or as a string?
 * What if we would like to be able to specify either "cache 8192" or
 * "cache auto"? What type should the value have then?
 *
 * Such decisions are made not here, but in higher-level modules that use
 * the data in their own way. Therefore, we store all parsed instances of
 * a literal and let the higher level modules to choose the type.
 */
typedef struct TfwCfgVal {
	struct list_head siblings;

	/* A TfwCfgVal object may act as a node's value or attribute (an element
	 * of val_list or attr_list in TfwCfgNode respectively).
	 * So the field field is not NULL only when the object is an attribute.
	 * Actually this is cheating, we are using the same structure for the
	 * list and the dictionary implementation, which is not efficient.
	 * TODO: create a more efficient attribute implementation. */
	const char *attr_name;

	/* The @mask determines which parsed values are valid. */
	u8 mask;
	bool val_bool;
	int val_int;
	TfwAddr val_addr;

	/* The raw unparsed string, always available regardless of the @mask */
	char val_str[];
} TfwCfgVal;

typedef enum {
	TFW_CFG_VAL_bool  = 1 << 0,
	TFW_CFG_VAL_int   = 1 << 1,
	TFW_CFG_VAL_addr  = 1 << 2,
	TFW_CFG_VAL_MASK  = 0b111ul,
} tfw_cfg_val_mask_t;


static bool
name_is_valid(const char *str)
{
	size_t len;
	int i;
	char c;

	if (!str)
		return false;

	len = strlen(str);
	if (len == 0 || len > TFW_CFG_NAME_MAX_LEN)
		return false;

	c = str[0];
	if (!isalpha(c) && c != '_')
		return false;

	for (i = 0; i < len; ++i) {
		c = str[i];
		if (!isalnum(c) && c != '_')
			return false;
	}

	return true;
}

char *
name_alloc(const char *buf, size_t str_len)
{
	char *str;
	size_t total_len = str_len + 1;

	str = kmalloc(total_len, GFP_KERNEL);
	memcpy(str, buf, str_len);
	str[str_len] = '\0';

	return str;
}

void
name_free(const char *id)
{
	kfree(id);
}

static void
val_validate(const TfwCfgVal *val)
{
	BUG_ON(!val);
	BUG_ON(val->attr_name && !name_is_valid(val->attr_name));
	BUG_ON(val->mask & ~TFW_CFG_VAL_MASK);
	BUG_ON((val->mask & TFW_CFG_VAL_bool) && (val->val_bool & ~1ul));

	IF_DEBUG {
		size_t len;
		int i;

		len = strlen(val->val_str);
		BUG_ON(len > TFW_CFG_STR_MAX_LEN);

		for (i = 0; i < len; ++i)
			BUG_ON(!isascii(val->val_str[i]));
	}
}

static TfwCfgVal *
val_alloc(size_t str_len)
{
	size_t total_len;
	TfwCfgVal *val;

	total_len = sizeof(*val) + str_len + 1;
	val = kzalloc(total_len, GFP_KERNEL);
	BUG_ON(!val);

	INIT_LIST_HEAD(&val->siblings);

	val_validate(val);

	return val;
}

static void
val_free(TfwCfgVal *val)
{
	if (!val)
		return;

	val_validate(val);

	list_del(&val->siblings);
	name_free(val->attr_name);

	kfree(val);
}

static void
node_validate(const TfwCfgNode *node)
{
	BUG_ON(!node);

	IF_DEBUG {
		TfwCfgVal *val;
		TfwCfgVal *attr;
		TfwCfgNode *child;

		BUG_ON(node->name && !name_is_valid(node->name));

		list_for_each_entry(val, &node->val_list, siblings) {
			val_validate(val);
		}

		list_for_each_entry(attr, &node->attr_list, siblings) {
			val_validate(attr);
		}

		list_for_each_entry(child, &node->child_list, siblings) {
			node_validate(child);
		}
	}
}

static TfwCfgNode *
node_alloc(void)
{
	TfwCfgNode *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);

	INIT_LIST_HEAD(&node->siblings);
	INIT_LIST_HEAD(&node->val_list);
	INIT_LIST_HEAD(&node->attr_list);
	INIT_LIST_HEAD(&node->child_list);

	node->name = "new_node";
	node->meta.file = "";
	node->meta.src = "";

	node_validate(node);

	return node;
}

static void
node_free(TfwCfgNode *node)
{
	TfwCfgVal *val;
	TfwCfgVal *attr;
	TfwCfgVal *tmp1;
	TfwCfgNode *child;
	TfwCfgNode *tmp2;

	node_validate(node);

	list_del(&node->siblings);
	name_free(node->name);

	list_for_each_entry_safe(val, tmp1, &node->val_list, siblings) {
		val_free(val);
	}
	list_for_each_entry_safe(attr, tmp1, &node->attr_list, siblings) {
		val_free(attr);
	}
	list_for_each_entry_safe(child, tmp2, &node->child_list, siblings) {
		node_free(child);
	}

	kfree(node);
}

static void
node_set_name(TfwCfgNode *node, const char *name)
{
	node->name = name;
}

TfwCfgVal *
node_find_attr(const TfwCfgNode *node, const char *name)
{
	TfwCfgVal *attr;

	node_validate(node);
	if (!name_is_valid(name))
		return NULL;

	list_for_each_entry(attr, &node->attr_list, siblings) {
		if (!strcasecmp(name, attr->attr_name))
			return attr;
	}

	return NULL;
}

void
node_add_child(TfwCfgNode *parent, TfwCfgNode *new_child)
{
	node_validate(parent);
	node_validate(new_child);

	list_add_tail(&new_child->siblings, &parent->child_list);
}

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - public methods
 * ------------------------------------------------------------------------
 */

#define VAL_CAST(val, out_ptr, ptr_op, type)			\
({								\
	int _r = -1;						\
	if (val) {						\
		val_validate(val);				\
		if (val->mask & TFW_CFG_VAL_##type) {		\
			_r = 0;					\
			*out_ptr = ptr_op val->val_##type;	\
		}						\
	}							\
	_r;							\
})

int
tfw_cfg_val_cast_int(const TfwCfgVal *val, int *out)
{
	return VAL_CAST(val, out, , int);
}
EXPORT_SYMBOL(tfw_cfg_val_cast_int);

int
tfw_cfg_val_cast_bool(const TfwCfgVal *val, bool *out)
{
	return VAL_CAST(val, out, , bool);
}
EXPORT_SYMBOL(tfw_cfg_val_cast_bool);

int
tfw_cfg_val_cast_addr(const TfwCfgVal *val, const TfwAddr **out)
{
	return VAL_CAST(val, out, &, addr);
}
EXPORT_SYMBOL(tfw_cfg_val_cast_addr);

int
tfw_cfg_val_cast_str(const TfwCfgVal *val, const char **out)
{
	if (val) {
		val_validate(val);
		*out = val->val_str;
		return 0;
	}

	return -1;
}
EXPORT_SYMBOL(tfw_cfg_val_cast_str);

const TfwCfgVal *
tfw_cfg_val_clone(const TfwCfgVal *src)
{
	size_t len;
	TfwCfgVal *new;
	val_validate(src);

	len = strlen(src->val_str);
	new = val_alloc(len);
	memcpy(new, src, sizeof(*new));
	memcpy(new->val_str, src->val_str, len);

	return new;

}
EXPORT_SYMBOL(tfw_cfg_val_clone);


/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - value list methods
 * ------------------------------------------------------------------------
 */

const TfwCfgVal *
tfw_cfg_nval_get(const TfwCfgNode *node, int n)
{
	TfwCfgVal *val;

	node_validate(node);
	BUG_ON(n < 0);

	list_for_each_entry(val, &node->val_list, siblings) {
		if (!n)
			return val;
		--n;
	}

	return NULL;
}
EXPORT_SYMBOL(tfw_cfg_nval_get);

const TfwCfgVal *
tfw_cfg_nval_first(const TfwCfgNode *node)
{
	return list_first_entry_or_null(&node->val_list, TfwCfgVal, siblings);
}
EXPORT_SYMBOL(tfw_cfg_nval_first);

const TfwCfgVal *
tfw_cfg_nval_next(const TfwCfgNode *node, const TfwCfgVal *prev)
{
	if (prev->siblings.next == &node->val_list)
		return NULL;

	return list_entry(prev->siblings.next, TfwCfgVal, siblings);
}
EXPORT_SYMBOL(tfw_cfg_nval_next);

int
tfw_cfg_nval_count(const TfwCfgNode *node)
{
	int n = 0;
	struct list_head *pos;

	node_validate(node);

	list_for_each(pos, &node->val_list) {
		++n;
	}

	return n;
}
EXPORT_SYMBOL(tfw_cfg_nval_count);

int
tfw_cfg_nval_add(TfwCfgNode *node, const TfwCfgVal *v)
{
	TfwCfgVal *val = (TfwCfgVal *)v;

	node_validate(node);
	val_validate(val);

	list_add_tail(&val->siblings, &node->val_list);

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_nval_add);

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - attribute methods
 * ------------------------------------------------------------------------
 */

const TfwCfgVal *
tfw_cfg_nattr_get(const TfwCfgNode *node, const char *attr_name)
{
	TfwCfgVal *attr;

	node_validate(node);
	BUG_ON(!name_is_valid(attr_name));

	list_for_each_entry(attr, &node->attr_list, siblings) {
		if (!strcasecmp(attr_name, attr->attr_name))
			return attr;
	}

	return NULL;
}
EXPORT_SYMBOL(tfw_cfg_nattr_get);

void tfw_cfg_nattr_first(const TfwCfgNode *node, const char **out_name,
			 const TfwCfgVal **out_val)
{
	node_validate(node);
	BUG_ON(!out_name || !out_val);

	*out_val =  list_first_entry_or_null(&node->attr_list, TfwCfgVal, siblings);
	*out_name = (*out_val) ? (*out_val)->attr_name : NULL;
}
EXPORT_SYMBOL(tfw_cfg_nattr_first);

void tfw_cfg_nattr_next(const TfwCfgNode *node, const char **inout_name,
		        const TfwCfgVal **inout_val)
{
	const TfwCfgVal *prev, *next;

	node_validate(node);
	BUG_ON(!inout_name || !inout_val);
	BUG_ON(!(*inout_name) || !(*inout_val));
	BUG_ON(*inout_name != (*inout_val)->attr_name);

	prev = *inout_val;
	if (prev->siblings.next == &node->attr_list) {
		*inout_name = NULL;
		*inout_val = NULL;
	} else {
		next = list_entry(prev->siblings.next, TfwCfgVal, siblings);
		*inout_name = next->attr_name;
		*inout_val = next;
	}

}
EXPORT_SYMBOL(tfw_cfg_nattr_next);

int
tfw_cfg_nattr_set(TfwCfgNode *node, const char *attr_name,
		  const TfwCfgVal *v)
{
	TfwCfgVal *attr_val = (TfwCfgVal *)v;
	TfwCfgVal *existing_attr;

	node_validate(node);
	val_validate(attr_val);

	existing_attr = node_find_attr(node, attr_name);
	val_free(existing_attr);

	/* The caller should not know that we cheat with the linked list,
	 * so we take the name as an argument and set it here. */
	attr_val->attr_name = attr_name;
	list_add(&attr_val->siblings, &node->attr_list);

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_nattr_set);

/*
 * ------------------------------------------------------------------------
 *	TfwCfgNode - children node methods
 * ------------------------------------------------------------------------
 */

TfwCfgNode *
tfw_cfg_nchild_get(const TfwCfgNode *parent, const char *child_name)
{
	TfwCfgNode *child;

	node_validate(parent);
	BUG_ON(!name_is_valid(child_name));

	list_for_each_entry(child, &parent->child_list, siblings) {
		if (!strcasecmp(child_name, child->name))
			return child;
	}

	return NULL;
}
EXPORT_SYMBOL(tfw_cfg_nchild_get);

TfwCfgNode *
tfw_cfg_nchild_first(const TfwCfgNode *parent)
{
	return list_first_entry_or_null(&parent->child_list, TfwCfgNode, siblings);
}
EXPORT_SYMBOL(tfw_cfg_nchild_first);

TfwCfgNode *
tfw_cfg_nchild_next(const TfwCfgNode *parent, const TfwCfgNode *curr)
{
	if (curr->siblings.next == &parent->child_list)
		return NULL;

	return list_entry(curr->siblings.next, TfwCfgNode, siblings);
}
EXPORT_SYMBOL(tfw_cfg_nchild_next);

static void
path_validate(const char *path)
{
	BUG_ON(!path);

	IF_DEBUG {
		char c;
		while ((c = *path++)) {
			BUG_ON(!isalnum(c) && c != '_' && c != '.');
		}
	}
}

TfwCfgNode *
do_descend(TfwCfgNode *node, const char *path, bool should_create)
{
	TfwCfgNode *parent;
	char name[TFW_CFG_NAME_MAX_LEN];
	size_t name_len;

	node_validate(node);
	path_validate(path);

	while (node && *path) {
		name_len = strcspn(path, ".");
		if (!name_len)
			return NULL;

		BUG_ON(name_len >= TFW_CFG_NAME_MAX_LEN);
		memcpy(name, path, name_len);
		name[name_len] = '\0';

		parent = node;
		node = tfw_cfg_nchild_get(parent, name);
		if (!node && should_create) {
			const char *n;

			n = name_alloc(name, name_len);
			node = node_alloc();
			BUG_ON(!node || !n);

			node_set_name(node, n);
			node_add_child(parent, node);
		}
		parent = node;

		path += name_len;
		BUG_ON(*path && *path != '.');
		if (*path)
			path++;
	}

	return node;
}

TfwCfgNode *
tfw_cfg_nchild_descend(const TfwCfgNode *root, const char *path)
{
	return do_descend((TfwCfgNode *)root, path, false);
}
EXPORT_SYMBOL(tfw_cfg_nchild_descend);

TfwCfgNode *
tfw_cfg_nchild_descend_create(TfwCfgNode *root, const char *path)
{
	return do_descend(root, path, true);
}
EXPORT_SYMBOL(tfw_cfg_nchild_descend_create);

void
tfw_cfg_node_free( TfwCfgNode *node)
{
	node_free(node);
}
EXPORT_SYMBOL(tfw_cfg_node_free);

const char *
tfw_cfg_nname_get(const TfwCfgNode *node)
{
	return node->name;
}
EXPORT_SYMBOL(tfw_cfg_nname_get);

bool
tfw_cfg_nname_eq(const TfwCfgNode *node, const char *name)
{
	return !strcasecmp(node->name, name);
}
EXPORT_SYMBOL(tfw_cfg_nname_eq);

/*
 * ------------------------------------------------------------------------
 *	Configuration Parser - helper routines for parsing literals
 * ------------------------------------------------------------------------
 */

/**
 * Detect integer base and strip 0x and 0b prefixes from the string.
 *
 * The custom function is written because the kstrtox() treats leading zeros as
 * the octal base. That may cause an unexpected effect when you specify "010" in
 * the configuration and get 8 instead of 10. We want to avoid that.
 *
 * As a bonus, we have the "0b" support here. This may be handy for specifying
 * some masks and bit strings in the configuration.
 */
static int
detect_base(const char **pos, size_t *len)
{
	const char *p = *pos;
	size_t l = *len;

	if (!l)
		return 0;

	if (l > 2 && p[0] == '0' && isalpha(p[1])) {
		char c = tolower(p[1]);

		(*pos) += 2;
		(*len) -= 2;

		if (c == 'x')
			return 16;
		else if (c == 'b')
			return 2;
		else
			return 0;
	}

	return 10;
}

int
tfw_cfg_parse_int(const char *str, int *out_int)
{
	size_t len = strlen(str);
	int base = detect_base(&str, &len);

	*out_int = 0;

	if (!base)
		return -EINVAL;

	return kstrtoint(str, base, out_int);
}
EXPORT_SYMBOL(tfw_cfg_parse_int);

int
tfw_cfg_parse_bool(const char *str, bool *out_bool)
{
	bool is_true  = !strcasecmp(str, "1")
	              || !strcasecmp(str, "on")
	              || !strcasecmp(str, "yes")
	              || !strcasecmp(str, "true")
	              || !strcasecmp(str, "enable");

	bool is_false  = !strcasecmp(str, "0")
	               || !strcasecmp(str, "off")
	               || !strcasecmp(str, "no")
	               || !strcasecmp(str, "false")
	               || !strcasecmp(str, "disable");

	*out_bool = is_true;
	BUG_ON(is_true && is_false);

	return (!is_true && !is_false) ? -EINVAL : 0;
}
EXPORT_SYMBOL(tfw_cfg_parse_bool);

static int
parse_addr_ipv4(const char *pos, struct sockaddr_in *addr)
{
	unsigned long addr_val = 0;
	int port = 0;

	int r;
	int octet_val;
	int octet_idx;
	char octet_str[4];
	size_t octet_str_len;

	if (*pos == ':')
		goto port;

	/* Parse 4 decimal octets separated by dots. */
	for (octet_idx = 0; octet_idx < 4; ++octet_idx) {
		octet_str_len = strspn(pos, "1234567890");
		if (!octet_str_len || octet_str_len > 3)
			return -EINVAL;

		memcpy(octet_str, pos, octet_str_len);
		octet_str[octet_str_len] = '\0';

		r = kstrtoint(octet_str, 10, &octet_val);
		if (r || octet_val < 0 || octet_val > 255)
			return -EINVAL;

		addr_val = (addr_val << 8) | octet_val;
		pos += octet_str_len;

		if (octet_idx < 3 && *pos++ != '.')
			return -EINVAL;
	}

port:
	port = 0;
	if (*pos) {
		if (*pos++ != ':')
			return -EINVAL;

		r = kstrtoint(pos, 10, &port);
		if (r || port < 0 || port > 65535)
			return -EINVAL;
	}

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(addr_val);
	addr->sin_port = htons(port);

	return 0;
}

static int
parse_addr_ipv6(const char *pos, struct sockaddr_in6 *addr)
{
#define XD(x) ((x >= 'a') ? 10 + x - 'a' : x - '0')

	int words[9] = { -1, -1, -1, -1, -1, -1, -1, -1, -1 };
	int a, hole = -1, i = 0, port = -1, ipv4_mapped = 0;

	memset(addr, 0, sizeof(*addr));

	for ( ; *pos; ++pos) {
		if (i > 7 && !(i == 8 && port == 1))
			return -EINVAL;

		if (*pos == '[') {
			port = 0;
		}
		else if (*pos == ':') {
			if (*(pos + 1) == ':') {
				/*
				 * Leave current (if empty) or next (otherwise)
				 * word as a hole.
				 */
				++pos;
				hole = (words[i] != -1) ? ++i : i;
			} else if (words[i] == -1)
				return -EINVAL;

			/* Store port in the last word. */
			i = (port == 1) ? 8 : i + 1;
		}
		else if (*pos == '.') {
			++i;
			if (ipv4_mapped)
				continue;
			if (words[0] != -1 || words[1] != 0xFFFF
			   || words[2] == -1 || i != 3 || hole != 0)
				return -EINVAL;
			/*
			 * IPv4 mapped address.
			 * Recalculate the first 2 hexademical octets from to
			 * 1 decimal octet.
			 */
			addr->sin6_family = AF_INET;
			words[0] = ((words[2] & 0xF000) >> 12) * 1000
				   + ((words[2] & 0x0F00) >> 8) * 100
				   + ((words[2] & 0x00F0) >> 4) * 10
				   + (words[2] & 0x000F);
			if (words[0] > 255)
				return -EINVAL;
			ipv4_mapped = 1;
			i = 1;
			words[1] = words[2] = -1;
		}
		else if (isxdigit(*pos)) {
			words[i] = words[i] == -1 ? 0 : words[i];
			if (ipv4_mapped || port == 1) {
				if (!isdigit(*pos))
					return -EINVAL;
				words[i] = words[i] * 10 + *pos - '0';
				if (port) {
					if (words[i] > 0xFFFF)
						return -EINVAL;
				}
				else if (ipv4_mapped && words[i] > 255) {
					return -EINVAL;
				}
			} else {
				words[i] = (words[i] << 4) | XD(tolower(*pos));
				if (words[i] > 0xFFFF)
					return -EINVAL;
			}
		}
		else if (*pos == ']') {
			port = 1;
		}
		else {
			return -EINVAL;
		}
	}

	/* Some sanity checks. */
	if (!port || (port != -1 && words[8] <= 0)
	    || (ipv4_mapped && hole == -1)
	    || (ipv4_mapped && port == -1 && i != 3)
	    || (port == 1 && i != 8)
	    || (port == -1 && i < 7 && hole == -1))
		return -EINVAL;

	/* Copy parsed address. */
	if (ipv4_mapped) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		for (i = 0; i < 4; ++i)
			addr4->sin_addr.s_addr |= words[i] << (3 - i) * 8;
	} else {
		for (i = a = 7; i >= 0 && a >= 0; ) {
			if (words[i] == -1) {
				if (i > hole)
					--i;
				else
					if (a-- == i && i)
						--i;
			} else
				addr->sin6_addr.s6_addr16[a--]
					= htons(words[i--]);
		}
	}

	/* Set port. */
	if (port == -1) {
		addr->sin6_port = 0;
	} else {
		addr->sin6_port = htons(words[8]);
	}

	addr->sin6_family = AF_INET6;

	return 0;
#undef XD
}

/**
 * Parse IPv4 and IPv6 addresses with optional port.
 * See RFC5952.
 */
int
tfw_cfg_parse_addr(const char *str, TfwAddr *addr)
{
	memset(addr, 0, sizeof(*addr));

	/* The IPv6 address must be enclosed into square brackets,
	 * or else we can't distinguish it from the port. */
	if (str[0] == '[' && !strcspn(str, "1234567890ABCDEFabcdef:[]"))
		return parse_addr_ipv6(str, &addr->v6);

	if (!strcspn(str, "1234567890.:"))
		return parse_addr_ipv4(str, &addr->v4);

	return -1;
}
EXPORT_SYMBOL(tfw_cfg_parse_addr);

/*
 * ------------------------------------------------------------------------
 *	Configuration parser - tokenizer and parser FSMs
 * ------------------------------------------------------------------------
 */

typedef enum {
	TOKEN_NA = 0,
	TOKEN_LBRACE,
	TOKEN_RBRACE,
	TOKEN_EQSIGN,
	TOKEN_SEMICOLON,
	TOKEN_LITERAL,
	_TOKEN_COUNT,
} token_t;

typedef struct {
	const char *in;	   /* The whole input buffer. */

	/* Temporay variables, changed by FSMs during parsing. */

	const void *fsm_s;   /* Pointer to label (GCC extension). */
	const char *fsm_ss;  /* Label name as string (for debugging). */

	TfwCfgNode *n;	 /* Currently processed node. */
	const char *pos; /* Current position in the @in buffer. */

	const char *lit; /* Literal value (NULL when token != TOKEN_LITERAL). */
	const char *prev_lit;

	int lit_len;	 /* Length of @lit (the @lit is not terminated). */
	int prev_lit_len;

	token_t t;	 /* Currently processed token. */
	token_t prev_t;

	char c;		 /* Currently processed character. */
	char prev_c;

} ParserState;


/* Macros common for both TFSM and PFSM. */

#define FSM_STATE(name) 		\
	FSM_DBG("fsm: implicit exit from: %s\n", ps->fsm_ss); \
	BUG();				\
name:					\
	if (ps->fsm_s != &&name) {	\
		FSM_DBG("fsm turn: %s -> %s\n", ps->fsm_ss, #name); \
		ps->fsm_s = &&name;	\
		ps->fsm_ss = #name;	\
	}

#define FSM_JMP(to_state) goto to_state

#define FSM_COND_LAMBDA(cond, ...)	\
do {					\
	if (cond) {			\
		__VA_ARGS__;		\
	}				\
} while (0)				\

#define FSM_COND_JMP(cond, to_state) \
	FSM_COND_LAMBDA(cond, FSM_JMP(to_state))

/* Macros specific to TFSM. */

#define TFSM_MOVE(to_state)	\
do {				\
	ps->prev_c = ps->c;	\
	ps->c = *(++ps->pos);	\
	TFSM_DBG("tfsm move: '%c' -> '%c'\n", ps->prev_c, ps->c); \
	FSM_JMP(to_state);	\
} while (0)

#define TFSM_MOVE_EXIT(token_type)	\
do {					\
	ps->t = token_type;		\
	TFSM_MOVE(TS_EXIT);		\
} while (0)

#define TFSM_JMP_EXIT(token_type)	\
do {					\
	ps->t = token_type;		\
	FSM_JMP(TS_EXIT);		\
} while (0)

#define TFSM_SKIP() TFSM_MOVE(*ps->fsm_s);

#define TFSM_COND_SKIP(cond) \
	FSM_COND_LAMBDA(cond, TFSM_SKIP())

#define TFSM_COND_MOVE_EXIT(cond, token_type) \
	FSM_COND_LAMBDA(cond, TFSM_MOVE_EXIT(token_type))

#define TFSM_COND_JMP_EXIT(cond, token_type) \
	FSM_COND_LAMBDA(cond, TFSM_JMP_EXIT(token_type))

#define TFSM_COND_MOVE(cond, to_state) \
	FSM_COND_LAMBDA(cond, TFSM_MOVE(to_state))

/* Macros specific to PFSM. */

#define PFSM_MOVE(to_state)					\
do {								\
	read_next_token(ps);					\
	FSM_DBG("pfsm move: %d (\"%.*s\") -> %d (\"%.*s\")", 	\
		ps->prev_t, ps->prev_lit_len, ps->prev_lit,  	\
		ps->t, ps->lit_len, ps->lit); 			\
	FSM_COND_JMP(!ps->t, PS_ERROR);				\
	FSM_JMP(to_state);					\
} while (0)

#define PFSM_COND_MOVE(cond, to_state) \
	FSM_COND_LAMBDA(cond, PFSM_MOVE(to_state))


static token_t
read_next_token(ParserState *ps)
{
	ps->prev_t = ps->t;
	ps->prev_lit = ps->lit;
	ps->prev_lit_len = ps->lit_len;
	ps->lit = NULL;
	ps->lit_len = 0;
	ps->t = TOKEN_NA;
	ps->c = *ps->pos;

	FSM_DBG("tfsm start, char: '%c', pos: %.20s\n", ps->c, ps->pos);

	FSM_JMP(TS_START_NEW_TOKEN);

	FSM_STATE(TS_START_NEW_TOKEN) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* A backslash means that the next character definitely has
		 * no special meaning and thus starts a literal. */
		TFSM_COND_MOVE(ps->c == '\\', TS_LITERAL_FIRST_CHAR);

		/* Eat non-escaped spaces. */
		TFSM_COND_SKIP(isspace(ps->c));

		/* A character next to a double quote is the first character
		 * of a literal. The quote itself is not included to the
		 * literal's value. */
		TFSM_COND_MOVE(ps->c == '"', TS_QUOTED_LITERAL_FIRST_CHAR);

		/* A comment is starts with '#' (and ends with a like break) */
		TFSM_COND_MOVE(ps->c == '#', TS_COMMENT);

		/* Self-meaning single-token characters. */
		TFSM_COND_MOVE_EXIT(ps->c == '{', TOKEN_LBRACE);
		TFSM_COND_MOVE_EXIT(ps->c == '}', TOKEN_RBRACE);
		TFSM_COND_MOVE_EXIT(ps->c == '=', TOKEN_EQSIGN);
		TFSM_COND_MOVE_EXIT(ps->c == ';', TOKEN_SEMICOLON);

		/* Everything else is not a special character and therefore
		 * it starts a literal. */
		FSM_JMP(TS_LITERAL_FIRST_CHAR);
	}

	FSM_STATE(TS_COMMENT) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* Eat everything until a new line is reached.
		 * The line break cannot be escaped within a comment. */
		TFSM_COND_SKIP(ps->c != '\n');
		TFSM_MOVE(TS_START_NEW_TOKEN);
	}

	FSM_STATE(TS_LITERAL_FIRST_CHAR) {
		ps->lit = ps->pos;
		FSM_JMP(TS_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_LITERAL_ACCUMULATE) {
		/* EOF terminates a literal if there is any chars saved. */
		TFSM_COND_JMP_EXIT(!ps->c && !ps->lit_len, TOKEN_NA);
		TFSM_COND_JMP_EXIT(!ps->c && ps->lit_len, TOKEN_LITERAL);

		/* Non-escaped special characters terminate the literal. */
		if (ps->prev_c != '\\') {
			TFSM_COND_JMP_EXIT(isspace(ps->c), TOKEN_LITERAL);
			TFSM_COND_JMP_EXIT(ps->c == '"', TOKEN_LITERAL);
			TFSM_COND_JMP_EXIT(ps->c == '#', TOKEN_LITERAL);
			TFSM_COND_JMP_EXIT(ps->c == '{', TOKEN_LITERAL);
			TFSM_COND_JMP_EXIT(ps->c == '}', TOKEN_LITERAL);
			TFSM_COND_JMP_EXIT(ps->c == ';', TOKEN_LITERAL);
			TFSM_COND_JMP_EXIT(ps->c == '=', TOKEN_LITERAL);
		}

		/* Accumulate everything else. */
		++ps->lit_len;
		TFSM_SKIP();
	}

	FSM_STATE(TS_QUOTED_LITERAL_FIRST_CHAR) {
		ps->lit = ps->pos;
		FSM_JMP(TS_QUOTED_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_QUOTED_LITERAL_ACCUMULATE) {
		/* EOF means there is no matching double quote. */
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* Only a non-escaped quote terminates the literal. */
		TFSM_COND_MOVE_EXIT(ps->c == '"' && ps->prev_c != '\\', TOKEN_LITERAL);

		/* Everything else is accumulated (including line breaks). */
		++ps->lit_len;
		TFSM_SKIP();
	}

	FSM_STATE(TS_EXIT) {
		FSM_DBG("tfsm exit: t: %d, lit: %.*s\n", ps->t, ps->lit_len, ps->lit);
		return ps->t;
	}
}

static TfwCfgVal *
parse_literal(const char *literal, size_t len)
{
	TfwCfgVal *v = val_alloc(len);
	const char *s = v->val_str;

	memcpy(v->val_str, literal, len);

	v->mask |= TFW_CFG_VAL_int  * !tfw_cfg_parse_int(s, &v->val_int);
	v->mask |= TFW_CFG_VAL_bool * !tfw_cfg_parse_bool(s, &v->val_bool);
	v->mask |= TFW_CFG_VAL_addr * !tfw_cfg_parse_addr(s, &v->val_addr);

	return v;
}

TfwCfgNode *
parse_node(ParserState *ps)
{
	if (!ps->t)
		PFSM_MOVE(PS_START_NEW_NODE);

	FSM_JMP(PS_START_NEW_NODE); /* Should not read a token on recursion. */

	FSM_STATE(PS_ERROR) {
		const char *start = max((ps->pos - 80), ps->in);
		int len = ps->pos - start;
		ERR("syntax error: \n%.*s  <-- error here\n", len, start);

		node_free(ps->n);
		ps->n = NULL;

		return NULL;
	}

	FSM_STATE(PS_START_NEW_NODE) {
		ps->n = node_alloc();
		FSM_JMP(PS_NAME);
	}

	FSM_STATE(PS_NAME) {
		const char *name = name_alloc(ps->lit, ps->lit_len);

		FSM_DBG("set node name: %s\n", name);
		node_set_name(ps->n, name);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_VAL_OR_ATTR) {
		FSM_COND_JMP(ps->t == TOKEN_SEMICOLON, PS_FINISH_NODE);
		PFSM_COND_MOVE(ps->t == TOKEN_LBRACE, PS_CHILDREN);
		PFSM_COND_MOVE(ps->t == TOKEN_LITERAL, PS_MAYBE_EQSIGN);
	}

	FSM_STATE(PS_MAYBE_EQSIGN) {
		FSM_COND_JMP(ps->t == TOKEN_EQSIGN, PS_STORE_ATTR_PREV);
		FSM_JMP(PS_STORE_VAL_PREV);
	}

	FSM_STATE(PS_STORE_VAL_PREV) {
		TfwCfgVal *v = parse_literal(ps->prev_lit, ps->prev_lit_len);

		FSM_DBG("add value: %s (type mask: %#x)\n", v->val_str, v->mask);
		tfw_cfg_nval_add(ps->n, v);

		FSM_JMP(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_STORE_ATTR_PREV) {
		const char *name;
		TfwCfgVal *val;

		name = name_alloc(ps->prev_lit, ps->prev_lit_len);

		/* Current position is the '=' sign, so skip it. */
		read_next_token(ps);

		val = parse_literal(ps->lit, ps->lit_len);

		FSM_DBG("set attr: %s = %s\n", name, val->val_str);
		tfw_cfg_nattr_set(ps->n, name, val);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_CHILDREN) {
		FSM_COND_JMP(ps->t == TOKEN_RBRACE, PS_FINISH_NODE);
		FSM_COND_JMP(ps->t == TOKEN_LITERAL, PS_PARSE_CHILD_RECURSIVELY);
		FSM_JMP(PS_ERROR);
	}

	FSM_STATE(PS_PARSE_CHILD_RECURSIVELY) {
		TfwCfgNode *parent, *child;

		FSM_DBG("parse child: %.*s\n", ps->lit_len, ps->lit);

		parent = ps->n;
		child = parse_node(ps);
		ps->n = parent;

		if (child)
			node_add_child(parent, child);

		FSM_DBG("done child: %s\n", child->name);
		FSM_DBG("continue parent: %s\n", ps->n->name);

		FSM_JMP(PS_CHILDREN);
	}

	FSM_STATE(PS_FINISH_NODE) {
		read_next_token(ps); /* Eat ';'. */

		return ps->n;
	}
}

TfwCfgNode *
tfw_cfg_parse_single_node(const char *cfg_text)
{
	ParserState ps = {
		.in = cfg_text,
		.pos = cfg_text,
	};

	return parse_node(&ps);
}
EXPORT_SYMBOL(tfw_cfg_parse_single_node);

TfwCfgNode *
tfw_cfg_parse(const char *cfg_text)
{
	ParserState ps = {
		.in = cfg_text,
		.pos = cfg_text,
	};

	TfwCfgNode *root, *node;

	root = node_alloc();
	node_set_name(root, name_alloc("root", 4));

	do {
		node = parse_node(&ps);
		if (node)
			node_add_child(root, node);
	} while (node && ps.t);

	return root;
}
EXPORT_SYMBOL(tfw_cfg_parse);

