/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "tempesta_fw.h"
#include "tfw_tfwcfg.h"
#include "str.h"

/*
 * Helper function that converts a constant value (enum) to a string
 * that it corresponds to. Also there's conversion from a string to
 * a corresponding constant. Currenty that's done via TfwCfgEnum and
 * tfw_cfg_map_enum() function.
 */
static const char *
tfw_enum_string(const char * const * enum_string, int enum_max, int enum_val)
{
	if ((enum_val < 0) || (enum_val >= enum_max))
		return enum_string[enum_max];
	if (enum_string[enum_val])
		return enum_string[enum_val];
	return enum_string[enum_max];
}

/* Mappings and functions for configuration directives (statements). */
static const TfwCfgEnum const __read_mostly __tfwcfg_stmt_enum[] = {
	{ "cache_bypass",	TFW_D_CACHE_BYPASS },
	{ "cache_fulfill",	TFW_D_CACHE_FULFILL },
	{}
};
static const char * const __read_mostly __tfwcfg_enum_stmt[] = {
	[0 ... _TFW_D_COUNT]	= NULL,
	[TFW_D_CACHE_BYPASS]	= "cache_bypass",
	[TFW_D_CACHE_FULFILL]	= "cache_fulfill",
	[_TFW_D_COUNT]		= "UNKNOWN",
};
const char *
tfw_stmt_string(tfw_stmt_t stmt)
{
	return tfw_enum_string(__tfwcfg_enum_stmt, _TFW_D_COUNT, stmt);
}

/* Mappings for match operators. */
static const TfwCfgEnum const __read_mostly tfwcfg_match_enum[] = {
	{ "*",		TFW_HTTP_MATCH_O_WILDCARD },
	{ "eq",		TFW_HTTP_MATCH_O_EQ },
	{ "prefix",	TFW_HTTP_MATCH_O_PREFIX },
	{ "suffix",	TFW_HTTP_MATCH_O_SUFFIX },
	{}
};

/*
 * All 'location' directives are put into a fixed size array.
 * Duplicate directives are not allowed.
 */
#define TFW_LOCATION_ARRAY_SZ	(64)

static TfwCfgLocation	*tfwcfg_location;
static unsigned int	tfwcfg_location_sz;	/* Current size. */
static unsigned int	tfwcfg_location_max;	/* Maximum size. */

/*
 * All cache action directives are put into a fixed size array.
 * The directives are deduplicated when put into the array.
 * Individual directives are linked to from lists of cache action
 * directives for specific location sections.
 */
#define TFW_CAMATCH_ARRAY_SZ	(64)

static TfwCfgCacheMatch	*tfwcfg_camatch;
static unsigned int	tfwcfg_camatch_sz;	/* Current size. */
static unsigned int	tfwcfg_camatch_max;	/* Maximum size. */

/*
 * Default location is a wildcard location. It matches any URI.
 * It may (or may not) contain a set of cache matching directives.
 */
static TfwCfgCacheMatch *tfwcfg_camatch_dflt[TFW_CAMATCH_ARRAY_SZ];

static TfwCfgLocation tfwcfg_location_dflt = {
	.op = TFW_HTTP_MATCH_O_WILDCARD,
	.arg = "*",
	.len = 1,
	.cam = tfwcfg_camatch_dflt,
	.cam_sz = 0,
	.cam_max = TFW_CAMATCH_ARRAY_SZ
};

/*
 * Matching functions for match operators. A TfwStr{} is compared
 * with a plain C string according to a specified match operator.
 * The functions are generic.
 */
static bool
__tfwcfg_match_wildcard(tfw_match_t op, const char *cstr, int len, TfwStr *arg)
{
	return ((op == TFW_HTTP_MATCH_O_WILDCARD)
		&& (len == 1) && (*cstr == '*'));
}

static bool
__tfwcfg_match_suffix(tfw_match_t op, const char *cstr, int len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr_off(arg, arg->len - len, cstr, len, flags);
}

static bool
__tfwcfg_match_eq(tfw_match_t op, const char *cstr, int len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr(arg, cstr, len, flags);
}

static bool
__tfwcfg_match_prefix(tfw_match_t op, const char *cstr, int len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr(arg, cstr, len, flags);
}

typedef bool (*__tfwcfg_match_fn)(tfw_match_t, const char *, int, TfwStr *);

static const __tfwcfg_match_fn const __read_mostly __tfwcfg_match_fn_tbl[] = {
	[0 ... _TFW_HTTP_MATCH_O_COUNT] = NULL,
	[TFW_HTTP_MATCH_O_WILDCARD]	= __tfwcfg_match_wildcard,
	[TFW_HTTP_MATCH_O_EQ]		= __tfwcfg_match_eq,
	[TFW_HTTP_MATCH_O_PREFIX]	= __tfwcfg_match_prefix,
	[TFW_HTTP_MATCH_O_SUFFIX]	= __tfwcfg_match_suffix,
};

/*
 * Find a matching cache action directive. Strings are compared
 * according to the match operator in the directive. A pointer
 * to the matching TfwCfgCacheMatch structure is returned if
 * the match is found. Null is returned if there's no match.
 */
static bool
__tfw_camatch_match(TfwCfgCacheMatch *cam, TfwStr *arg)
{
	__tfwcfg_match_fn match_fn;

	match_fn = __tfwcfg_match_fn_tbl[cam->op];
	BUG_ON(!match_fn);

	return match_fn(cam->op, cam->arg, cam->len, arg);
}

TfwCfgCacheMatch *
tfw_camatch_match(TfwCfgLocation *loc, TfwStr *arg)
{
	int i;

	if (!loc || !loc->cam_sz)
		return NULL;

	for (i = 0; i < loc->cam_sz; ++i) {
		TfwCfgCacheMatch *cam = loc->cam[i];
		if (__tfw_camatch_match(cam, arg))
			return cam;
	}
	return NULL;
}

/*
 * Find a maching location directive. Strings are compared according
 * to the match operator in the directive. A pointer to the matching
 * TfwCfgLocation structure is returned if the match is found.
 * A pointer to the default location structure is returned if there's
 * no match.
 */
static bool
__tfw_location_match(TfwCfgLocation *loc, TfwStr *arg)
{
	__tfwcfg_match_fn match_fn;

	match_fn = __tfwcfg_match_fn_tbl[loc->op];
	BUG_ON(!match_fn);

	return match_fn(loc->op, loc->arg, loc->len, arg);
}

TfwCfgLocation *
tfw_location_match(TfwStr *arg)
{
	int i;

	for (i = 0; i < tfwcfg_location_sz; ++i) {
		TfwCfgLocation *loc = &tfwcfg_location[i];
		if (__tfw_location_match(loc, arg))
			return loc;
	}
	if (tfwcfg_location_dflt.cam_sz)
		return &tfwcfg_location_dflt;

	return NULL;
}

/*
 * Configuration processing.
 */

/*
 * Pointer to the current location structure.
 * The pointer is shared among several functions below.
 */
static TfwCfgLocation *tfwcfg_this_location;

/*
 * Find a cache action directive entry. The entry is looked up
 * in the array that holds all cache action directives from all
 * location sections.
 */
static TfwCfgCacheMatch *
tfwcfg_camatch_lookup(tfw_stmt_t stmt, tfw_match_t op, const char *arg, int len)
{
	int i;

	for (i = 0; i < tfwcfg_camatch_sz; ++i) {
		TfwCfgCacheMatch *cam = &tfwcfg_camatch[i];
		if ((cam->stmt == stmt) && (cam->op == op) && (cam->len == len)
		    && !strncasecmp(cam->arg, arg, len))
			return cam;
	}

	return NULL;
}

/*
 * Create and initialize a new cache action entry. The entry is placed
 * in the array for all cache action entries from all location sections.
 */
static TfwCfgCacheMatch *
tfwcfg_camatch_new(tfw_stmt_t stmt, tfw_match_t op, const char *arg, int len)
{
	char *argmem;
	TfwCfgCacheMatch *cam;

	if (tfwcfg_camatch_sz == tfwcfg_camatch_max)
		return NULL;

	if ((argmem = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return NULL;

	cam = &tfwcfg_camatch[tfwcfg_camatch_sz++];
	cam->stmt = stmt;
	cam->op = op;
	cam->arg = argmem;
	cam->len = len;
	memcpy((void *)cam->arg, (void *)arg, len + 1);

	return cam;
}

/*
 * Add a new cache action entry to the given location structure.
 * The entry is added as a pointer into the array for all cache
 * action entries.
 */
static TfwCfgCacheMatch *
tfwcfg_camatch_add(TfwCfgLocation *loc, TfwCfgCacheMatch *cam)
{
	if (loc->cam_sz == loc->cam_max)
		return NULL;
	loc->cam[loc->cam_sz++] = cam;
	return cam;
}

/*
 * Process a cache action directive. The directive is added to the
 * current location structure. Duplicate directives are ignored but
 * a warning is produced in that case. if a directive lists several
 * strings to match, then an identical directive is added for each
 * string that is listed.
 */
static int
tfwcfg_handle_camatch(TfwCfgSpec *cs, TfwCfgEntry *ce, tfw_stmt_t stmt)
{
	int i, ret, in_len;
	tfw_match_t op;
	const char *in_op, *in_arg;

	BUG_ON(!tfwcfg_this_location);
	BUG_ON((stmt != TFW_D_CACHE_BYPASS) && (stmt != TFW_D_CACHE_FULFILL));

	if (ce->attr_n || (ce->val_n < 2))
		return -EINVAL;

	in_op = ce->vals[0];	/* Match operator. */

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfwcfg_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR("Unknown match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* Add each match string in the directive to the array.*/
	for (i = 1; i < ce->val_n; ++i) {
		TfwCfgCacheMatch *cam;

		in_arg = ce->vals[i];
		in_len = strlen(in_arg);

		/* Get the cache action entry. */
		cam = tfwcfg_camatch_lookup(stmt, op, in_arg, in_len);
		if (cam) {
			TFW_WARN("%s: Duplicate entry: '%s %s %s'\n",
				 cs->name, cs->name, in_op, in_arg);
			continue;
		}
		cam = tfwcfg_camatch_new(stmt, op, in_arg, in_len);
		if (!cam)
			return -ENOMEM;
		/* Link the cache action entry with the location entry. */
		if (!tfwcfg_camatch_add(tfwcfg_this_location, cam))
			return -ENOENT;
	}

        return 0;
}

/*
 * The configuration parser has recognized the cache action directive
 * already, so there's no need to spend cycles and convert it again
 * from the string to the enum value. The functions below are for
 * each directive inside the location section, and for each directive
 * outside of any location section.
 */
static int
tfwcfg_handle_in_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfwcfg_handle_camatch(cs, ce, TFW_D_CACHE_FULFILL);
}

static int
tfwcfg_handle_in_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfwcfg_handle_camatch(cs, ce, TFW_D_CACHE_BYPASS);
}

static int
tfwcfg_handle_out_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfwcfg_location_dflt;
	return tfwcfg_handle_camatch(cs, ce, TFW_D_CACHE_FULFILL);
}

static int
tfwcfg_handle_out_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfwcfg_location_dflt;
	return tfwcfg_handle_camatch(cs, ce, TFW_D_CACHE_BYPASS);
}

/*
 * Find a location directive entry. The entry is looked up
 * in the array that holds all location directives.
 */
static TfwCfgLocation *
tfwcfg_location_lookup(tfw_match_t op, const char *arg, int len)
{
	int i;

	for (i = 0; i < tfwcfg_location_sz; ++i) {
		TfwCfgLocation *loc = &tfwcfg_location[i];
		if ((loc->op == op) && (loc->len == len)
		    && !strncasecmp(loc->arg, arg, len))
			return loc;
	}

	return NULL;
}

/*
 * Create and initialize a new entry for a location directive.
 * The entry is placed in the array that holds all location directives.
 */
static TfwCfgLocation *
tfwcfg_location_new(tfw_match_t op, const char *arg, int len)
{
	char *argmem;
	TfwCfgLocation *loc;
	TfwCfgCacheMatch **cam;
	size_t size = sizeof(TfwCfgCacheMatch *) * TFW_CAMATCH_ARRAY_SZ;

	if (tfwcfg_location_sz == tfwcfg_location_max)
		return NULL;

	if ((argmem = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return NULL;
	if ((cam = kmalloc(size, GFP_KERNEL)) == NULL) {
		kfree(argmem);
		return NULL;
	}

	loc = &tfwcfg_location[tfwcfg_location_sz++];
	loc->op = op;
	loc->arg = argmem;
	loc->len = len;
	loc->cam = cam;
	loc->cam_sz = 0;
	loc->cam_max = TFW_CAMATCH_ARRAY_SZ;
	memcpy((void *)loc->arg, (void *)arg, len + 1);

	return loc;
}

/*
 * Process the location directive that opens a section for cache
 * action directives in the configuration.
 */
static int
tfwcfg_begin_location(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int ret, in_len;
	tfw_match_t op;
	const char *in_op, *in_arg;

	if (ce->attr_n || (ce->val_n != 2))
		return -EINVAL;

	/* Get the values of the 'location' directive. */
	in_op = ce->vals[0];	/* Match operator. */
	in_arg = ce->vals[1];	/* String for the match operator. */
	in_len = strlen(in_arg);

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfwcfg_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR("%s: Unknown match OP: '%s %s %s'\n",
			cs->name, cs->name, in_op, in_arg);
		return -EINVAL;
	}

	/* Make sure the location is not a duplicate. */
	if (tfwcfg_location_lookup(op, in_arg, in_len)) {
		TFW_ERR("%s: Duplicate entry: '%s %s %s'\n",
			cs->name, cs->name, in_op, in_arg);
		return -EINVAL;
	}

	/* Add new location and set it to be the current one. */
	tfwcfg_this_location = tfwcfg_location_new(op, in_arg, in_len);
	if (tfwcfg_this_location == NULL) {
		TFW_ERR("%s: Unable to add new location: '%s %s %s'\n",
			cs->name, cs->name, in_op, in_arg);
		return -EINVAL;
	}

	return 0;
}

/*
 * Close the section for a location directive.
 */
static int
tfwcfg_finish_location(TfwCfgSpec *cs)
{
	BUG_ON(!tfwcfg_this_location);
	tfwcfg_this_location = NULL;
	return 0;
}

/*
 * Free only the memory that has been allocated while processing
 * configuration directives. Make sure the memory is not freed twice.
 */
static void
__tfwcfg_cleanup_locache(void)
{
	int i;

	for (i = 0; i < tfwcfg_location_sz; ++i) {
		TfwCfgLocation *loc = &tfwcfg_location[i];
		if (loc->arg) {
			kfree(loc->arg);
			loc->arg = NULL;
		}
		if (loc->cam) {
			kfree(loc->cam);
			loc->cam = NULL;
		}
	}
	for (i = 0; i < tfwcfg_camatch_sz; ++i) {
		TfwCfgCacheMatch *cam = &tfwcfg_camatch[i];
		if (cam->arg) {
			kfree(cam->arg);
			cam->arg = NULL;
		}
	}
}

static void
tfwcfg_cleanup_locache(TfwCfgSpec *cs)
{
	__tfwcfg_cleanup_locache();
}

static void
tfwcfg_location_print_one(int idx, TfwCfgLocation *loc)
{
	int i;

	printk(KERN_ERR "%s: [%d]: location op [%d] arg [%s] len [%d]"
		" cam [%p] cam_sz [%d] cam_max [%d]\n",
		__func__, idx, loc->op, loc->arg, loc->len,
		loc->cam, loc->cam_sz, loc->cam_max);

	if (!loc->cam)
		return;

	for (i = 0; i < loc->cam_sz; ++i) {
		TfwCfgCacheMatch *cam = loc->cam[i];
		printk(KERN_ERR "    %s: [%d]: cache match stmt [%d]"
			" op [%d] arg [%s] len [%d]\n",
			__func__, i, cam->stmt, cam->op,
			cam->arg, cam->len);
	}
}
static void
tfwcfg_location_print_all(void)
{
	int i;

	printk(KERN_ERR "%s: tfwcfg_location_sz [%d] tfwcfg_location_max [%d]\n",
		__func__, tfwcfg_location_sz, tfwcfg_location_max);

	for (i = 0; i < tfwcfg_location_sz; ++i) {
		TfwCfgLocation *loc = &tfwcfg_location[i];
		tfwcfg_location_print_one(i, loc);
	}

	printk(KERN_ERR "%s: default location\n", __func__);
	tfwcfg_location_print_one(0, &tfwcfg_location_dflt);
}

static int
tfwcfg_start(void)
{
tfwcfg_location_print_all();
	return 0;
}

static void
tfwcfg_stop(void)
{
	__tfwcfg_cleanup_locache();
}

static TfwCfgSpec tfwcfg_location_specs[] = {
        {
		"cache_bypass", NULL,
		tfwcfg_handle_in_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.cleanup = tfwcfg_cleanup_locache
        },
        {
		"cache_fulfill", NULL,
		tfwcfg_handle_in_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.cleanup = tfwcfg_cleanup_locache
        },
        {}
};

static TfwCfgSpec tfwcfg_specs[] = {
	{
		"cache_bypass", NULL,
		tfwcfg_handle_out_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.cleanup = tfwcfg_cleanup_locache
	},
        {
		"cache_fulfill", NULL,
		tfwcfg_handle_out_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.cleanup = tfwcfg_cleanup_locache
        },
	{
		"location", NULL,
		tfw_cfg_handle_children,
		tfwcfg_location_specs,
		&(TfwCfgSpecChild) {
			.begin_hook = tfwcfg_begin_location,
			.finish_hook = tfwcfg_finish_location
		},
		.allow_none = true,
		.allow_repeat = true,
		/* .cleanup function in a section with
		   children causes a BUG_ON in cfg.c. */
	},
	{},
};

TfwCfgMod tfw_tfwcfg_cfg_mod = {
	.name	= "tfwcfg",
	.start	= tfwcfg_start,
	.stop	= tfwcfg_stop,
	.specs	= tfwcfg_specs,
};

int
tfw_tfwcfg_init(void)
{
	int size;

	BUG_ON(tfwcfg_camatch);
	BUG_ON(tfwcfg_location);

	/* Array of location directives. */
	size = sizeof(TfwCfgLocation) * TFW_LOCATION_ARRAY_SZ;
	tfwcfg_location = kzalloc(size, GFP_KERNEL);
	if (!tfwcfg_location) {
		TFW_ERR("Unable to allocate memory"
			" for location directives: %d bytes\n", size);
		return -ENOMEM;
	}
	tfwcfg_location_sz = 0;
	tfwcfg_location_max = TFW_LOCATION_ARRAY_SZ;

	/* Array of cache action directives. */
	size = sizeof(TfwCfgCacheMatch) * TFW_CAMATCH_ARRAY_SZ;
	tfwcfg_camatch = kzalloc(size, GFP_KERNEL);
	if (!tfwcfg_camatch) {
		TFW_ERR("Unable to allocate memory"
			" for cache action directives: %d bytes\n", size);
		kfree(tfwcfg_location);
		tfwcfg_location = NULL;
		return -ENOMEM;
	}
	tfwcfg_camatch_sz = 0;
	tfwcfg_camatch_max = TFW_CAMATCH_ARRAY_SZ;

	return 0;
}

void
tfw_tfwcfg_exit(void)
{
	int i;

	if (tfwcfg_camatch) {
		kfree(tfwcfg_camatch);
		tfwcfg_camatch = NULL;
	}
	if (tfwcfg_location) {
		for (i = 0; i < tfwcfg_location_sz; ++i)
			if (tfwcfg_location[i].cam)
				kfree(tfwcfg_location[i].cam);
		kfree(tfwcfg_location);
		tfwcfg_location = NULL;
	}
}

