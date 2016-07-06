/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#ifndef __TFW_CFG_H__
#define __TFW_CFG_H__

#include <linux/list.h>

/*
 * ------------------------------------------------------------------------
 *	Interface for Tempesta FW modules.
 * ------------------------------------------------------------------------
 */

#define TFW_CFG_PATH "/etc/tempesta/tempesta_fw.conf"

/*
 * For simplicity, we store attributes and values as a static array,
 * so at this point we can't handle arbitrary many values like this:
 *   listen :8081 :8082 :8083 :8084 :8085 :8086 :8087 :8088 :8089 8090;
 *
 * Currently we have the maximum of 16 values and 16 attributes per entry.
 *
 * Also, such long lists of values looks ugly, so you almost always want to
 * transform the example above to something like this:
 *   listen 8081;
 *   listen 8082;
 *   listen 8083;
 * ...which is feasible with the current implementation.
 */
#define TFW_CFG_ENTRY_VAL_MAX  16
#define TFW_CFG_ENTRY_ATTR_MAX 16

/**
 * TfwCfgEntry represents a single parsed entry in a configuration file.
 *
 * Consider this raw configuration example:
 *     server example.com {
 *         listen 10.0.0.1:80 192.168.0.1:80 :8080 proto=http;
 *         listen :443 [::0]:443 proto=https;
 *     }
 * This is not a real configuration, but it is synthetically valid, and if you
 * parse it, the parser will produce the following three entries:
 *  1. TfwCfgEntry {
 *         .name = "server",
 *         .val_n = 1,
 *         .vals = { "example.com" }
 *         .have_children = true
 *     }
 *  2. TfwCfgEntry {
 *         .name = "listen",
 *         .val_n = 3,
 *         .vals = { "10.0.0.1:80", "192.168.0.1:80", ":8080" },
 *         .attr_n = 1,
 *         .attrs = { { .key="proto", .val="http" } },
 *         .have_children = false
 *     }
 *  3. TfwCfgEntry {
 *         .name = "listen",
 *         .val_n = 2,
 *         .vals = { ":443", "[::0]:443" },
 *         .attr_n = 1,
 *         .attrs = { { .key="proto", .val="https" } },
 *         .have_children = false
 *     }
 *
 * Both sections and directives are expressed by the TfwCfgEntry structure.
 * The difference is only in the @have_children flag which is true for sections.
 *
 * Generally this is a temporary structure that lives only during the parsing
 * and acts as an interface between the parser FSM and TfwCfgSpec->handler.
 * The parser accumulates data in the TfwCfgEntry, and when the current entry is
 * finished, the parser executes the handler and then destroys the structure.
 */
typedef struct {
	bool have_children;
	size_t val_n;
	size_t attr_n;
	const char *name;
	const char *vals[TFW_CFG_ENTRY_VAL_MAX];
	struct {
		const char *key;
		const char *val;
	} attrs[TFW_CFG_ENTRY_ATTR_MAX];
} TfwCfgEntry;

/**
 * Usage example:
 *   int print_attrs(const TfwCfgEntry *entry)
 *   {
 *           const char *key, *val;
 *           int i;
 *           TFW_CFG_ENTRY_FOR_EACH_ATTR(entry, i, key, val) {
 *                   printk("%s = %s\n", key, val);
 *           }
 *   }
 */
#define TFW_CFG_ENTRY_FOR_EACH_ATTR(e, idx, k, v)	\
	for ((idx) = 0, (k) = (e)->attrs[0].key, (v) = (e)->attrs[0].val; \
	     (idx++) < (e)->attr_n; \
	     (k) = (e)->attrs[(idx)].key, (v) = (e)->attrs[(idx)].val)

#define TFW_CFG_ENTRY_FOR_EACH_VAL(e, idx, v)	\
	for ((idx) = 0, (v) = (e)->vals[0];	\
	     (idx) < (e)->val_n;		\
	     (v) = (e)->vals[++(idx)])

/**
 * TfwCfgSpec is a single instruction for the configuration parser.
 * It specifies a @handler which is executed when the parser mets an entry with
 * the given @name.
 *
 * @name is the key for matching with TfwCfgEntry->name. Usually you provide an
 * array of TfwCfgSpec structures to the parser, and it searches for a matching
 * one for every parsed configuration entry.
 *
 * @deflt is a default value which is used when the configuration file contains
 * no matching entries. In this case the field is parsed into a fake TfwCfgEntry
 * object and pushed to the @handler in the same way as if it was a part of a
 * real configuration file. That is awkward for simple data types like integers
 * or booleans, but beneficial for complex ones like IP addresses and strings
 * where handler functions allocate memory.
 *
 * @handler is a callback function which is responsible for:
 *  1. Serializing strings into native data types.
 *     We don't make the parser bloated by handling all sorts of data types in
 *     there. Instead, we do only basic syntax parsing and leave rest of the job
 *     to the @handler. You choose an appropriate handler function that converts
 *     string to a desired type (int, bool, TfwAddr, etc); or you can implement
 *     your own handler without augmenting the parser, so this is flexible.
 *  2. Copying strings from TfwCfgEntry to some storage.
 *     The TfwCfgEntry is destroyed after the @handler returns, so you can't
 *     save pointers and you have to copy strings located in there. Usually you
 *     don't want strings, or you prefer to store them in a more efficient way,
 *     so we don't complicate things here with reference counters.
 *
 * @dest and @spec_ext are "arguments" used by the @handler.
 * Each handler function has its own types of these arguments.
 * Usually @dest is a destination object which is modified by the @handler,
 * and @spec_ext is a spec extension like TfwCfgSpecInt that contains some
 * constraints like minimum/maximum values,
 * WARNING: no type checking. You have to check carefully that these fields are
 * what @handler desires, or you get a memory corruption.
 *
 * @call_counter is how many times the @handler was invoked during the parsing
 * process. It is used by the parser to determine whether it needs to process
 * the @deflt field. The counter is reset when configuration is re-loaded.
 *
 * @cleanup is another callback which is supposed to free memory allocated
 * by the @handler. It is called when the configuration is un-loaded (either the
 * system is stopped, or new configuration is available, or an error occurred).
 * The @cleanup callback is invoked when @handler was called at least once
 * regardless of the handler's return value.
 */
typedef struct TfwCfgSpec TfwCfgSpec;
struct TfwCfgSpec {
	const char *name;
	const char *deflt;
	int (*handler)(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
	void *dest;
	void *spec_ext;			/* TfwCfgSpecInt, TfwCfgSpecStr, etc. */
	int call_counter;		/* Incremented after @handler call. */
	struct {
		bool allow_repeat:1;	/* allow @call_counter > 1 */
		bool allow_none:1;	/* allow @call_counter == 0 */
	};
	void (*cleanup)(TfwCfgSpec *self);
};

/**
 * Walks over a NULL-terminated array of TfwCfgSpec structures.
 */
#define TFW_CFG_FOR_EACH_SPEC(spec_pos, spec_arr) \
	for ((spec_pos) = (spec_arr); (spec_pos)->name; ++(spec_pos))

/**
 * Internally, the Tmpesta FW code is split into modules (not kernel modules,
 * but rather loosely coupled pieces of code). We need to distribute parsed
 * configuration data and start/stop events over them, but we don't want to make
 * the parser depend on all possible modules, so we utilize the late binding
 * approach here.
 *
 * Each module defines a TfwCfgMod structure and calls tfw_cfg_mod_register().
 * We maintain a list of registered modules in runtime and push events and
 * configuration data via callbacks.
 *
 * @name is a unique text identifier of the module.
 * Just like C identifiers, it must consist of alphanumeric characters and start
 * with a letter and so on.
 *
 * @specs is the specification for the configuration parser that lists all
 * possible configuration sections and directives for this module and describes
 * how to handle them.
 * @specs must be an array of TfwCfgSpec structures which is terminated
 * by a null (zero'ed) element.
 *
 * @start and @stop callbacks are invoked when corresponding events are received
 * via sysctl. The @start is called after the configuration is parsed and @specs
 * are handled.
 */
typedef struct {
	struct list_head list;	/* Private. Don't touch. */
	const char *name;	/* [A-Za-z0-9_], starts with a letter. */
	int  (*start)(void);
	void (*stop)(void);
	TfwCfgSpec *specs;	/* An array terminated by a null element. */
} TfwCfgMod;

/* Subscribe/unsubscribe a module to sysctl events and configuration updates. */
int tfw_cfg_mod_register(TfwCfgMod *mod);
void tfw_cfg_mod_unregister(TfwCfgMod *mod);

TfwCfgMod *tfw_cfg_mod_find(const char *name);

/*
 * ------------------------------------------------------------------------
 *	Generic TfwCfgSpec->handler functions.
 * ------------------------------------------------------------------------
 */

typedef struct {
	const char *name;
	int value;
} TfwCfgEnum;

/* TfwCfgSpec->spec_ext for tfw_cfg_set_int(). */
typedef struct {
	int multiple_of;
	struct {
		long min;
		long max;
	} range;
	TfwCfgEnum *enums;   /* NULL-terminated array. */
} TfwCfgSpecInt;

/**
 * TfwCfgSpec->spec_ext for tfw_cfg_set_str().
 *
 * @len_range is the min/max length constraint for the input string.
 * Ignored when @len_range.min == @len_range.max.
 */
typedef struct {
	struct {
		size_t min;
		size_t max;
	} len_range;
	const char *cset;
} TfwCfgSpecStr;

/**
 * TfwCfgSpec->spec_ext for tfw_cfg_handle_children().
 *
 * The @begin_hook is called before any children is parsed,
 * and the @finish_hook is called after all children entries are parsed.
 */
typedef struct {
	int (*begin_hook)(TfwCfgSpec *self, TfwCfgEntry *parent_entry);
	int (*finish_hook)(TfwCfgSpec *self);
} TfwCfgSpecChild;

/* Generic TfwCfgSpec->handler functions. */
int tfw_cfg_set_bool(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_int(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_str(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_handle_children(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);

/* Various helpers for building custom handler functions. */
int tfw_cfg_check_range(long value, long min, long max);
int tfw_cfg_check_multiple_of(long value, int divisor);
int tfw_cfg_check_val_n(const TfwCfgEntry *e, int val_n);
int tfw_cfg_check_single_val(const TfwCfgEntry *e);
int tfw_cfg_parse_int(const char *s, int *out_int);
int tfw_cfg_map_enum(const TfwCfgEnum mappings[],
		     const char *in_name, void *out_int);
const char *tfw_cfg_get_attr(const TfwCfgEntry *e, const char *attr_key,
			     const char *default_val);

/* Functions for making dynamic additions to configuration. */
TfwCfgSpec *tfw_cfg_spec_find(TfwCfgSpec specs[], const char *name);
int tfw_cfg_parse_mods_cfg(const char *cfg_text, struct list_head *mod_list);

#endif /* __TFW_CFG_H__ */
