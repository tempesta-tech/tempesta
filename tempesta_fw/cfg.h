/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
 * @dflt_value is set to true when a default value is submitted for parsing.
 *
 * Generally this is a temporary structure that lives only during the parsing
 * and acts as an interface between the parser FSM and TfwCfgSpec->handler.
 * The parser accumulates data in the TfwCfgEntry, and when the current entry is
 * finished, the parser executes the handler and then destroys the structure.
 *
 * @line_no	- Current line number, used to show propper config parsing error
 *		  to user.
 * @line	- Pointer to start of the current line, for same purpose.
 */
typedef struct {
	struct {
		bool have_children : 1;
		bool dflt_value : 1;
	};
	size_t val_n;
	size_t attr_n;
	const char *name;
	const char *vals[TFW_CFG_ENTRY_VAL_MAX];
	struct {
		const char *key;
		const char *val;
	} attrs[TFW_CFG_ENTRY_ATTR_MAX];
	size_t line_no;
	const char *line;
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
 *
 * Configuration specification may have nested entries. In that case @handler
 * must be filled with pointer to function @tfw_cfg_handle_children(),
 * @dest - null-terminated array of nested specifications, @spec_ext -
 * poitner to instance of @TfwCfgSpecChild struct. @cleanup function cleaning
 * specification and all the nested entries is a mandatory in this case.
 * Generic @tfw_cfg_cleanup_children() function calls @cleanup functions for all
 * the nested entries and may be used here. Or user-defined function may be
 * provided, if so it takes responsibility to clean up all the nested entries.
 *
 * Note: There is special case of repeatable specifications containing
 * non-repeatable nested entries. Such entries need @call_counter values
 * of non-repeatable child entries to be reset before using specs in the
 * configuration parser. That breaks generic @cleanup approach based on
 * @call_counter values, so reset will take place only if user-defined cleanup
 * function is provided.
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

static inline bool
tfw_cfg_is_dflt_value(TfwCfgEntry *cfg_entry)
{
	return cfg_entry->dflt_value;
}

/* Generic TfwCfgSpec->handler functions. */
int tfw_cfg_set_bool(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_int(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_set_str(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry);
int tfw_cfg_handle_children(TfwCfgSpec *self, TfwCfgEntry *parsed_entry);
void tfw_cfg_cleanup_children(TfwCfgSpec *cs);

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

void *tfw_cfg_read_file(const char *path, size_t *file_size);

int tfw_cfg_start(struct list_head *mod_list);
void tfw_cfg_stop(struct list_head *mod_list);

#endif /* __TFW_CFG_H__ */
