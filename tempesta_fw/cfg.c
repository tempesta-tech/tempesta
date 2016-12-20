/**
 *		Tempesta FW
 *
 * Tempesta FW Configuration Framework.
 *
 * Requirements:
 *  - The configuring process must be habitual for any system administrator.
 *  - An ability to specify relatively complex configuration entities
 *    (lists, dictionaries, trees, etc).
 *  - Decomposition into modules. Other Tempesta subsystems should be able to
 *    register their sections in a configuration file. That should be possible
 *    for other kernel modules as well, so late binding has to be used.
 *  - Configuration refresh in run time (at least partially).
 *  - An ability to manage very large lists (e.g. blocked IP addresses).
 *
 *  None of existing approaches (sysfs, configfs, sysctl, ioctl) mets all the
 *  requirements, so we implement our own configuration subsystem. Current
 *  implementation doesn't fit all requirements either, but it is flexible
 *  enough for future extensions.
 *
 *  Basically, we store configuration in plain-text files and read them via VFS
 *  and parse right in the kernel space. This is not very conventional, but
 *  allows to pass relatively complex data structures to the kernel.
 *
 *  The configuration looks like this:
 *    entry1 42;
 *    entry2 1 2 3 foo=bar;
 *    entry3 {
 *        sub_entry1;
 *        sub_entry2;
 *    }
 *    entry4 with_value {
 *       and_subentries {
 *           and_subsubentries;
 *       }
 *    }
 *  It consists of entries. Each entry has:
 *    1. name;
 *    2. values (usually just one, but variable number of values is supported);
 *    3. attributes (a dictionary of key-value pairs);
 *    4. children entries (such entries act as sections or trees);
 *  The only name is required. Everything else is optional. The idea is similar
 *  to SDL (http://www.ikayzo.org/display/SDL/Language+Guide), but our syntax
 *  and terminology is more habitual for C/Linux programmers and users.
 *
 *  Tempesta FW modules register themselves and provide their configuration
 *  specifications via TfwCfgMod and TfwCfgSpec structures. The code here pushes
 *  events and parsed configuration via callbacks specified in these structures.
 *
 *  The code in this unit contains four main entities:
 *    1. The configuration parser.
 *       We utilize FSM approach for the parser. The code is divided into two
 *       FSMs: TFSM (tokenizer) and PFSM (the parser that produces entries).
 *    2. A bunch of generic  TfwCfgSpec->handler callbacks for the parser.
 *    3. TfwCfgMod list related routines, the top-level parsing routine.
 *       This part of code implements publishing start/stop events and parsed
 *       configuration data across modules.
 *    4. The list of registered modules, VFS and sysctl helpers, kernel module
 *       parameters. The stateful part of code.
 *
 * TODO:
 *  - "include" directives.
 *  - Handling large sets of data, possibly via TDB.
 *  - Re-loading some parts of the configuration on the fly without stopping the
 *    whole system.
 *  - Verbose error reporting: include file/line and expected/got messages.
 *  - Improve efficiency: too many memory allocations and data copying.
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

#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <net/net_namespace.h> /* for sysctl */

#include "addr.h"
#include "log.h"
#include "client.h"

#include "cfg.h"

/*
 * ------------------------------------------------------------------------
 *	Configuration Parser - TfwCfgEntry helpers
 * ------------------------------------------------------------------------
 *
 * TfwCfgEntry is a temporary structure that servers only as an interface
 * between the parser and TfwCfgSpec->handler callbacks.
 * The parser walks over input entries accumulating data in the TfwCfgEntry
 * structure. As soon as an entry is parsed, the parser invokes the handler
 * callback and then destroys the TfwCfgEntry object.
 *
 * Strings in the TfwCfgEntry are pieces of the input plain-text configuration,
 * but they have to be NULL-terminated, so we have to allocate space and copy
 * them. Helpers below facilitate that.
 */

static const char *
alloc_and_copy_literal(const char *src, size_t len)
{
	const char *src_pos, *src_end;
	char *dst, *dst_pos;
	bool is_escaped;

	BUG_ON(!src);

	dst = kmalloc(len + 1, GFP_KERNEL);
	if (!dst) {
		TFW_ERR("can't allocate memory\n");
		return NULL;
	}

	/* Copy the string eating escaping backslashes. */
	/* FIXME: the logic looks like a tiny FSM,
	 *        so perhaps it should be included to the TFSM. */
	src_end = src + len;
	src_pos = src;
	dst_pos = dst;
	is_escaped = false;
	while (src_pos < src_end) {
		if (*src_pos != '\\' || is_escaped) {
			is_escaped = false;
			*dst_pos = *src_pos;
			++dst_pos;
		}
		else if (*src_pos == '\\') {
			is_escaped = true;
		}
		++src_pos;
	}
	*dst_pos = '\0';

	return dst;
}

/**
 * Check name of an attribute or name
 *
 * Much like C identifiers, names must start with a letter and consist
 * only of alphanumeric and underscore characters. Currently this is
 * only a sanity check and the parser code would work without it, but in
 * future it may help to preserve compatibility if we decide to change
 * the parser.
 */
static bool
check_identifier(const char *buf, size_t len)
{
	size_t i;

	if (!len) {
		TFW_ERR("the string is empty\n");
		return false;
	}

	if ((len == 1) && (buf[0] == '*'))
		return true;

	if (!isalpha(buf[0])) {
		TFW_ERR("the first character is not a letter: '%c'\n", buf[0]);
		return false;
	}

	for (i = 0; i < len; ++i) {
		if (!isalnum(buf[i]) && buf[i] != '_') {
			TFW_ERR("invalid character: '%c' in '%.*s'\n",
				buf[i], (int)len, buf);
			return false;
		}
	}

	return true;
}

static void
entry_reset(TfwCfgEntry *e)
{
	const char *key, *val;
	size_t i;

	BUG_ON(!e);

	kfree(e->name);

	TFW_CFG_ENTRY_FOR_EACH_VAL(e, i, val)
		kfree(val);

	TFW_CFG_ENTRY_FOR_EACH_ATTR(e, i, key, val) {
		kfree(key);
		kfree(val);
	}

	memset(e, 0, sizeof(*e));
}

static int
entry_set_name(TfwCfgEntry *e, const char *name_src, size_t name_len)
{
	BUG_ON(!e);
	BUG_ON(e->name);

	if (!name_src || !name_len)
		return -EINVAL;

	if (!check_identifier(name_src, name_len))
		return -EINVAL;

	e->name = alloc_and_copy_literal(name_src, name_len);
	if (!e->name)
		return -ENOMEM;

	return 0;
}

static int
entry_add_val(TfwCfgEntry *e, const char *val_src, size_t val_len)
{
	const char *val;

	BUG_ON(!e);
	BUG_ON(e->val_n > ARRAY_SIZE(e->vals));

	if (!val_src)
		return -EINVAL;

	if (e->val_n == ARRAY_SIZE(e->vals)) {
		TFW_ERR("maximum number of values per entry reached\n");
		return -ENOBUFS;
	}

	/* Store an incoming value even if it's an empty string. */
	if (val_len)
		val = alloc_and_copy_literal(val_src, val_len);
	else
		val = alloc_and_copy_literal("", 0);

	if (!val)
		return -ENOMEM;

	e->vals[e->val_n++] = val;
	return 0;
}

static int
entry_add_attr(TfwCfgEntry *e, const char *key_src, size_t key_len,
		const char *val_src, size_t val_len)
{
	const char *key, *val;

	BUG_ON(!e);
	BUG_ON(e->attr_n > ARRAY_SIZE(e->attrs));

	if (!key_src || !key_len || !val_src || !val_len)
		return -EINVAL;

	if (e->attr_n == ARRAY_SIZE(e->attrs)) {
		TFW_ERR("maximum number of attributes per entry reached\n");
		return -ENOBUFS;
	}

	if (!check_identifier(key_src, key_len))
		return -EINVAL;

	key = alloc_and_copy_literal(key_src, key_len);
	val = alloc_and_copy_literal(val_src, val_len);

	if (!key || !val) {
		kfree(key);
		kfree(val);
		return -ENOMEM;
	}

	e->attrs[e->attr_n].key = key;
	e->attrs[e->attr_n].val = val;
	++e->attr_n;
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	Configuration parser - tokenizer and parser FSMs
 * ------------------------------------------------------------------------
 *
 * Basic terms used in this code:
 *   - MOVE - change FSM state and read the next character/token.
 *   - JMP  - change the state without reading anything.
 *   - SKIP - read the next character/token and re-enter the current state.
 *   - TURN - enter a new state (not re-enter the current state).
 *   - COND_JMP/COND_MOVE/COND_SKIP/etc - do it if the given condition is true.
 *   - lexeme - a sequence of characters in the input buffer.
 *   - token - type/class of a lexeme.
 *   - literal - a lexeme that carries a string value. Regular tokens are syntax
 *               elements, they don't have a value and their lexemes are always
 *               special control characters. Literals are not part of the syntax
 *               and they do have a value.
 *
 * Macro ownership:
 *   - FSM_*() - generic macros shared between PFSM and TFSM.
 *   - PFSM_*()/TFSM_*() - macros specific to parser/tokenizer.
 * For example, FSM_STATE() and FSM_JMP() are generic, they do the same thing
 * in both FSMs (a label and a jump to it); but PFSM_MOVE() and TFSM_MOVE() are
 * different, since they read values from different input streams (tokens and
 * characters respectively).
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
	const char  *in;      /* The whole input buffer. */
	const char  *pos;     /* Current position in the @in buffer. */

	/* Current FSM state is saved to here. */
	const void  *fsm_s;   /* Pointer to label (GCC extension). */
	const char  *fsm_ss;  /* Label name as string (for debugging). */

	/* Currently/previously processed character. */
	char        c;
	char        prev_c;

	/* Currently/previously processed token.
	 * The language is context-sensitive, so we need to store all these
	 * previous tokens and literals to parse it without peek()'ing. */
	token_t t;
	token_t prev_t;

	/* Literal value (not NULL only when @t == TOKEN_LITERAL). */
	const char *lit;
	const char *prev_lit;

	/* Length of @lit (the @lit is not terminated). */
	int lit_len;
	int prev_lit_len;
	int line;

	int  err;  /* The latest error code. */

	/* Currently parsed entry. Accumulates literals as values/attributes.
	 * When current entry is done, a TfwCfgSpec->handler is called and a new
	 * entry is started. */
	TfwCfgEntry e;
} TfwCfgParserState;

/* Macros common for both TFSM and PFSM. */

#define FSM_STATE(name) 		\
	TFW_DBG3("fsm: implicit exit from: %s\n", ps->fsm_ss); \
	BUG();				\
name:					\
	if (ps->fsm_s != &&name) {	\
		TFW_DBG3("fsm turn: %s -> %s\n", ps->fsm_ss, #name); \
		ps->fsm_s = &&name;	\
		ps->fsm_ss = #name;	\
	}

#define FSM_JMP(to_state) goto to_state

#define FSM_COND_JMP(cond, to_state) \
	FSM_COND_LAMBDA(cond, FSM_JMP(to_state))

#define FSM_COND_LAMBDA(cond, ...)	\
do {					\
	if (cond) {			\
		__VA_ARGS__;		\
	}				\
} while (0)				\

/* Macros specific to TFSM. */

#define TFSM_MOVE(to_state)	\
do {				\
	ps->prev_c = ps->c;	\
	ps->c = *(++ps->pos);	\
	TFW_DBG3("tfsm move: '%c' -> '%c'\n", ps->prev_c, ps->c); \
	FSM_JMP(to_state);	\
	if ( ps->prev_c == '\n'){\
		++ps->line; }	 \
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
	TFW_DBG3("pfsm move: %d (\"%.*s\") -> %d (\"%.*s\")", 	\
		ps->prev_t, ps->prev_lit_len, ps->prev_lit,  	\
		ps->t, ps->lit_len, ps->lit); 			\
	if(!ps->t) {						\
		ps->err = -EINVAL;				\
		FSM_JMP(PS_EXIT);				\
	}							\
	FSM_JMP(to_state);					\
} while (0)

#define PFSM_COND_MOVE(cond, to_state) \
	FSM_COND_LAMBDA(cond, PFSM_MOVE(to_state))

/**
 * The TFSM (Tokenizer Finite State Machine).
 *
 * Steps over characters in the input stream and classifies them as tokens.
 * Eats whitespace and comments automatically, never produces tokens for them.
 * Accumulates string literals in @ps->lit.
 * Produces one token per call (puts it to @ps->t), shifts current position
 * accordingly. Produces TOKEN_NA on EOF or invalid input.
 */
static void
read_next_token(TfwCfgParserState *ps)
{
	ps->prev_t = ps->t;
	ps->prev_lit = ps->lit;
	ps->prev_lit_len = ps->lit_len;
	ps->lit = NULL;
	ps->lit_len = 0;
	ps->t = TOKEN_NA;
	ps->c = *ps->pos;

	TFW_DBG3("tfsm start, char: '%c', pos: %.20s\n", ps->c, ps->pos);

	FSM_JMP(TS_START_NEW_TOKEN);

	/* The next character is read at _TFSM_MOVE(), so we have a fresh
	 * character automatically whenever we enter a state. */

	FSM_STATE(TS_START_NEW_TOKEN) {
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* A backslash means that the next character definitely has
		 * no special meaning and thus starts a literal. */
		FSM_COND_JMP(ps->c == '\\', TS_LITERAL_FIRST_CHAR);

		/* Eat non-is_escaped spaces. */
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
		 * The line break cannot be is_escaped within a comment. */
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

		/* Accumulate backslash together with any next character. */
		TFSM_COND_MOVE(ps->c == '\\', TS_LITERAL_ACC_ESCAPE);

		/* Non-escaped special characters terminate the literal. */
		TFSM_COND_JMP_EXIT(isspace(ps->c), TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '"', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '#', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '{', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '}', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == ';', TOKEN_LITERAL);
		TFSM_COND_JMP_EXIT(ps->c == '=', TOKEN_LITERAL);

		/* Accumulate everything else. */
		++ps->lit_len;
		TFSM_SKIP();
	}

	FSM_STATE(TS_LITERAL_ACC_ESCAPE) {
		ps->lit_len += 2;
		TFSM_MOVE(TS_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_QUOTED_LITERAL_FIRST_CHAR) {
		ps->lit = ps->pos;
		FSM_JMP(TS_QUOTED_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_QUOTED_LITERAL_ACCUMULATE) {
		/* EOF means there is no matching double quote. */
		TFSM_COND_JMP_EXIT(!ps->c, TOKEN_NA);

		/* A double quote terminates the literal,
		 * but it may be escaped with a backslash. */
		TFSM_COND_MOVE(ps->c == '\\', TS_QUOTED_LIT_ACC_ESCAPE);
		TFSM_COND_MOVE_EXIT(ps->c == '"', TOKEN_LITERAL);

		/* Everything else is accumulated (including line breaks). */
		++ps->lit_len;
		TFSM_SKIP();
	}

	FSM_STATE(TS_QUOTED_LIT_ACC_ESCAPE) {
		ps->lit_len += 2;
		TFSM_MOVE(TS_QUOTED_LITERAL_ACCUMULATE);
	}

	FSM_STATE(TS_EXIT) {
		TFW_DBG3("tfsm exit: t: %d, lit: %.*s\n",
			 ps->t, ps->lit_len, ps->lit);
	}
}

/**
 * The PFSM (Parser Finite State Machine).
 *
 * Steps over a stream of tokens (produces by the TFSM), accumulates values
 * in TfwCfgEntry and returns it when the input entry is terminated with ';'.
 * Returns one entry at a time and shifts the input position accordingly.
 * Should be called in a loop until NULL is returned.
 *
 * Doesn't recurse into nested entries.
 * I.e. it doesn't fully parse this:
 *   entry1 {
 *       entry2;
 *   }
 * Instead, it stops at the '{' character and the higher-level code has to use
 * push-down automaton approach to parse the section between '{' and '}'.
 * That is done because we are not going to complicate things here by building
 * a large syntax tree and creating a DSL to query it.
 */
static void
parse_cfg_entry(TfwCfgParserState *ps)
{
	TFW_DBG3("pfsm: start\n");
	BUG_ON(ps->err);

	/* Start of the input? Read the first token and start a new entry. */
	if (ps->in == ps->pos) {
		read_next_token(ps);
		if (!ps->t)
			FSM_JMP(PS_EXIT);
	}

	/* Continue: start a new entry at the current position. */
	BUG_ON(!ps->t);
	FSM_JMP(PS_START_NEW_ENTRY);

	/* Every _PFSM_MOVE() invokes _read_next_token(), so when we enter
	 * any state, we get a new token automatically.
	 * So:
	 *  name key = value;
	 *  ^
	 *  current literal is here; we need to store it as the name.
	 */
	FSM_STATE(PS_START_NEW_ENTRY) {
		entry_reset(&ps->e);
		TFW_DBG3("set name: %.*s\n", ps->lit_len, ps->lit);

		ps->err = entry_set_name(&ps->e, ps->lit, ps->lit_len);
		ps->e.line = ps->line;
		FSM_COND_JMP(ps->err, PS_EXIT);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	/* The name was easy.
	 * Now we have a situation where at current position we don't know
	 * whether we have a value or an attribute:
	 *     name key = value;
	 *          ^
	 *          current position here
	 *
	 * An implementation of peek_token() would be tricky here because the
	 * TFSM is not pure (it alters the current state). So instead of looking
	 * forward, we move to the next position and look to the '=' sign:
	 * if it is there - then we treat previous value as an attribute name,
	 * otherwise we save it as a value of the current node.
	 */

	FSM_STATE(PS_VAL_OR_ATTR) {
		PFSM_COND_MOVE(ps->t == TOKEN_LITERAL, PS_MAYBE_EQSIGN);
		FSM_COND_JMP(ps->t == TOKEN_SEMICOLON, PS_SEMICOLON);
		FSM_COND_JMP(ps->t == TOKEN_LBRACE, PS_LBRACE);

		ps->err = -EINVAL;
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_MAYBE_EQSIGN) {
		FSM_COND_JMP(ps->t == TOKEN_EQSIGN, PS_STORE_ATTR_PREV);
		FSM_JMP(PS_STORE_VAL_PREV);
	}

	FSM_STATE(PS_STORE_VAL_PREV) {
		/* name val1 val2;
		 *           ^
		 *           We are here (but still need to store val1). */
		TFW_DBG3("add value: %.*s\n", ps->prev_lit_len, ps->prev_lit);

		ps->err = entry_add_val(&ps->e, ps->prev_lit, ps->prev_lit_len);
		FSM_COND_JMP(ps->err, PS_EXIT);

		FSM_JMP(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_STORE_ATTR_PREV) {
		/* name key = val;
		 *          ^
		 *          We are here. */
		const char *key, *val;
		int key_len, val_len;

		key = ps->prev_lit;
		key_len = ps->prev_lit_len;
		read_next_token(ps);  /* eat '=' */
		val = ps->lit;
		val_len = ps->lit_len;

		TFW_DBG3("add attr: %.*s = %.*s\n", key_len, key, val_len, val);

		ps->err = entry_add_attr(&ps->e, key, key_len, val, val_len);
		FSM_COND_JMP(ps->err, PS_EXIT);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_LBRACE) {
		/* Simply exit on '{' leaving nested nodes untouched and
		 * surrounded with braces. The caller should detect it and parse
		 * them in a loop. */
		ps->e.have_children = true;
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_SEMICOLON) {
		/* Simply eat ';'. Don't MOVE because the next character may be
		 * '\0' and that triggers an error (because we expect more input
		 * tokens when we do _PFSM_MOVE()). */
		read_next_token(ps);
		FSM_JMP(PS_EXIT);
	}

	FSM_STATE(PS_EXIT) {
		/* Cleanup entry on error */
		if (ps->err)
			entry_reset(&ps->e);
		TFW_DBG3("pfsm: exit\n");
	}
}

/*
 * ------------------------------------------------------------------------
 *	Configuration Parser - TfwCfgSpec helpers.
 * ------------------------------------------------------------------------
 *
 * The configuration parsing is done slightly differently depending on the
 * context (top-level vs recursing into children entries), but the TfwCfgSpec
 * is handled in the same way in both cases. So the code below is the shared
 * logic between these two cases.
 */

static TfwCfgSpec *
spec_find(TfwCfgSpec specs[], const char *name)
{
	TfwCfgSpec *spec;

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (!strcmp(spec->name, name))
			return spec;
	}

	return NULL;
}

static void
spec_start_handling(TfwCfgSpec specs[])
{
	TfwCfgSpec *spec;

	BUG_ON(!specs);

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		BUG_ON(!spec->name);
		BUG_ON(!*spec->name);
		BUG_ON(!check_identifier(spec->name, strlen(spec->name)));
		BUG_ON(!spec->handler);
		BUG_ON(spec->call_counter < 0);
	}
}

static int
spec_handle_entry(TfwCfgSpec *spec, TfwCfgEntry *parsed_entry)
{
	int r;

	if (!spec->allow_repeat && spec->call_counter) {
		TFW_ERR("duplicate entry: '%s', only one such entry is allowed."
			"\n", parsed_entry->name);
		return -EINVAL;
	}

	TFW_DBG2("spec handle: '%s'\n", spec->name);
	r = spec->handler(spec, parsed_entry);
	++spec->call_counter;
	if (r)
		TFW_ERR("configuration handler returned error: %d\n", r);

	return r;
}

/**
 * Handle TfwCfgSpec->deflt . That is done by constructing a buffer containing
 * fake configuration text and parsing it as if it was a real configuration.
 * The parsed TfwCfgEntry then is passed to the TfwCfgSpec->handler as usual.
 *
 * TODO: refactoring. The code is not elegant.
 */
static int
spec_handle_default(TfwCfgSpec *spec)
{
	int len, r;
	static char fake_entry_buf[PAGE_SIZE];
	static TfwCfgParserState ps;

	len = snprintf(fake_entry_buf, sizeof(fake_entry_buf), "%s %s;",
		 spec->name, spec->deflt);
	BUG_ON(len >= sizeof(fake_entry_buf));

	TFW_DBG2("use default entry: '%s'\n", fake_entry_buf);

	memset(&ps, 0, sizeof(ps));
	ps.in = ps.pos = fake_entry_buf;
	parse_cfg_entry(&ps);
	BUG_ON(!ps.e.name);
	BUG_ON(ps.err);
	BUG_ON(ps.t != TOKEN_NA);

	r = spec_handle_entry(spec, &ps.e);
	entry_reset(&ps.e);
	return r;
}

static int spec_finish_handling(TfwCfgSpec specs[]);

static int
spec_handle_default_section(TfwCfgSpec *spec)
{
	if (spec->handler != tfw_cfg_handle_children)
		return 0;
	TFW_DBG2("use default values for section '%s'\n", spec->name);
	if (spec->dest == NULL)
		return 0;
	return spec_finish_handling(spec->dest);
}

static int
spec_finish_handling(TfwCfgSpec specs[])
{
	int r;
	TfwCfgSpec *spec;

	/* Here we are interested in specs that were not triggered during
	 * the configuration parsing. There are three cases here:
	 *  1. deflt != NULL
	 *     Ok: just use the default value instead of real configuration.
	 *  2. deflt == NULL && allow_none == true
	 *     Ok: no such entry parsed at all (including the default),
	 *     but this is allowed, so do nothing.
	 *  3. deflt == NULL && allow_none == false
	 *     Error: the field is not optional, no such entry parsed and no
	 *     default value is provided, so issue an error.
	 */
	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (spec->call_counter)
			continue;
		if (spec->handler == tfw_cfg_handle_children) {
			if (!spec->allow_none)
				/* Whole section absent */
				if ((r = spec_handle_default_section(spec)))
					goto err_dflt_val;
		} else if (spec->deflt) {
			if ((r = spec_handle_default(spec)))
				goto err_dflt_val;
		} else if (!spec->allow_none) {
			/* Jump just because TFW_ERR() is ugly here. */
			goto err_no_entry;
		}
	}

	return 0;

err_no_entry:
	TFW_ERR("the required entry is not found: '%s'\n", spec->name);
	return -EINVAL;

err_dflt_val:
	TFW_ERR("Error handling default value for: '%s'\n", spec->name);
	return r;
}

static void
spec_cleanup(TfwCfgSpec specs[])
{
	TfwCfgSpec *spec;

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (spec->call_counter && spec->cleanup) {
			TFW_DBG2("spec cleanup: '%s'\n", spec->name);
			spec->cleanup(spec);
		}
		spec->call_counter = 0;

		/**
		 * When spec processing function is tfw_cfg_handle_children(),
		 * a user-defined .cleanup function for that spec is not
		 * allowed. Instead, an special .cleanup function is assigned
		 * to that spec, thus overwriting the (zero) value there.
		 * When the whole cleanup process completes, revert that spec
		 * entry to original (zero) value. That will allow reuse of
		 * the spec.
		 */
		if (spec->handler == &tfw_cfg_handle_children) {
			spec->cleanup = NULL;
		}
	}
}

/*
 * ------------------------------------------------------------------------
 *	Configuration parser - generic TfwCfgSpec->handlers functions
 *	and other helpers for writing custom handlers.
 * ------------------------------------------------------------------------
 */

int
tfw_cfg_map_enum(const TfwCfgEnum mappings[],
		 const char *in_name, void *out_int)
{
	int *out;
	const TfwCfgEnum *pos;

	/* The function writes an int, but usually you want to pass an enum
	 * as the @out_int, so ensure check that their sizes are equal.
	 * Beware: that doesn't protect from packed enums. You may get a memory
	 * corruption if you pass an enum __attribute__((packed)) as @out_int.
	 */
	typedef enum { _DUMMY } _dummy;
	BUILD_BUG_ON(sizeof(_dummy) != sizeof(int));

	BUG_ON(!mappings);
	BUG_ON(!in_name);
	BUG_ON(!out_int);

	for (pos = mappings; pos->name; ++pos) {
		BUG_ON(!check_identifier(pos->name, strlen(pos->name)));
		if (!strcasecmp(in_name, pos->name)) {
			out = out_int;
			*out = pos->value;
			return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(tfw_cfg_map_enum);

/**
 * Get value of attribute with name @attr_key.
 * Return @default_val if the attribute is not found in the entry @e.
 */
const char *
tfw_cfg_get_attr(const TfwCfgEntry *e, const char *attr_key,
		 const char *default_val)
{
	size_t i;
	const char *key, *val;

	TFW_CFG_ENTRY_FOR_EACH_ATTR(e, i, key, val) {
		if (!strcasecmp(key, attr_key))
			return val;
	}

	return default_val;
}
EXPORT_SYMBOL(tfw_cfg_get_attr);

/**
 * Check that integer is in specified range.
 * Print an error and return non-zero if it is out of range.
 */
int
tfw_cfg_check_range(long value, long min, long max)
{
	if (min != max && (value < min || value > max)) {
		TFW_ERR("the value %ld is out of range: [%ld, %ld]\n",
			value, min, max);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_check_range);

/**
 * Check that integer @value is a multiple of @divisor (print an error
 * otherwise);
 */
int
tfw_cfg_check_multiple_of(long value, int divisor)
{
	if (divisor && (value % divisor)) {
		TFW_ERR("the value of %ld is not a multiple of %d\n",
			value, divisor);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_check_multiple_of);

/**
 * Check that the entry @e has exactly @val_n values.
 */
int
tfw_cfg_check_val_n(const TfwCfgEntry *e, int val_n)
{
	if (e->val_n != val_n) {
		TFW_ERR("invalid number of values; expected: %d, got: %zu\n",
			val_n, e->val_n);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_check_val_n);

/**
 * Most of the handlers below work with single-value entries like this:
 *   option1 42;
 *   option2 true;
 *   option3 192.168.1.1;
 *
 * This function helps those handlers to check that the input entry matches
 * to the expected pattern: single value, no attributes, no children entries.
 */
int
tfw_cfg_check_single_val(const TfwCfgEntry *e)
{
	int r = -EINVAL;

	if (e->val_n == 0)
		TFW_ERR("no value specified\n");
	else if (e->val_n > 1)
		TFW_ERR("more than one value specified\n");
	else if (e->attr_n)
		TFW_ERR("unexpected attributes\n");
	else if (e->have_children)
		TFW_ERR("unexpected children entries\n");
	else
		r = 0;

	return r;
}
EXPORT_SYMBOL(tfw_cfg_check_single_val);

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
detect_base(const char **pos)
{
	const char *str = *pos;
	size_t len = strlen(str);

	if (!len)
		return 0;

	if (len > 2 && str[0] == '0' && isalpha(str[1])) {
		char c = tolower(str[1]);

		(*pos) += 2;

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
tfw_cfg_parse_int(const char *s, int *out_int)
{
	int base = detect_base(&s);
	if (!base)
		return -EINVAL;
	return kstrtoint(s, base, out_int);
}
EXPORT_SYMBOL(tfw_cfg_parse_int);

static void
tfw_cfg_cleanup_children(TfwCfgSpec *cs)
{
	TfwCfgSpec *nested_specs = cs->dest;
	spec_cleanup(nested_specs);
}

/**
 * This handler allows to parse nested entries recursively.
 *
 * @arg must be an array of TfwCfgSpec structures which is applied to nested
 * entries.
 *
 * When there are nested entries, the parse_and_handle_cfg_entry()
 * stops at this position:
 *         v
 * section {
 *     option1;
 *     option2;
 *     option3;
 *     ...
 * }
 * ...and invokes the TfwCfgSpec->handler which turns out to be this fucntion.
 * Here we simply continue parsing by recursing to parse_and_handle_cfg_entry().
 *
 * Also, we cheat here: we don't create a new TfwCfgParserState, but rather
 * continue using the parent state. We know that the TfwCfgEntry is the part
 * of the parent state, so we simply restore it with container_of().
 */
int
tfw_cfg_handle_children(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	TfwCfgParserState *ps = container_of(e, TfwCfgParserState, e);
	TfwCfgSpecChild *cse = cs->spec_ext;
	TfwCfgSpec *nested_specs = cs->dest;
	TfwCfgSpec *matching_spec;
	int ret;

	BUG_ON(!nested_specs);
	BUG_ON(!cs->call_counter && cs->cleanup);
	cs->cleanup = tfw_cfg_cleanup_children;

	if (!e->have_children) {
		TFW_ERR("the entry has no nested children entries\n");
		return -EINVAL;
	}

	/* Call TfwCfgSpecChild->begin_hook before parsing anything. */
	ret = (cse && cse->begin_hook) ? cse->begin_hook(cs, e) : 0;
	if (ret)
		return ret;

	/* Prepare child TfwCfgSpec for parsing. */
	spec_start_handling(nested_specs);

	/*
	 * We get to this function when the caller finds
	 * an opening brace. Confirm we have a '{' here.
	 */
	BUG_ON(ps->t != TOKEN_LBRACE);

	read_next_token(ps);
	if (ps->err)
		return ps->err;

	/* Walk over children entries. */
	while (ps->t && (ps->t != TOKEN_RBRACE)) {
		parse_cfg_entry(ps);
		if (ps->err) {
			TFW_ERR("parser error\n");
			return ps->err;
		}

		matching_spec = spec_find(nested_specs, ps->e.name);
		if (!matching_spec) {
			TFW_ERR("don't know how to handle: %s\n", ps->e.name);
			entry_reset(&ps->e);
			return -EINVAL;
		}

		ret = spec_handle_entry(matching_spec, &ps->e);
		entry_reset(&ps->e);
		if (ret)
			return ret;
	}

	/*
	 * Normally, we get out of the loop when a closing brace
	 * is found. Otherwise, there's an error in configuration.
	 * Check that we have a '}' here.
	 */
	if (ps->t != TOKEN_RBRACE) {
		TFW_ERR("%s: Missing closing brace.\n", cs->name);
		return -EINVAL;
	}

	read_next_token(ps);
	if (ps->err)
		return ps->err;
	ret = spec_finish_handling(nested_specs);
	if (ret)
		return ret;

	/* Children entries are parsed, call TfwCfgSpecChild->finish_hook. */
	ret = (cse && cse->finish_hook) ? cse->finish_hook(cs) : 0;
	return ret;
}
EXPORT_SYMBOL(tfw_cfg_handle_children);

int
tfw_cfg_set_bool(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	bool is_true, is_false;
	bool *dest_bool = cs->dest;
	const char *in_str = e->vals[0];

	BUG_ON(!dest_bool);

	/* Handle simple flag without a value.
	 * Usually it looks like this:
	 *   backend 127.0.0.1:8001 {
	 *      health_check;
	 *      ...;
	 *   }
	 */
	if (!e->val_n && !e->attr_n && !e->have_children) {
		*dest_bool = true;
		return 0;
	}

	/* Handle explicit (single) value, for example:
	 *   feature on;
	 *   feature off;
	 */
	if (tfw_cfg_check_single_val(e))
		return -EINVAL;

	is_true =  !strcasecmp(in_str, "1")
	        || !strcasecmp(in_str, "y")
	        || !strcasecmp(in_str, "on")
	        || !strcasecmp(in_str, "yes")
	        || !strcasecmp(in_str, "true")
	        || !strcasecmp(in_str, "enable");

	is_false =  !strcasecmp(in_str, "0")
	         || !strcasecmp(in_str, "n")
	         || !strcasecmp(in_str, "off")
	         || !strcasecmp(in_str, "no")
	         || !strcasecmp(in_str, "false")
	         || !strcasecmp(in_str, "disable");

	BUG_ON(is_true && is_false);
	if (!is_true && !is_false) {
		TFW_ERR("invalid boolean value: '%s'\n", in_str);
		return -EINVAL;
	}

	*dest_bool = is_true;
	return 0;
}
EXPORT_SYMBOL(tfw_cfg_set_bool);


int
tfw_cfg_set_int(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int r, val;
	int *dest_int;
	const char *in_str;
	TfwCfgSpecInt *cse;

	BUG_ON(!cs->dest);
	r = tfw_cfg_check_single_val(e);
	if (r)
		goto err;

	/* First, try to substitute an enum keyword with an integer value. */
	in_str = e->vals[0];
	cse = cs->spec_ext;
	if (cse && cse->enums) {
		r = tfw_cfg_map_enum(cse->enums, in_str, &val);
		if (!r)
			goto val_is_parsed;
	}

	r = tfw_cfg_parse_int(in_str, &val);
	if (r)
		goto err;

val_is_parsed:
	/* Check value restrictions if we have any in the spec extension. */
	if (cse) {
		r  = tfw_cfg_check_multiple_of(val, cse->multiple_of);
		r |= tfw_cfg_check_range(val, cse->range.min, cse->range.max);
		if (r)
			goto err;
	}

	dest_int = cs->dest;
	*dest_int = val;
	return 0;

err:
	TFW_ERR("can't parse integer");
	return -EINVAL;
}
EXPORT_SYMBOL(tfw_cfg_set_int);

static void
tfw_cfg_cleanup_str(TfwCfgSpec *cs)
{
	char **strp = cs->dest;
	char *str = *strp;

	/* The function shall only be called when some memory was allocated. */
	BUG_ON(!str);
	kfree(str);
	*strp = NULL;
	cs->cleanup = NULL;
}

static bool
is_matching_to_cset(const char *p, const char *cset)
{
	while (*p) {
		if (!strchr(cset, *p))
			return false;
		++p;
	}
	return true;
}

int
tfw_cfg_set_str(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	const char **dest_strp;
	int r;

	BUG_ON(!cs);
	BUG_ON(!cs->dest);
	BUG_ON(cs->call_counter);
	BUG_ON(cs->cleanup);

	r = tfw_cfg_check_single_val(e);
	if (r)
		return r;

	if (cs->spec_ext) {
		TfwCfgSpecStr *cse = cs->spec_ext;
		const char *str, *cset;
		int min, max, len;

		str = e->vals[0];
		len = strlen(str);

		min = cse->len_range.min;
		max = cse->len_range.max;
		if (min != max && (len < min || len > max)) {
			TFW_ERR("the string length (%d) is out of valid range "
				" (%d, %d): '%s'\n", len, min, max, str);
			return -EINVAL;
		}

		cset = cse->cset;
		if (cset && !is_matching_to_cset(str, cset)) {
			TFW_ERR("invalid characters found: '%s'\n", str);
			return -EINVAL;
		}
	}

	/* Simply steal the dynamically allocated value from the TfwCfgEntry
	 * and set a callback to free it properly. */
	dest_strp = cs->dest;
	*dest_strp = e->vals[0];
	e->vals[0] = NULL;
	cs->cleanup = tfw_cfg_cleanup_str;

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_set_str);

/*
 * ------------------------------------------------------------------------
 *	TfwCfgMod list related routines, the top-level parsing routine.
 * ------------------------------------------------------------------------
 */

#define MOD_FOR_EACH(pos, head) \
	list_for_each_entry(pos, head, list)

#define MOD_FOR_EACH_REVERSE(pos, head) \
	list_for_each_entry_reverse(pos, head, list)

#define MOD_FOR_EACH_SAFE_REVERSE(pos, tmp, head) \
	list_for_each_entry_safe_reverse(pos, tmp, head, list)

/**
 * Iterate over modules in reverse order starting from current element
 * @curr_pos. Useful for roll-back'ing all previously processed modules
 * when an operation for current module has failed. We start from current
 * element as an operation for current module may have been half-done,
 * and the module needs to be called as well.
 */
#define MOD_FOR_EACH_REVERSE_FROM_CURR(pos, curr_pos, head) 		\
	for (pos = curr_pos;  &pos->list != head; 			\
	     pos = list_entry(pos->list.prev, TfwCfgMod, list))

static int
mod_start(TfwCfgMod *mod)
{
	int ret = 0;

	TFW_DBG2("mod_start(): %s\n", mod->name);
	if (mod->start)
		ret = mod->start();
	if (ret)
		TFW_ERR("start() for module '%s' returned the error: %d\n",
			mod->name, ret);
	return ret;
}

static void
mod_stop(TfwCfgMod *mod)
{
	TFW_DBG2("mod_stop(): %s\n", mod->name);
	if (mod->stop)
		mod->stop();
}

static void
print_parse_error(const TfwCfgParserState *ps)
{

	TFW_ERR("configuration parsing error: str:%d;w:%s\n", ps->e.line + 1,
		ps->e.name);
}

/*
 * Find configuration option specs by option name.
 * This is a helper function for outside use.
 * It is used in making dynamic additions to configuration.
 */
TfwCfgSpec *
tfw_cfg_spec_find(TfwCfgSpec specs[], const char *name)
{
	return spec_find(specs, name);
}
EXPORT_SYMBOL(tfw_cfg_spec_find);

/**
 * The top-level parsing routine.
 *
 * Parses @cfg_text and pushes the parsed data to all modules in the @mod_list.
 * For each parsed entry searches for a matching TfwCfgSpec across all specs
 * of all modules in the @mod_list.
 */
int
tfw_cfg_parse_mods_cfg(const char *cfg_text, struct list_head *mod_list)
{
	TfwCfgParserState ps = {
		.in = cfg_text,
		.pos = cfg_text
	};
	TfwCfgMod *mod;
	TfwCfgSpec *matching_spec = NULL;
	int r = -EINVAL;

	MOD_FOR_EACH(mod, mod_list) {
		spec_start_handling(mod->specs);
	}

	do {
		parse_cfg_entry(&ps);
		if (ps.err) {
			TFW_ERR("syntax error\n");
			goto err;
		}
		if (!ps.e.name)
			break; /* EOF - nothing is parsed and no error. */

		MOD_FOR_EACH(mod, mod_list) {
			matching_spec = spec_find(mod->specs, ps.e.name);
			if (matching_spec)
				break;
		}
		if (!matching_spec) {
			TFW_ERR("don't know how to handle: '%s'\n", ps.e.name);
			entry_reset(&ps.e);
			goto err;
		}

		r = spec_handle_entry(matching_spec, &ps.e);
		entry_reset(&ps.e);
		if (r)
			goto err;
	} while (ps.t);

	MOD_FOR_EACH(mod, mod_list) {
		r = spec_finish_handling(mod->specs);
		if (r)
			goto err;
	}

	return 0;
err:
	print_parse_error(&ps);
	return -EINVAL;
}
EXPORT_SYMBOL(tfw_cfg_parse_mods_cfg);

/**
 * Parse the @cfg_text with pushing parsed data to modules, and then start
 * all modules via the TfwCfgMod->start callback.
 *
 * Upon error, the function tries to roll-back the state: if any modules are
 * already started, it stops them and so on.
 */
static int
tfw_cfg_start_mods(const char *cfg_text, struct list_head *mod_list)
{
	int ret;
	TfwCfgMod *mod, *tmp_mod;

	BUG_ON(list_empty(mod_list));

	TFW_DBG2("parsing configuration and pushing it to modules...\n");
	ret = tfw_cfg_parse_mods_cfg(cfg_text, mod_list);
	if (ret) {
		TFW_ERR("can't parse configuration data\n");
		goto err_recover_cleanup;
	}

	TFW_DBG("Checking backends and listeners\n");
	ret = tfw_sock_check_listeners();
	if (ret) {
		TFW_ERR("One of the backends is tempesta itself! Fix config\n");
		goto err_recover_cleanup;
	}

	TFW_DBG2("starting modules...\n");
	MOD_FOR_EACH(mod, mod_list) {
		ret = mod_start(mod);
		if (ret)
			goto err_recover_stop;
	}

	TFW_LOG("modules are started\n");
	return 0;

err_recover_stop:
	TFW_DBG2("stopping already stared modules\n");
	MOD_FOR_EACH_REVERSE_FROM_CURR(tmp_mod, mod, mod_list) {
		mod_stop(tmp_mod);
	}

err_recover_cleanup:
	MOD_FOR_EACH_REVERSE(mod, mod_list) {
		spec_cleanup(mod->specs);
	}

	return ret;
}

/**
 * Stop all registered modules and clean up theeir parsed configuration data.
 *
 * Passes are done in reverse order of tfw_cfg_mod_start_all()
 * (modules are started/stopped in LIFO manner).
 */
void
tfw_cfg_stop_mods(struct list_head *mod_list)
{
	TfwCfgMod *mod;

	MOD_FOR_EACH_REVERSE(mod, mod_list) {
		mod_stop(mod);
		spec_cleanup(mod->specs);
	}
}
/*
 * ------------------------------------------------------------------------
 *	The list of registered modules, VFS and sysctl helpers.
 * ------------------------------------------------------------------------
 */

/* The file path is passed via the kernel module parameter.
 * Usually you would not like to change it on a running system. */
static char *tfw_cfg_path = TFW_CFG_PATH;
module_param(tfw_cfg_path, charp, 0444);
MODULE_PARM_DESC(tfw_cfg_path,
		 "Path to Tempesta FW configuration file. Must be absolute.");

/* The buffer net.tempesta.state value as a string.
 * We need to store it to avoid double start or stop action. */
static char tfw_cfg_sysctl_state_buf[32];
DEFINE_MUTEX(tfw_cfg_sysctl_state_buf_mtx);

/* The global list of all registered modules (consists of TfwCfgMod objects). */
static LIST_HEAD(tfw_cfg_mods);
static DEFINE_RWLOCK(cfg_mods_lock);

/* The deserialized value of tfw_cfg_sysctl_state_buf.
 * Indicates that all registered modules are started. */
bool tfw_cfg_mods_are_started;


/**
 * The functions returns a buffer containing the whole file.
 * The buffer must be freed with vfree().
 */
void *
tfw_cfg_read_file(const char *path, size_t *file_size)
{
	char *out_buf;
	struct file *fp;
	ssize_t bytes_read;
	size_t read_size, buf_size;
	loff_t offset;
	mm_segment_t oldfs;

	if (!path || !*path) {
		TFW_ERR("can't open file with empty name\n");
		return NULL;
	}

	TFW_DBG2("reading file: %s\n", path);

	oldfs = get_fs();
	set_fs(get_ds());

	fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR_OR_NULL(fp)) {
		TFW_ERR("can't open file: %s (err: %ld)\n", path, PTR_ERR(fp));
		goto err_open;
	}

	buf_size = fp->f_inode->i_size;
	TFW_DBG2("file size: %zu bytes\n", buf_size);
	buf_size += 1; /* for '\0' */

	if (file_size)
		*file_size = buf_size;

	out_buf = vmalloc(buf_size);
	if (!out_buf) {
		TFW_ERR("can't allocate memory\n");
		goto err_alloc;
	}

	offset = 0;
	do {
		TFW_DBG3("read by offset: %d\n", (int)offset);
		read_size = min((size_t)(buf_size - offset), PAGE_SIZE);
		bytes_read = vfs_read(fp, out_buf + offset, read_size, \
				      &offset);
		if (bytes_read < 0) {
			TFW_ERR("can't read file: %s (err: %zu)\n", path,
				bytes_read);
			goto err_read;
		}
	} while (bytes_read);

	/* Exactly one byte (reserved for '\0') should remain. */
	if (buf_size - offset - 1) {
		TFW_ERR("file size changed during the read: '%s'\n,", path);
		goto err_read;
	}

	filp_close(fp, NULL);

	out_buf[offset] = '\0';
	set_fs(oldfs);
	return out_buf;

err_read:
	vfree(out_buf);
err_alloc:
	filp_close(fp, NULL);
err_open:
	set_fs(oldfs);
	return NULL;
}

/**
 * Process command received from sysctl as string (either "start" or "stop").
 * Do corresponding actions, but only if the state is changed.
 */
static int
handle_state_change(const char *old_state, const char *new_state)
{
	TFW_LOG("got state via sysctl: %s\n", new_state);

	if (!strcasecmp(old_state, new_state)) {
		TFW_LOG("the state '%s' isn't changed, nothing to do\n",
			new_state);
		return 0;
	}
	if (!strcasecmp("start", new_state)) {
		int ret;
		char *cfg_text_buf;

		TFW_DBG3("reading configuration file...\n");
		cfg_text_buf = tfw_cfg_read_file(tfw_cfg_path, NULL);
		if (!cfg_text_buf)
			return -ENOENT;

		TFW_LOG("starting all modules...\n");
		ret = tfw_cfg_start_mods(cfg_text_buf, &tfw_cfg_mods);
		if (ret)
			TFW_ERR("failed to start modules\n");
		else
			tfw_cfg_mods_are_started = true;

		vfree(cfg_text_buf);
		return ret;
	}
	if (!strcasecmp("stop", new_state)) {
		TFW_LOG("stopping all modules...\n");
		if (tfw_cfg_mods_are_started)
			tfw_cfg_stop_mods(&tfw_cfg_mods);
		tfw_cfg_mods_are_started = false;
		return 0;
	}

	/* Neither "start" or "stop"? */
	TFW_ERR("invalid state: '%s'. Should be either 'start' or 'stop'\n",
		new_state);
	return -EINVAL;
}

/**
 * Syctl handler for tempesta.state read/write operations.
 */
static int
handle_sysctl_state_io(struct ctl_table *ctl, int is_write,
		       void __user *user_buf, size_t *lenp, loff_t *ppos)
{
	int r = 0;

	mutex_lock(&tfw_cfg_sysctl_state_buf_mtx);

	if (is_write) {
		char new_state_buf[ctl->maxlen];
		char *new_state, *old_state;
		size_t copied_data_len;

		copied_data_len = min((size_t)ctl->maxlen, *lenp);
		r = strncpy_from_user(new_state_buf, user_buf, copied_data_len);
		if (r < 0)
			goto out;

		new_state_buf[r] = 0;
		new_state = strim(new_state_buf);
		old_state = ctl->data;

		r = handle_state_change(old_state, new_state);
		if (r)
			goto out;
	}

	r = proc_dostring(ctl, is_write, user_buf, lenp, ppos);
out:
	mutex_unlock(&tfw_cfg_sysctl_state_buf_mtx);
	return r;
}

static struct ctl_table_header *tfw_cfg_sysctl_hdr;
static struct ctl_table tfw_cfg_sysctl_tbl[] = {
	{
		.procname	= "state",
		.data		= tfw_cfg_sysctl_state_buf,
		.maxlen		= sizeof(tfw_cfg_sysctl_state_buf) - 1,
		.mode		= 0644,
		.proc_handler	= handle_sysctl_state_io,
	},
	{}
};

int
tfw_cfg_if_init(void)
{
	tfw_cfg_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta",
						 tfw_cfg_sysctl_tbl);
	if (!tfw_cfg_sysctl_hdr) {
		TFW_ERR("can't register sysctl table\n");
		return -1;
	}

	return 0;
}

/**
 * The global shutdown routine: stop and un-register all modules,
 * and then un-register the sysctl interface.
 */
void
tfw_cfg_if_exit(void)
{
	TfwCfgMod *mod, *tmp;

	TFW_DBG2("stopping and unregistering all cfg modules...\n");

	if (tfw_cfg_mods_are_started)
		tfw_cfg_stop_mods(&tfw_cfg_mods);

	list_for_each_entry_safe_reverse(mod, tmp, &tfw_cfg_mods, list) {
		tfw_cfg_mod_unregister(mod);
	}
	unregister_net_sysctl_table(tfw_cfg_sysctl_hdr);
}

/**
 * Add @mod to the global list of registered modules and call @mod->init.
 *
 * After the registration the module starts receiving start/stop/setup/cleanup
 * events and configuration updates.
 */
int
tfw_cfg_mod_register(TfwCfgMod *mod)
{
	BUG_ON(!mod || !mod->name);

	TFW_DBG2("register cfg: %s\n", mod->name);

	if (tfw_cfg_mods_are_started) {
		TFW_ERR("can't register module: %s - Tempesta FW is running\n",
			mod->name);
		return -EPERM;
	}

	write_lock(&cfg_mods_lock);

	INIT_LIST_HEAD(&mod->list);
	list_add_tail(&mod->list, &tfw_cfg_mods);

	write_unlock(&cfg_mods_lock);

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_mod_register);

/**
 * Remove the @mod from the global list and call the @mod->exit callback.
 */
void
tfw_cfg_mod_unregister(TfwCfgMod *mod)
{
	BUG_ON(!mod || !mod->name);

	TFW_DBG2("unregister cfg: %s\n", mod->name);

	/* We can't return an error code here because the function may be called
	 * from a module_exit() routine that shall not fail.
	 * Also we can't produce BUG() here because it may hang the system on
	 * forced module removal. */
	WARN(tfw_cfg_mods_are_started,
	     "Module '%s' is unregistered while Tempesta FW is running.\n"
	     "Other modules may still reference this unloaded module.\n"
	     "This is dangerous. Continuing with fingers crossed...\n",
	     mod->name);

	write_lock(&cfg_mods_lock);

	list_del(&mod->list);

	write_unlock(&cfg_mods_lock);

	if (tfw_cfg_mods_are_started) {
		mod_stop(mod);
		spec_cleanup(mod->specs);
	}
}
EXPORT_SYMBOL(tfw_cfg_mod_unregister);

TfwCfgMod *
tfw_cfg_mod_find(const char *name)
{
	TfwCfgMod *mod;

	read_lock(&cfg_mods_lock);

	list_for_each_entry(mod, &tfw_cfg_mods, list) {
		if (!name || !strcasecmp(name, mod->name)) {
			read_unlock(&cfg_mods_lock);
			return mod;
		}
	}

	read_unlock(&cfg_mods_lock);

	return NULL;
}
