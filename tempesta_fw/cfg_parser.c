/**
 *		Tempesta FW
 *
 * The parser is a piece of code that transforms plain-text configuration to
 * a tree of TfwCfgNode objects containing all parsed configuration entities
 * (see cfg_node.c for the TfwCfgNode description).
 *
 * 1. Basic language structure
 * ===========================
 *
 * In order better describe what the configuration syntax is,
 * pick an example of an nginx-like configuration:
 *   http {
 *        index index.html index.htm index.php;
 *
 *        server {
 *            listen 80;
 *            name example1.com;
 *        }
 *
 *        upstream us {
 *            server 127.0.0.3:8000 weight=5;
 *            server 192.168.0.1:8000;
 *        }
 *
 *        server {
 *            listen 80;
 *            name example2.com;
 *
 *            location / {
 *                proxy_pass http://us;
 *            }
 *        }
 *   }
 *
 * Here we have:
 *   - A tree of sub-sections: http, http.server, http.server.location, etc.
 *   - A list of values: "index index.html index.htm index.php;"
 *   - A key-value pair: "server ... weight=5;"
 *
 * We generalize all this things and represent the configuration text to a
 * giant tree of nodes with their attributes and values like this:
 *
 *   node1_name  value1 value2 value3  attr1=val1 attr2=val2  {
 *       child1 42;
 *       child2 is_foo=true;
 *       child3 {
 *           sub_child1;
 *           sub_child2;
 *           ...
 *       }
 *   }
 *
 * The top-level node has the following "fields":
 *   - name: node1_name;
 *   - values: value1 value2 value3
 *   - attributes: attr1=val1 attr2=val2
 *   - children: child1, child2 child3
 * Every field except the name is optional.
 *
 * So the parser maps such a text entity into a single TfwCfgNode structure.
 * The structure has all the corresponding "fields": name, values, attributes
 * and children nodes. Refer to the cfg_node.c file for the documentation.
 *
 *
 * 2. Tokens and literals
 * ======================
 *
 * During the parsing, the input stream is split into a sequence of tokens.
 * Tokens are separated by spaces or special characters like quotes, semicolons
 * and curly braces.
 *
 * Tokens are divided into two major parts: literal end everything else.
 * A literal is a special token that carries an in-place value.
 * Non-literal tokens are special syntax characters that don't have any
 * particular value.
 * Examples:
 *   - Literals: foo 42 "a quoted string" true 10.1.100.112
 *   - Non-literals: { } # ; =
 *
 * At this point, the following literals are supported:
 *  1. string:
 *      a. simple_word
 *      b. string\ with\ escaped\ special\ characters\{\}
 *      c. "a string enclosed into double quotes"
 *  2. integer:
 *      a. 42
 *      b. -42
 *      c. 0xDEADBEEF
 *      d. 0b0010011011  (yes, we do support the binary base)
 *  3. boolean:
 *      one of:  true false on off yes no enable disable 1 0
 *  4. address:
 *      a. 127.0.0.1
 *      b. 127.0.0.1:8081
 *      c. :8081
 *      d. [0000:0000:0000:0000:0000:0000:0000:0001]:8081
 *      e. [::1]:8081
 *
 * Yes, we support IP addresses as a separate class of literals, we parse them
 * and give ready-to-use TfwAddr structures to higher-level modules.
 * That is done because IP addresses are quite common in a configuration of
 * a networking-related project like the Tempesta FW.
 *
 * There are two notable things about types of literals:
 *  1. We emulate dynamic typing.
 *     The TfwCfgVal carries information about type of the parsed literal.
 *  2. We parse each literal to all possible instances.
 *     For example, "42" will be parsed both as an integer and as a string.
 *     All the parsed instances are stored in the TfwCfgVal structure.
 * That is done because the parser is made simple and it doesn't take any
 * parsing rules from higher-level modules. At this level we simply don't know
 * how "42" will be interpreted, so we parse it to all possible representations.
 *
 *
 * 3. Parser code
 * ======================
 *
 * The parser code is based on finite-state automation idea.
 * There are two FSMs here: TFSM (tokenizer) and PFSM (parser).
 *
 * The TFSM takes a stream of characters as input and produces tokens.
 * The parser is quite simple, there is no preprocessing and derivation, so the
 * tokenizer handles some extra stuff like eating whitespace and handling quoted
 * strings and escaped characters.
 *
 * The PFSM constructs a tree of TfwCfgNode objects from the stream of tokens
 * produced by the TFSM. It uses recursion to handle nested nodes. This is not
 * quite push-down automation, more like a hybrid of FSM approach and C code.
 *
 * Both FSMs are implemented as functions: read_next_token() and parse_node()
 * with a bunch of macros that hide FSM implementation details. Both are closely
 * related to each other, they share the same state and the most of the code.
 * Both use the goto-based FSM approach which is used for cleaner coding rather
 * than performance here. The parser code runs only once during the life cycle
 * of Tempesta FW application, so pefromance is not required here.
 *
 * Beside FSMs, there is a bunch of helper routines for parsing particular
 * literal types (tfw_cfg_parse_int(), tfw_cfg_parse_bool(), etc).
 *
 * An entry point to the parser is: tfw_cfg_parse().
 *
 *
 * TODO:
 *   - "include" directives
 *   - Passing binary data through the configuration (do we need this?).
 *   - References within the configuration file (useful, but a bit complex).
 *   - Size units: 10MB/4KiB/1G/etc  (useful for things like cache_size).
 *   - Time units: 1ms/20ns/1min/etc (useful for timeouts, etc).
 *   - Better error reporting (file/line/etc, useful for system administrators).
 *   - Careful error checking: in some places errors are ignored or BUG()s are
 *     produced instead of reporting errors to the user.
 *
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
#include <linux/string.h>

#include "cfg_parser.h"
#include "cfg_private.h"


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
DEBUG_EXPORT_SYMBOL(tfw_cfg_parse_int);

int
tfw_cfg_parse_bool(const char *str, bool *out_bool)
{
	bool is_true  = !strcasecmp(str, "1")
	              || !strcasecmp(str, "y")
	              || !strcasecmp(str, "on")
	              || !strcasecmp(str, "yes")
	              || !strcasecmp(str, "true")
	              || !strcasecmp(str, "enable");

	bool is_false  = !strcasecmp(str, "0")
	               || !strcasecmp(str, "n")
	               || !strcasecmp(str, "off")
	               || !strcasecmp(str, "no")
	               || !strcasecmp(str, "false")
	               || !strcasecmp(str, "disable");

	*out_bool = is_true;
	BUG_ON(is_true && is_false);

	return (!is_true && !is_false) ? -EINVAL : 0;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_parse_bool);

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
DEBUG_EXPORT_SYMBOL(tfw_cfg_parse_addr);

/*
 * ------------------------------------------------------------------------
 *	Configuration parser - tokenizer and parser FSMs
 * ------------------------------------------------------------------------
 *
 * Basic terms used in this code:
 *   - STATE
 *   - JMP  - change FSM state without reading input character or tokens.
 *   - MOVE - change state and read input character or token.
 *   - SKIP - read input character/token and re-enter the current state.
 *   - COND_JMP/COND_MOVE/COND_SKIP/etc - do it if the given condition is true.
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
	const char *in;	     /* The whole input buffer. */

	/* Current FSM state is saved to here. */
	const void *fsm_s;   /* Pointer to label (GCC extension). */
	const char *fsm_ss;  /* Label name as string (for debugging). */

	TfwCfgNode *n;	 /* Currently processed node. */
	const char *pos; /* Current position in the @in buffer. */

	/* Literal value (only not NULL when @t == TOKEN_LITERAL). */
	const char *lit;
	const char *prev_lit;

	/* Length of @lit (the @lit is not terminated). */
	int lit_len;
	int prev_lit_len;

	 /* Currently/previously processed token. */
	token_t t;
	token_t prev_t;

	/* Currently/previously processed character. */
	char c;
	char prev_c;

	/* A temporary buffer where we can terminate @lit to make a string
	 * for node or attribute name operations. */
	char name[TFW_CFG_NAME_MAX_LEN];
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
	TfwCfgVal *v = tfw_cfg_val_alloc(len);
	const char *s = v->val_str;

	/* Literal value as is - always available. */
	v->mask |= TFW_CFG_VAL_str;
	memcpy(v->val_str, literal, len);

	/* Others depend on whether the literal value may be parsed to a
	 * particular representation. */
	v->mask |= TFW_CFG_VAL_int  * !tfw_cfg_parse_int(s, &v->val_int);
	v->mask |= TFW_CFG_VAL_bool * !tfw_cfg_parse_bool(s, &v->val_bool);
	v->mask |= TFW_CFG_VAL_addr * !tfw_cfg_parse_addr(s, &v->val_addr);

	return v;
}

static void
copy_and_term_literal(char *dest_buf, size_t buf_size,
		      const char *literal, size_t lit_len)
{
	size_t len = min((buf_size - 1), lit_len);
	memcpy(dest_buf, literal, len);
	dest_buf[len] = '\0';
}

TfwCfgNode *
parse_node(ParserState *ps)
{
	/* Read a token for a freshly initialized state. */
	if (!ps->t)
		PFSM_MOVE(PS_START_NEW_NODE);

	/* Don't read a token on recursion (ps->t is set by the caller). */
	FSM_JMP(PS_START_NEW_NODE);

	FSM_STATE(PS_ERROR) {
		const char *start = max((ps->pos - 80), ps->in);
		int len = ps->pos - start;

		/* TODO: verbose error messages. */
		ERR("syntax error: \n%.*s  <-- error here\n", len, start);

		tfw_cfg_node_free(ps->n);
		ps->n = NULL;

		return NULL;
	}

	FSM_STATE(PS_START_NEW_NODE) {
		copy_and_term_literal(ps->name, sizeof(ps->name),
				      ps->lit, ps->lit_len);
		FSM_DBG("create new node: %s\n", ps->name);

		ps->n = tfw_cfg_node_alloc(ps->name);
		FSM_COND_JMP(!ps->n, PS_ERROR);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	/* The name was easy.
	 * Now we have a situation where at current position we don't know
	 * whether we have a value or an attribute:
	 *     name attr = value;
	 *          ^
	 *          current position here
	 *
	 * An implementation of peek_token() would be tricky here because the
	 * TFSM is not pure, it alters the current state. So instead of looking
	 * forward, we move to the next position and look to the '=' sign:
	 * if it is there - then we treat previous value as an attribute name,
	 * otherwise we save it as a value of the current node.
	 */

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
		int r;

		TfwCfgVal *v = parse_literal(ps->prev_lit, ps->prev_lit_len);
		FSM_DBG("add value: %s (type mask: %#x)\n", v->val_str, v->mask);

		r = tfw_cfg_nval_add(ps->n, v);
		FSM_COND_JMP(r, PS_ERROR);

		FSM_JMP(PS_VAL_OR_ATTR);
	}

	FSM_STATE(PS_STORE_ATTR_PREV) {
		TfwCfgVal *val;
		int r;

		copy_and_term_literal(ps->name, sizeof(ps->name),
				      ps->prev_lit, ps->prev_lit_len);

		/* Current position is the '=' sign, so skip it. */
		read_next_token(ps);

		val = parse_literal(ps->lit, ps->lit_len);
		FSM_DBG("set attr: %s = %s\n", ps->name, val->val_str);

		r = tfw_cfg_nattr_set(ps->n, ps->name, val);
		FSM_COND_JMP(r, PS_ERROR);

		PFSM_MOVE(PS_VAL_OR_ATTR);
	}

	/* Children are easy: we just call parse_node() recursively while there
	 * are literals (say node names) between the curly braces: { }.
	 *
	 * The recursive call of parse_node() parses exactly one node starting
	 * from the current position, and when it exits, it automatically leaves
	 * the ParserState at a position of the next node, so all what we need
	 * to do - is call parse_node() again until we reach the '}' token.
	 */

	FSM_STATE(PS_CHILDREN) {
		FSM_COND_JMP(ps->t == TOKEN_RBRACE, PS_FINISH_NODE);
		FSM_COND_JMP(ps->t == TOKEN_LITERAL, PS_PARSE_CHILD_RECURSIVELY);
		FSM_JMP(PS_ERROR);
	}

	FSM_STATE(PS_PARSE_CHILD_RECURSIVELY) {
		int r;
		TfwCfgNode *parent, *child;

		FSM_DBG("parse child: %.*s\n", ps->lit_len, ps->lit);

		parent = ps->n;
		child = parse_node(ps);
		ps->n = parent;

		if (child)
			r = tfw_cfg_nchild_add(parent, child);

		FSM_COND_JMP(!child || r, PS_ERROR);
		FSM_DBG("done child: %s\n", child->name);
		FSM_DBG("continue parent: %s\n", ps->n->name);

		FSM_JMP(PS_CHILDREN);
	}

	FSM_STATE(PS_FINISH_NODE) {
		read_next_token(ps); /* eat ';' or '}' */

		return ps->n;
	}
}

/**
 * A shortcut for parsing a single node contained in @cfg_text.
 *
 * Unlike fw_cfg_parse(), this function doesn't parse a sequence
 * of nodes and doesn't create a fake root element to host these nodes.
 */
TfwCfgNode *
tfw_cfg_parse_single_node(const char *cfg_text)
{
	ParserState ps = {
		.in = cfg_text,
		.pos = cfg_text,
	};

	return parse_node(&ps);
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_parse_single_node);

/**
 * Parse plain configuration text to a tree of TfwCfgNode objects.
 *
 * The input text may contain many sequential nodes, like this:
 *
 *     node1 foo;
 *     node2 {
 *       bar;
 *     }
 *     node3 {
 *       baz;
 *     }
 *
 * But the function is supposed to return a single tree (we are not going to
 * complicate things and work with forests). To solve the problem, the function
 * creates a dummy node called "root", so the output tree would look like this:
 *
 *  root
 *   |-- node1
 *   |-- node2
 *   |     |-- bar
 *   |-- node3
 *   |     |-- baz
 *
 *
 * The returned node must be freed using the tfw_cfg_node_free().
 */
TfwCfgNode *
tfw_cfg_parse(const char *cfg_text)
{
	ParserState ps = {
		.in = cfg_text,
		.pos = cfg_text,
	};

	TfwCfgNode *root, *node;

	root = tfw_cfg_node_alloc("root");

	if (!*cfg_text)
		return root;

	do {
		node = parse_node(&ps);
		if (node)
			tfw_cfg_nchild_add(root, node);
	} while (node && ps.t);

	return root;
}
DEBUG_EXPORT_SYMBOL(tfw_cfg_parse);

