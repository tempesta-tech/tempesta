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

#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
#include <linux/string.h>

#include "lib.h"
#include "log.h"
#include "sched_match.h"

#define RULES_TEXT_BUF_SIZE 1024
#define IP_ADDR_TEXT_BUF_SIZE 64

/*
 * The following code is a sysctl interface with a primitive descend parser
 * for the configuration. The code is a bit awkward, it is a subject to change
 * in the near future.
 */

typedef enum {
	TOKEN_NA = 0,
	TOKEN_LBRACE,
	TOKEN_RBRACE,
	TOKEN_STR,
} token_t;

static const char *token_str_tbl[] = {
	[TOKEN_NA] 	= STRINGIFY(TOKEN_NA),
	[TOKEN_LBRACE] 	= STRINGIFY(TOKEN_LBRACE),
	[TOKEN_RBRACE] 	= STRINGIFY(TOKEN_RBRACE),
	[TOKEN_STR] 	= STRINGIFY(TOKEN_STR),
};

const char *
token_str(token_t t)
{
	BUG_ON(t >= ARRAY_SIZE(token_str_tbl));
	return token_str_tbl[t];
}

typedef struct {
	token_t token;
	int len;
	const char *lexeme;
	const char *pos;
	Rule *rule;
	RuleTbl *tbl;
} ParserState;

#define PARSER_ERR(s, ...) \
do { \
	ERR("Parser error: " __VA_ARGS__); \
	ERR("lexeme: %.*s  position: %.80s\n", s->len, s->lexeme, s->pos); \
} while (0)

token_t get_token(ParserState *s)
{
	static const token_t single_char_tokens[] = {
		[0 ... 255] = TOKEN_NA,
		['{'] = TOKEN_LBRACE,
		['}'] = TOKEN_RBRACE,
	};
	const char *p;

	s->token = TOKEN_NA;
	s->lexeme = NULL;
	s->len = 0;
	s->pos = skip_spaces(s->pos);

	if (!s->pos[0])
		goto out;
	s->lexeme = s->pos;

	s->token = single_char_tokens[(u8)s->pos[0]];
	if (s->token) {
		s->pos++;
		s->len = 1;
		goto out;
	}

	if (s->lexeme[0] == '"') {
		for (p = s->pos + 1; *p; ++p) {
			if (*p == '"' && *(p - 1) != '\\') {
				break;
			}
		}
		if (*p == '"') {
			s->lexeme++;
			s->len = (p - s->lexeme);
			s->pos = ++p;
			s->token = TOKEN_STR;
		} else {
			PARSER_ERR(s, "unterminated quote");
		}
	} else {
		for (p = s->pos + 1; *p && !isspace(*p); ++p);
		s->len = (p - s->pos);
		s->pos = p;
		s->token = TOKEN_STR;
	}

out:
	return s->token;
}

static token_t
peek_token(ParserState *s)
{
	ParserState old_state = *s;
	token_t t = get_token(s);
	*s = old_state;

	return t;
}

/*
 * The following functions are trying to mimic something like this:
 *  input   ::= rules
 *  rules   ::= rule rules
 *  rule    ::= subj
 *            | op
 *            | pattern
 *            | LBRACE
 *            | servers
 *            | RBRACE
 *  servers ::= server servers
 *  server  ::= STR
 *  subj    ::= STR
 *  op      ::= STR
 *  pattern ::= STR
 */

#define EXPECT(token, s, action_if_unexpected) 		\
do { 							\
	token_t _t = peek_token(s); 			\
	if (_t != token) { 				\
		PARSER_ERR(s, "Unexpected token: %s (expected %s)\n", \
		              token_str(_t), token_str(token)); \
		action_if_unexpected;			\
	} 						\
} while (0)

#define EXPECT_EITHER(t1, t2, s, action_if_unexpected) 	\
({ 							\
	token_t _t = peek_token(s); 			\
	if (_t != t1 && _t != t2) { 			\
		PARSER_ERR(s, "Unexpected token: %s (expected: %s or %s)\n", \
		              token_str(_t) token_str(t1), token_str(t2)); \
		action_if_unexpected; 			\
	} 						\
	_t; 						\
})

#define IDX_BY_STR(array, str, maxlen)			\
({ 							\
	int _found_idx = 0; 				\
	int _i; 					\
	for (_i = 0; _i < ARRAY_SIZE(array); ++_i) { 	\
		if (!strncmp(str, array[_i], maxlen)) {	\
			_found_idx = _i; 		\
			break; 				\
		} 					\
	} 						\
	_found_idx; 					\
})

static int
parse_subj(ParserState *s)
{
	static const char *subj_str_tbl[] = {
		[SUBJ_NA] 	= STRINGIFY(SUBJ_NA),
		[SUBJ_HOST] 	= "host",
		[SUBJ_URI] 	= "uri",
		[SUBJ_HEADER] 	= "header",
	};
	subj_t subj;

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	subj = IDX_BY_STR(subj_str_tbl, s->lexeme, s->len);
	if (!subj) {
		PARSER_ERR(s, "invalid subject");
		return -1;
	}

	s->rule->subj = subj;

	return 0;
}

static int
parse_op(ParserState *s)
{
	static const char *op_str_tbl[] = {
		[OP_NA] = STRINGIFY(OP_NA),
		[OP_EQUAL] = "=",
		[OP_PREFIX] = "^",
	};
	op_t op;

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	op = IDX_BY_STR(op_str_tbl, s->lexeme, s->len);
	if (!op) {
		PARSER_ERR(s, "invalid operator");
		return -1;
	}

	s->rule->op = op;

	return 0;
}

static int
parse_pattern(ParserState *s)
{
	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	if (s->len >= sizeof(s->rule->pattern)) {
		PARSER_ERR(s, "too long pattern: %.*s", s->len, s->lexeme);
		return -1;
	}

	memcpy(s->rule->pattern, s->lexeme, s->len);
	s->rule->pattern[s->len] = '\0';

	return 0;
}

static int
parse_server(ParserState *s)
{
	int ret = 0;
	TfwAddr *addr;
	char *pos;
	char buf[IP_ADDR_TEXT_BUF_SIZE + 1];

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	if (s->rule->addrs_n >= ARRAY_SIZE(s->rule->addrs)) {
		PARSER_ERR(s, "max number of addresses per rule reached");
		return -1;
	}

	if (s->len >= sizeof(buf)) {
		PARSER_ERR(s, "too long address: %.*s", s->len, s->lexeme);
		return -1;
	}

	memcpy(buf, s->lexeme, s->len);
	buf[s->len] = '\0';
	pos = buf;
	addr = &s->rule->addrs[s->rule->addrs_n++];
	ret = tfw_inet_pton(&pos, addr);

	if (ret) {
		PARSER_ERR(s, "invalid address");
	}

	return ret;
}

static int
parse_servers(ParserState *s)
{
	EXPECT(TOKEN_LBRACE, s, return -1);
	get_token(s);

	while (1) {
		token_t t = peek_token(s);
		if (t == TOKEN_RBRACE) {
			get_token(s);
			return 0;
		} else {
			EXPECT(TOKEN_STR, s, return -1);
			if (parse_server(s))
				return -1;
		}
	}

	return 0;
}

static int
parse_rule(ParserState *s)
{
	return parse_subj(s) || parse_op(s) || parse_pattern(s) || parse_servers(s);
}

static int
parse_rules(ParserState *s)
{
	int ret;

	while (peek_token(s)) {
		if (s->tbl->rules_n >= ARRAY_SIZE(s->tbl->rules)) {
			PARSER_ERR(s, "max number of rules reached");
			return -1;
		}

		s->rule = &s->tbl->rules[s->tbl->rules_n++];

		ret = parse_rule(s);
		if (ret)
			return ret;
	}

	return 0;
}

int run_parser(const char *input, RuleTbl *tbl)
{
	ParserState s = {
		.pos = input,
		.tbl = tbl
	};

	return parse_rules(&s);
}

static int
sysctl_handle_rules(ctl_table *ctl, int write, void __user *user_buf,
                   size_t *lenp, loff_t *ppos)
{
	int ret = 0;
	int len = 0;
	char *buf = NULL;
	RuleTbl *tbl = NULL;

	if (write) {
		buf = kzalloc(ctl->maxlen + 1, GFP_KERNEL);
		tbl = kzalloc(sizeof(*tbl), GFP_KERNEL);
		if (!buf || !tbl) {
			ERR("Can't allocate memory\n");
			ret = -ENOMEM;
			goto out;
		}

		len = min((size_t)ctl->maxlen, *lenp);
		ret = copy_from_user(buf, user_buf, len);
		if (ret) {
			ERR("Can't copy data from user-space\n");
			goto out;
		}

		ret = run_parser(buf, tbl);
		if (ret) {
			ERR("Can't parse input data\n");
			ret = -EINVAL;
			goto out;
		}

		ret = apply_new_rules(tbl);
		if (ret) {
			ERR("Can't apply new matching rules\n");
			goto out;
		}
	}

	ret = proc_dostring(ctl, write, user_buf, lenp, ppos);
	if (!ret)
		goto out;

out:
	kfree(buf);
	kfree(tbl);

	return ret;
}

static char ctl_data[RULES_TEXT_BUF_SIZE];

static ctl_table sched_match_tbl[] = {
	{
		.procname	= "sched_match",
		.data		= ctl_data,
		.maxlen		= RULES_TEXT_BUF_SIZE,
		.mode		= 0644,
		.proc_handler	= sysctl_handle_rules
	},
	{}
};

static struct ctl_table_header *sched_match_ctl;

int
sysctl_register(void)
{
	sched_match_ctl = register_net_sysctl(&init_net, "net/tempesta",
	                                      sched_match_tbl);

	return sched_match_ctl ? 0 : 1;
}

void
sysctl_unregister(void)
{
	unregister_net_sysctl_table(sched_match_ctl);
}
