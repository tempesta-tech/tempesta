/**
 *		Tempesta Language
 *
 * Definition of the structure used to build the syntax tree.
 *
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
#ifndef __AST_H__
#define __AST_H__

#include <iostream>
#include <list>
#include <vector>

#include "sym_tbl.h"

namespace tl {

typedef enum {
	TL_IDENT,	// identifier

	TL_LONGINT,	// 64bit integer
	TL_IPV4,	// IPv4 address
	TL_STR,		// string
	TL_REGEX,	// regexp/string matcher

	TL_DEREF,	// '.' structure member dereference
	TL_LPAREN,	// (
	TL_RPAREN,	// )
	TL_EQ,		// ==
	TL_NEQ,		// !=
	TL_REEQ,	// =~
	TL_RENEQ,	// !~
	TL_GT,		// >
	TL_GE,		// >=
	TL_LT,		// <
	TL_LE,		// <=
	TL_AND,		// &&
	TL_OR,		// ||

	TL_IF,		// if statement
	TL_FUNC,	// function call

	TL_EOS,		// ; End Of Statement

	TL_UNDEF
} tl_term_t;
 
/**
 * Expression structure.
 * This one works as AST node.
 */
struct Expr {
	typedef std::vector<Expr *> FArgs;

	Expr(tl_term_t t = TL_UNDEF, Expr *l = nullptr, Expr *r = nullptr,
	     Symbol *s = nullptr) noexcept
		: type_(t),
		left_(l),
		right_(r),
		sym_(s)
	{}

	~Expr() noexcept
	{
		delete left_;
		delete right_;
		for (auto &a: args_)
			delete a;
	}

	Expr *set_str(const std::string &str) noexcept;
	Expr *set_val(long v) noexcept;

	tl_term_t	type_;		// type of AST node
	Expr		*left_;		// left side of the tree
	Expr		*right_;	// right side of the tree
	Symbol		*sym_;		// the entry in symbol table
	long		value_;
	std::string	str_;
	FArgs		args_;		// function args, block statemets etc
};
 
Expr *create_number(long value) noexcept;
Expr *create_str(tl_term_t type, const std::string &str) noexcept;
Expr *create_identifier(const std::string &name, Symbol *s) noexcept;
Expr *create_ipv4(const std::string  &addr);
Expr *create_op(tl_term_t type, Expr *left, Expr *right) noexcept;
Expr *create_deref(Expr *ident, const std::string &member) noexcept;
Expr *create_func_noargs(Expr *ident) noexcept;
Expr *create_func(Expr *ident, Expr::FArgs &args) noexcept;

std::ostream& operator<<(std::ostream& os, const Expr *expr);

// Currently just a sequence of statements.
struct AST {
	void
	push_expr(Expr *e) noexcept
	{
		expr_l_.push_back(e);
	}

	std::list<Expr *>	expr_l_;
};

} // namespace tl

#endif // __AST_H__
