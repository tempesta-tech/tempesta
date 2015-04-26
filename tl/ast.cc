/**
 *		Tempesta Language
 *
 * Implementation of functions used to build the syntax tree.
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
#include <arpa/inet.h>

#include "ast.h"
#include "exception.h"

namespace tl {

Expr *
Expr::set_str(const char *str) noexcept
{
	str_ = str;
	return this;
}

Expr *
Expr::set_val(long val) noexcept
{
	value_ = val;
	return this;
}

Expr *
create_number(long value) noexcept
{
	return (new Expr(TL_LONGINT))->set_val(value);
}

Expr *
create_str(tl_term_t type, const char *str) noexcept
{
	return (new Expr(type))->set_str(str);
}

Expr *
create_identifier(const char *name, Symbol *s) noexcept
{
	return (new Expr(TL_IDENT, nullptr, nullptr, s))->set_str(name);
}

Expr *
create_ipv4(const char *addr)
{
	Expr *e = new Expr(TL_IPV4);
	struct sockaddr_in v4;

	if (!inet_pton(AF_INET, addr, &v4.sin_addr))
		throw TfwExcept("invalid IPv4 address: %s", addr);
	e->value_ = v4.sin_addr.s_addr;

	return e;
}
 
Expr *
create_op(tl_term_t type, Expr *left, Expr *right) noexcept
{
	return new Expr(type, left, right);
}

Expr *
create_func(const char *name, Expr::FArgs &args) noexcept
{
	Expr *e = new Expr(TL_FUNC);

	e->set_str(name);
	e->args_ = std::move(args);

	return e;
}

std::ostream&
operator<<(std::ostream& os, const Expr *expr) noexcept
{
	switch (expr->type_) {
	case TL_IDENT:
	case TL_FUNC:
	case TL_STR:
	case TL_REGEX:
		os << expr->str_;
		break;
	case TL_LONGINT:
	case TL_IPV4:
		os << "'" << expr->value_ << "'";
		break;
	case TL_DEREF:
		os << ".";
		break;
	case TL_EQ:
		os << "==";
		break;
	case TL_NEQ:
		os << "!=";
		break;
	case TL_REEQ:
		os << "=~";
		break;
	case TL_RENEQ:
		os << "!~";
		break;
	case TL_GT:
		os << ">";
		break;
	case TL_GE:
		os << ">=";
		break;
	case TL_LT:
		os << "<";
		break;
	case TL_LE:
		os << "<=";
		break;
	case TL_AND:
		os << "&&";
		break;
	case TL_OR:
		os << "||";
		break;
	case TL_IF:
		os << "if";
		break;
	default:
		os << "[undef]";
	}

	return os;
}

} // namespace tl
