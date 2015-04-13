/**
 *		Tempesta Language
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
#ifndef __COMPILER_H__
#define __COMPILER_H__

#include <string>

#include "ast.h"
#include "sym_tbl.h"
#include "scanner.h"

namespace tl {

class Compiler {
public:
	Compiler(bool debug) noexcept;

	void parse(std::string &program);
	void ast_print() noexcept;

private:
	void ast_node_print(const Expr *node, int lvl) noexcept;

private:
	AST		ast_root_;
	SymTbl		st_;
	FlexScanner	scanner_;
	BisonParser	parser_;
};

} // namespace tl

#endif // __COMPILER_H__
