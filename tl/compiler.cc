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
#include <iostream>
#include <sstream>

#include <boost/assert.hpp>

#include "compiler.h"

namespace tl {

Compiler::Compiler(bool debug) noexcept
	: parser_(scanner_, ast_root_, st_)
{
	if (debug) {
		scanner_.set_debug(1);
#ifdef YYDEBUG
		parser_.set_debug_level(1);
#endif
	}
}

void
Compiler::parse(std::string &program)
{
	std::istringstream iss(program);

	scanner_.switch_streams(&iss);

	parser_.parse();
}

/**
 * Recursively print all AST nodes.
 * We use recursion since the nodes don't have pointers to parent.
 */
void
Compiler::ast_node_print(const Expr *node, int lvl) noexcept
{
	if (!node)
		return;

	for (auto l = 0; l < lvl; ++l)
		std::cout << "  ";
	std::cout << node << std::endl;

	if (node->type_ == TL_FUNC) {
		BOOST_ASSERT(node->left_ && !node->right_);
		ast_node_print(node->left_, lvl + 1);
		for (auto &a: node->args_)
			ast_node_print(a, lvl + 1);
	} else {
		BOOST_ASSERT(node->args_.empty());
		ast_node_print(node->left_, lvl + 1);
		ast_node_print(node->right_, lvl + 1);
	}
}

void
Compiler::ast_print() noexcept
{
	std::cout << "Parsed AST (left branches are on top):" << std::endl;

	for (auto n: ast_root_.expr_l_)
		ast_node_print(n, 0);
}

} // namespace tl
