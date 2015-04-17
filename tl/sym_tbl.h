/**
 *		Tempesta Language
 *
 * Symbols table.
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
#ifndef __SYM_TBL_H__
#define __SYM_TBL_H__

#include <map>

namespace tl {

class Symbol {
};

class SymTbl {
public:
	SymTbl() noexcept
		: parent_(NULL) // global symbol table by default
	{}

	~SymTbl() noexcept
	{
		for (auto &s: tbl_)
			delete s.second;
	}

	void
	add(std::string &name) noexcept
	{
		tbl_[name] = new Symbol;
	}

	// TODO control reserved words. Also for functions.
	Symbol *
	lookup(std::string &name) noexcept
	{
		Symbol *s;

		// Lookup in current and all enclosing evironments.
		for (SymTbl *t = this; t; t = t->parent_) {
			auto is = t->tbl_.find(name);
			if (is != t->tbl_.end())
				return is->second;
		}
		s = new Symbol;

		// Creat the symbol in local env.
		tbl_[name] = s;

		return s;
	}

private:
	SymTbl				*parent_;
	std::map<std::string, Symbol *>	tbl_;
};

} // namespace tl

#endif // __SYM_TBL_H__
