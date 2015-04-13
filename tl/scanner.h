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
#ifndef __SCANNER_H__
#define __SCANNER_H__

#if !defined(yyFlexLexerOnce)
#include <FlexLexer.h>
#endif

#undef YY_DECL
#define YY_DECL int tl::FlexScanner::yylex()

#include "parser.h"

namespace tl {

class FlexScanner : public yyFlexLexer {
public:
	// save the pointer to yylval so we can change it, and invoke scanner
	int
	yylex(tl::BisonParser::semantic_type * lval)
	{
		yylval = lval;
		return yylex();
	}

private:
	// Scanning function created by Flex; make this private to force usage
	// of the overloaded method so we can get a pointer to Bison's yylval
	int yylex();

	// point to yylval (provided by Bison in overloaded yylex)
	tl::BisonParser::semantic_type *yylval;
};

} // namespace tl

#endif // __SCANNER_H__
