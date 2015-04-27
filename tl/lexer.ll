%{
/**
 *		Tempesta Language
 *
 * TL lexer.
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
#include <stdlib.h>

#include "ast.h"
#include "exception.h"
#include "scanner.h"

char str_buf[256], *str;
%}

%option outfile="lexer.cc" header-file="lexer.h"
%option yyclass="FlexScanner"
%option noyywrap nodefault c++

WS		[ \r\n\t]*
COMMENT		#.*\n
NUMBER		0|[1-9][0-9]*
IDENT		[a-zA-Z_][a-zA-Z0-9_]*
IPV4		[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}

%x STRING
%x REGEX

%%

{WS}		{ /* Skip whitespaces. */ }
{COMMENT}	{ /* Skip comments. */ }

{NUMBER}	{
			yylval->build<long>() = atol(yytext);
			return tl::TL_LONGINT;
		}

{IPV4}		{
			yylval->build<std::string>() = yytext;
			return tl::TL_IPV4;
		}

	/* Process strings and regular expressions with escaped symbols. */
\"		{
			BEGIN STRING;
			str = str_buf;
		}
<STRING>\\n	{ *str++ = '\n'; }
<STRING>\\t	{ *str++ = '\t'; }
<STRING>\\\"	{ *str++ = '\"'; }
<STRING>\"	{
			*str = 0;
			BEGIN 0;
		}
<STRING>\n	{ throw TfwExcept("bad string [%s]", yytext); }
<STRING>.	{ *str++ = *yytext; }

\/		{
			BEGIN REGEX;
			str = str_buf;
		}
<REGEX>\\n	{ *str++ = '\n'; }
<REGEX>\\t	{ *str++ = '\t'; }
<REGEX>\\\"	{ *str++ = '\"'; }
<REGEX>\/i?	{
			*str = 0;
			BEGIN 0;
		}
<REGEX>\n	{ throw TfwExcept("bad regexp [%s]", yytext); }
<REGEX>.	{ *str++ = *yytext; }

"."		{ return tl::TL_DEREF; }
"("		{ return tl::TL_LPAREN; }
")"		{ return tl::TL_RPAREN; }
"=="		{ return tl::TL_EQ; }
"!="		{ return tl::TL_NEQ; }
"=~"		{ return tl::TL_REEQ; }
"!~"		{ return tl::TL_RENEQ; }
">"		{ return tl::TL_GT; }
">="		{ return tl::TL_GE; }
"<"		{ return tl::TL_LT; }
"<="		{ return tl::TL_LE; }
"&&"		{ return tl::TL_AND; }
"<"		{ return tl::TL_OR; }

"if"		{
			return tl::TL_IF;
		}

{IDENT}		{
			yylval->build<std::string>() = yytext;
			return tl::TL_IDENT;
		}

.		{ throw TfwExcept("unknown character[%s]", yytext); }
