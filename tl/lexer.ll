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

#define pt tl::BisonParser::token

char str_buf[256], *str;
int yylineno;
%}

%option outfile="lexer.cc" header-file="lexer.h"
%option yyclass="FlexScanner"
%option noyywrap nodefault c++
%option yylineno
%option debug

WS		[ \r\n\t]*
COMMENT		#.*
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
			return pt::LONGINT;
		}

{IPV4}		{
			yylval->build<std::string>() = yytext;
			return pt::IPV4;
		}

	/* Process strings with escaped symbols. */
\"		{
			BEGIN STRING;
			str = str_buf;
		}
<STRING>\\n	{ *str++ = '\n'; }
<STRING>\\t	{ *str++ = '\t'; }
<STRING>\\\"	{ *str++ = '\"'; }
<STRING>\"	{
			*str = 0;
			yylval->build<std::string>() = str_buf;
			BEGIN 0;
			return pt::STR;
		}
<STRING>\n	{ throw TfwExcept("bad string [%s]", yytext); }
<STRING>.	{ *str++ = *yytext; }

	/* Process regular expressions with escaped symbols. */
\/		{
			BEGIN REGEX;
			str = str_buf;
		}
<REGEX>\\n	{ *str++ = '\n'; }
<REGEX>\\t	{ *str++ = '\t'; }
<REGEX>\\\"	{ *str++ = '\"'; }
<REGEX>\/i?	{
			if (!strcmp(yytext, "/i")) {
				*str++ = '/';
				*str++ = 'i';
			}
			*str = 0;
			yylval->build<std::string>() = str_buf;
			BEGIN 0;
			return pt::RE;
		}
<REGEX>\n	{ throw TfwExcept("bad regexp [%s]", yytext); }
<REGEX>.	{ *str++ = *yytext; }

[.,()><;]	{ return *yytext; }
"=="		{ return pt::EQ; }
"!="		{ return pt::NEQ; }
"=~"		{ return pt::REEQ; }
"!~"		{ return pt::RENEQ; }
">="		{ return pt::GE; }
"<="		{ return pt::LE; }
"&&"		{ return pt::AND; }
"||"		{ return pt::OR; }

"if"		{ return pt::IF; }

{IDENT}		{
			yylval->build<std::string>() = yytext;
			return pt::IDENT;
		}

.		{ throw TfwExcept("unknown character [%s]", yytext); }

