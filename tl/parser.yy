%{
/**
 *		Tempesta Language
 *
 * TL parser and grammar definition.
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
#include "ast.h"
#include "exception.h"
#include "sym_tbl.h"
%}
 
%require "3.0.0"
%skeleton "lalr1.cc"
%output "parser.cc"
%defines "parser.h"
%define api.namespace { tl }
%define parser_class_name { BisonParser }
%parse-param { tl::FlexScanner &scanner }
%parse-param { tl::AST *ast }
%parse-param { tl::SymTbl &st }

%code requires {
	namespace tl {
		class FlexScanner;
	}
}

%code {
	static int yylex(tl::BisonParser::semantic_type * yylval,
			 tl::FlexScanner &scanner);
}

%union {
	long		value;
	std::string	str;
	tl::Expr	*expr;
}

%left "||"
%left "&&"
%nonassoc "==" "!="
%nonassoc '>' '<' ">=" "<="
%nonassoc "=~" "!~"
%left '.' '(' ')'
 
%token <str> IDENT
%token <str> IPV4
%token <value> LONGINT
%token <str> STR
%token <str> REGEX
%token IF
 
%type <expr> stmt expr
%type <tl::Expr::FAgrs> args
 
%%
 
program:
	stmt
		{ ast->push_expr($1); }
	| program stmt
		{ ast->push_expr($2); }
	;

stmt:
	expr ';'
		{ $$ = $1; }
	| "if" '(' expr ')' stmt
		{ $$ = create_op(TL_IF, $3, $5); }
	| STR '(' ')'
		{ $$ = create_func($1, NULL); }
	| STR '(' args ')'
		{ $$ = create_func($1, $3); }
	;

args:
	expr
		{
			$$ = FArgs();
			$$.push_back($1);
		}
	| args ',' expr
		{
			FArgs &args = $1;
			args.push_back($3);
			$$ = args;
		}
	;
	
expr:
	IDENT
		{ $$ = create_identifier($1, st->lookup($1)); }
	| LONGINT
		{ $$ = create_number($1); }
	| IPV4
		{ $$ = create_ipv4($1); }
	| STR
		{ $$ = create_str(TL_STR, $1); }
	| REGEX
		{ $$ = create_str($1); }
	| expr '.' expr
		{ $$ = create_op(TL_DEREF, $1, $3); }
	| expr "==" expr
		{ $$ = create_op(TL_EQ, $1, $3); }
	| expr "!=" expr
		{ $$ = create_op(TL_NEQ, $1, $3); }
	| expr "=~" expr
		{ $$ = create_op(TL_REEQ, $1, $3); }
	| expr "!~" expr
		{ $$ = create_op(TL_RENEQ, $1, $3); }
	| expr '>' expr
		{ $$ = create_op(TL_GT, $1, $3); }
	| expr ">=" expr
		{ $$ = create_op(TL_GE, $1, $3); }
	| expr '<' expr
		{ $$ = create_op(TL_LT, $1, $3); }
	| expr "<=" expr
		{ $$ = create_op(TL_LE, $1, $3); }
	| '(' expr ')'
		{ $$ = $2; }
	;
 
%%

void
tl::BisonParser::error(const tl::BisonParser::location_type &loc,
		       const std::string &msg)
{
	throw TfwExcept("%d: %u:%u %u:%u %s", yylineno,
			loc.begin.line, loc.begin.column,
			loc.end.line, loc.end.column,
			msg.c_str());
}

#include "scanner.h"

static int
yylex(tl::BisonParser::semantic_type * yylval, tl::FlexScanner &scanner)
{
	return scanner.yylex(yylval);
}
