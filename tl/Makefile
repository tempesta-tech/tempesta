#		Tempesta Language
#
# Copyright (C) 2015 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

CXX		= g++
LEX		= flex++
YACC		= bison
# Use gnu++11 instead of c++11 for standard C header compatibility.
CFLAGS		= -O2 -std=gnu++11 -ggdb -Wall
LDFLAGS		= -lboost_program_options
INCLUDES	= -I../lib

OBJECTS		= ast.o compiler.o lexer.o main.o parser.o

all : gen_parser tl

gen_parser: lexer.ll parser.yy
	$(LEX) lexer.ll
	$(YACC) -v parser.yy

tl: $(OBJECTS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

lexer.o: lexer.cc
	$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

parser.o: parser.cc
	$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cc
	$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean: FORCE
	rm -f *.o* *~ tl lexer.h lexer.cc parser.cc parser.h stack.hh

FORCE:

