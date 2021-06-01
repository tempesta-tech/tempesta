#		Tempesta DB User-space Library
#
# Copyright (C) 2015 Tempesta Technologies.
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
# Use gnu++11 instead of c++11 for standard C header compatibility.
CFLAGS		= -O2 -ggdb -Wall
LDFLAGS		= -shared -fPIC
INCLUDES	= -I../core

OBJECTS	= handler.o

all : libtdb.so

libtdb.so: $(OBJECTS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.cc
	$(CXX) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -c $< -o $@

clean: FORCE
	rm -f *.o* *~ libtdb.so

FORCE:

