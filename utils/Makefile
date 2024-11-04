#		Tempesta FW
#
# Copyright (C) 2024 Tempesta Technologies, Inc.
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

CXX := g++
LDFLAGS := -lclickhouse-cpp-lib
PAGE_SIZE := $(shell getconf PAGE_SIZE)
CXXFLAGS := -O3 -Wall -Wextra -std=c++23 -DPAGE_SIZE=$(PAGE_SIZE)
SRCS := tfw_logger.cc mmap_buffer.cc clickhouse.cc
OBJS := $(SRCS:.cc=.o)
TARGET := tfw_logger

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
