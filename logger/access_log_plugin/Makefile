#		Tempesta FW
#
# Copyright (C) 2024-2025 Tempesta Technologies, Inc.
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

CLICKHOUSE_DIR := ../clickhouse
CLICKHOUSE_LIB := tfw_clickhouse.a

LDFLAGS += $(shell pkgconf --libs spdlog)
LDFLAGS += -rdynamic -ldl

CXX := g++
PAGE_SIZE := $(shell getconf PAGE_SIZE)
CXXFLAGS := -Wall -Wextra -std=c++23 -march=native -mtune=native \
	    -DPAGE_SIZE=$(PAGE_SIZE) -fPIC

CXXFLAGS += $(shell pkgconf -cflags spdlog)
CXXFLAGS += -I $(CLICKHOUSE_DIR)/clickhouse-cpp
CXXFLAGS += -I $(CLICKHOUSE_DIR)/clickhouse-cpp/contrib/absl

OBJS := $(patsubst %.cc, %.o, $(wildcard *.cc))
TARGET := access_log.so

DEBUG ?= 0
ifeq ($(DEBUG), 0)
	CXXFLAGS += -O3 -DNDEBUG -s
else
	CXXFLAGS += -DDEBUG=1 -O0 -ggdb3
endif

all: $(TARGET)

# We don't want to worry about compatibility, so just link ClickHouse statically.
# But we need to pass CXXFLAGS to build clickhouse with our building flags.
$(CLICKHOUSE_LIB):
	$(MAKE) -C $(CLICKHOUSE_DIR) TARGET_DIR=$(abspath .) CXXFLAGS="$(CXXFLAGS)" -j$(shell nproc)

$(TARGET): $(CLICKHOUSE_LIB) $(OBJS)
	$(CXX) -shared $(CXXFLAGS) -o $@ $(OBJS) $(CLICKHOUSE_LIB) $(LDFLAGS)

%.o: %.cc $(CLICKHOUSE_LIB)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	$(MAKE) -C $(CLICKHOUSE_DIR) clean TARGET_DIR=$(abspath .)
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
