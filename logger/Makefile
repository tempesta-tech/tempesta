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

CLICKHOUSE_DIR := clickhouse-cpp
CLICKHOUSE_BUILD_DIR := $(CLICKHOUSE_DIR)/build
CLICKHOUSE_REPO_URL := https://github.com/ClickHouse/clickhouse-cpp.git

CXX := g++
LDFLAGS := -lfmt -lboost_program_options -lboost_filesystem
LDFLAGS += -lclickhouse-cpp-lib -L $(CLICKHOUSE_BUILD_DIR)/clickhouse
LDFLAGS += -lcityhash -L $(CLICKHOUSE_BUILD_DIR)/contrib/cityhash/cityhash
LDFLAGS += -lzstdstatic -L $(CLICKHOUSE_BUILD_DIR)/contrib/zstd/zstd
LDFLAGS += -llz4 -L $(CLICKHOUSE_BUILD_DIR)/contrib/lz4/lz4
LDFLAGS += -labsl_int128 -L $(CLICKHOUSE_BUILD_DIR)/contrib/absl/absl
LDFLAGS += -ltus -L ../libtus -Wl,-rpath,'$$ORIGIN/../lib:$$ORIGIN/../libtus'
LDFLAGS += $(shell pkgconf -libs spdlog)
LDFLAGS += -rdynamic -ldl
PAGE_SIZE := $(shell getconf PAGE_SIZE)
CXXFLAGS := -Wall -Wextra -std=c++23 -march=native -mtune=native \
	    -DPAGE_SIZE=$(PAGE_SIZE)
CXXFLAGS += $(shell pkgconf -cflags spdlog)
CXXFLAGS += -I $(CLICKHOUSE_DIR)
CXXFLAGS += -I $(CLICKHOUSE_DIR)/contrib/absl
OBJS := $(patsubst %.cc, %.o, $(wildcard *.cc))
TARGET := tfw_logger

DEBUG ?= 0
ifeq ($(DEBUG), 0)
	CXXFLAGS += -O3 -DNDEBUG -s
else
	CXXFLAGS += -DDEBUG=1 -O0 -ggdb3
endif

all:
	$(MAKE) clickhouse
	$(MAKE) $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean: clickhouse_clean
	rm -f $(OBJS) $(TARGET)

clickhouse: $(CLICKHOUSE_DIR)
	mkdir -p $(CLICKHOUSE_DIR)/build
	cd $(CLICKHOUSE_DIR)/build && cmake .. && $(MAKE)

$(CLICKHOUSE_DIR):
	git clone $(CLICKHOUSE_REPO_URL) $(CLICKHOUSE_DIR)

clickhouse_install:
	$(MAKE) -C $(CLICKHOUSE_BUILD_DIR) install

clickhouse_clean:
	$(RM) -rf $(CLICKHOUSE_DIR)

sanitize: $(OBJS)
	$(CXX) -O0 -g -Wall -Wextra -std=c++23 -fsanitize=address,undefined -fno-omit-frame-pointer -o $(TARGET) $^ $(LDFLAGS)

tfw_logger_sanitize:
	$(MAKE) clickhouse
	$(MAKE) sanitize

.PHONY: all clean clickhouse clickhouse_install clickhouse_clean sanitize tfw_logger_sanitize
