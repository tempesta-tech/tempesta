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
CXXFLAGS := -std=c++23 -Wall -Wextra -O0 -g -DDEBUG
CXXFLAGS += -I../ -I/usr/include/boost
LDFLAGS := -lgtest -lgtest_main -lboost_program_options -lboost_filesystem -pthread

# Parent directory (logger/)
PARENT_DIR := ..

# Test source files from unit/ subdirectory
UNIT_TEST_SRCS := unit/test_config.cc
UNIT_TEST_OBJS := $(patsubst unit/%.cc,%.o,$(UNIT_TEST_SRCS))

# Main source files we're testing
MAIN_SRCS := $(PARENT_DIR)/tfw_logger_config.cc
MAIN_OBJS := $(patsubst $(PARENT_DIR)/%.cc,%.o,$(MAIN_SRCS))

# Test executables
TEST_TARGETS := test_config

.PHONY: all test clean help

all: $(TEST_TARGETS)

# Build test executable
test_config: test_config.o tfw_logger_config.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Compile test files from unit/ subdirectory
test_config.o: unit/test_config.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile main source files
tfw_logger_config.o: $(PARENT_DIR)/tfw_logger_config.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TEST_TARGETS)
	@echo "Running unit tests..."
	@for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo "All unit tests passed!"

clean:
	rm -f $(TEST_TARGETS) $(UNIT_TEST_OBJS) $(MAIN_OBJS)
	rm -f *.o *.gcov *.gcda *.gcno

help:
	@echo "Available targets:"
	@echo "  all           - Build all test executables"
	@echo "  test          - Run all unit tests"
	@echo "  clean         - Clean build artifacts"
	@echo "  help          - Show this help"
