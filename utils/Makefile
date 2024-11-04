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
