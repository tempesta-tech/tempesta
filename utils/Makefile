CXX := g++
LDFLAGS := -lclickhouse-cpp-lib
PAGE_SIZE := $(shell getconf PAGE_SIZE)
CXXFLAGS := -O3 -Wall -Wextra -std=c++23 -DPAGE_SIZE=$(PAGE_SIZE)
SRCS := tfw_logger.cpp mmap_buffer.cpp clickhouse.cpp
OBJS := $(SRCS:.cpp=.o)
TARGET := tfw_logger

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
