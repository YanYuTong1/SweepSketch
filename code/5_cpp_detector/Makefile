CXX ?= clang++
CXXFLAGS ?= -O3 -std=c++20 -Wall -Wextra -Wno-unused-parameter
ARCH := $(shell $(CXX) -march=native -E -x c++ /dev/null >/dev/null 2>&1 && echo -march=native)
CXXFLAGS += $(ARCH)
SRC = src/main.cpp
OUT = build/detector

all: $(OUT)

$(OUT): $(SRC) $(wildcard src/*.hpp)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -o $(OUT) $(SRC)

clean:
	rm -rf build

.PHONY: all clean
