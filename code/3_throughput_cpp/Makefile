CXX ?= clang++
CXXFLAGS = -O3 -std=c++17 -Wall

ARCH := $(shell $(CXX) -march=native -E -x c++ /dev/null >/dev/null 2>&1 && echo -march=native)
CXXFLAGS += $(ARCH)

SRC = src/bench.cpp
OUT = build/bench

all: $(OUT)

$(OUT): $(SRC) $(wildcard src/*.hpp)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -o $(OUT) $(SRC)

verify: $(OUT)
	$(OUT) --trace verify/trace.csv --verify verify/expected --budget 512 --method all

clean:
	rm -rf build

.PHONY: all verify clean
