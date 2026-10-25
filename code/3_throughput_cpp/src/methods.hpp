






#pragma once
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace bench {

struct Pkt {
    uint32_t s, d;
    uint64_t ts_ns;
};

struct Method {
    virtual ~Method() = default;
    virtual void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) = 0;
    
    virtual void scores(std::vector<std::pair<uint64_t, double>>& out) const {
        (void)out;
    }
    virtual const char* name() const = 0;
};

}  
