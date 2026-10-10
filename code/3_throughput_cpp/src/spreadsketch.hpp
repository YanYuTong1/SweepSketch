








#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "bob_hash.hpp"
#include "methods.hpp"

namespace bench {

namespace spread_impl {

inline double lc(int ones, int m) {
    int z = m - ones;
    if (z <= 0) z = 1;
    return (double)m * std::log((double)m / (double)z);
}

inline int popcount(const uint8_t* p, size_t n) {
    int ones = 0;
    for (size_t i = 0; i < n; i++) ones += __builtin_popcount(p[i]);
    return ones;
}
}  

struct SpreadSketchCpp : Method {
    static constexpr int M = 512;      
    static constexpr int ROWS = 4;     

    struct Bucket {                    
        uint32_t key = 0;              
        uint32_t level = 0;
        uint8_t bm[M / 8] = {};        
    };

    int cols;
    std::vector<Bucket> buckets;       

    explicit SpreadSketchCpp(int budget_kb, int n_pfx) {
        (void)n_pfx;
        
        cols = std::max(2, budget_kb * 1024 / (ROWS * (8 + M / 8)));
        buckets.assign((size_t)ROWS * cols, Bucket{});   
    }

    
    static int loghash64(uint64_t p) {
        int t = 0;
        while (p & 1) {
            t++;
            p >>= 1;
        }
        return t + 1;
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)pkt_i;
        (void)ts_ns;
        
        uint64_t p = ((uint64_t)bob_hash_u32x2(s, d, 0x5500) << 32) |
                     bob_hash_u32x2(s, d, 0x5501);
        int lvl = loghash64(p);                                    
        uint32_t pos = (uint32_t)(((p >> 32) * (uint64_t)M) >> 32);  
        for (int i = 0; i < ROWS; i++) {                           
            Bucket& b = buckets[(size_t)i * cols +
                                bob_hash_u32(s, 0x6600 + i) % (uint32_t)cols];
            if (b.level < lvl) {                                   
                b.level = (uint32_t)lvl;
                b.key = s;
            }
            b.bm[pos >> 3] |= (uint8_t)(0x80 >> (pos & 7));        
        }
    }

    
    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        std::map<uint64_t, double> m;
        for (const Bucket& b : buckets)
            if (b.key) m[b.key] = 0.0;                 
        for (auto& kv : m) {
            double best = 0.0;
            bool first = true;                         
            for (int i = 0; i < ROWS; i++) {           
                const Bucket& b = buckets[(size_t)i * cols +
                                          bob_hash_u32((uint32_t)kv.first, 0x6600 + i) %
                                              (uint32_t)cols];
                double e = spread_impl::lc(spread_impl::popcount(b.bm, M / 8), M);
                if (first || e < best) {
                    best = e;
                    first = false;
                }
            }
            kv.second = best;                          
        }
        out.assign(m.begin(), m.end());
    }

    const char* name() const override { return "spreadsketch"; }
};

inline std::unique_ptr<Method> create_spreadsketch(int budget_kb, int n_pfx) {
    return std::make_unique<SpreadSketchCpp>(budget_kb, n_pfx);
}

}  
