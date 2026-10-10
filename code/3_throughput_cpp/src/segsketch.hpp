








#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "bob_hash.hpp"
#include "methods.hpp"

namespace bench {

namespace segsk_impl {

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

struct SegSketchCpp : Method {
    
    static constexpr int G = 4;                        
    static constexpr int SUB_BITS = 256;               
    static constexpr int HOST_BITS = 4096;             
    static constexpr int R = 3;                        
    static constexpr int BUCKET_BYTES = 4 + SUB_BITS / 8 + HOST_BITS / 8;  

    struct Bucket {                                    
        uint32_t key = 0;                              
        uint8_t sub[SUB_BITS / 8] = {};                
        uint8_t host[HOST_BITS / 8] = {};              
    };

    int cols;
    std::vector<Bucket> buckets;                       

    explicit SegSketchCpp(int budget_kb, int n_pfx) {
        (void)n_pfx;
        
        cols = std::max(2, budget_kb * 1024 / (R * BUCKET_BYTES));
        buckets.assign((size_t)R * cols, Bucket{});    
    }

    
    double est(const Bucket& b) const {
        return segsk_impl::lc(segsk_impl::popcount(b.host, HOST_BITS / 8), HOST_BITS);
    }

    
    void mark(Bucket& b, uint32_t d) const {
        uint32_t bit = 0;
        for (int k = 0; k < 8; k++) {
            uint32_t seg = (d >> (28 - 4 * k)) & 0xFu;   
            bit = (bit << 1) | (bob_hash_u32(seg, 0x2100) & 1u);
        }
        b.sub[bit >> 3] |= (uint8_t)(0x80 >> (bit & 7));  
        uint32_t h = bob_hash_u32(d, 0x3300) % HOST_BITS; 
        b.host[h >> 3] |= (uint8_t)(0x80 >> (h & 7));     
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)ts_ns;
        
        Bucket* cands[R];
        for (int i = 0; i < R; i++)
            cands[i] = &buckets[(size_t)i * cols + bob_hash_u32(s, 0x1100 + i) % (uint32_t)cols];
        
        for (int i = 0; i < R; i++)
            if (cands[i]->key == s) {
                mark(*cands[i], d);
                return;
            }
        
        for (int i = 0; i < R; i++)
            if (cands[i]->key == 0) {
                cands[i]->key = s;
                mark(*cands[i], d);
                return;
            }
        
        Bucket* cand = cands[0];                        
        double cmin = est(*cands[0]);
        for (int i = 1; i < R; i++) {
            double e = est(*cands[i]);
            if (e < cmin) {
                cmin = e;
                cand = cands[i];
            }
        }
        double nhat = std::max(est(*cand), 1.0);        
        double r = bob_hash_u32x2(s, (uint32_t)pkt_i, 0x9900) / 4294967296.0;  
        if (r < 1.0 / (std::log(nhat) + 1.0)) {         
            cand->key = s;                              
            std::memset(cand->sub, 0, sizeof(cand->sub));
            std::memset(cand->host, 0, sizeof(cand->host));
            mark(*cand, d);
        }
    }

    
    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        std::map<uint64_t, double> m;
        for (const Bucket& b : buckets)
            if (b.key) m[b.key] = est(b);
        out.assign(m.begin(), m.end());
    }

    const char* name() const override { return "segsketch"; }
};

inline std::unique_ptr<Method> create_segsketch(int budget_kb, int n_pfx) {
    return std::make_unique<SegSketchCpp>(budget_kb, n_pfx);
}

}  
