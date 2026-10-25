










#pragma once
#include "methods.hpp"
#include "bob_hash.hpp"
#include <algorithm>
#include <cstdint>
#include <vector>

namespace bench {

struct RHHHCpp : Method {
    
    static constexpr uint32_t MASKS[4] = {0xFFFFFFFFu, 0xFFFFFF00u, 0xFFFF0000u,
                                          0xFF000000u};

    
    
    
    
    struct Level {
        std::vector<uint32_t> keys;
        std::vector<uint32_t> cnts;
        std::vector<uint8_t> occ;     
        std::vector<uint32_t> order;  
        uint32_t n = 0;
        uint32_t cap = 0;
        uint32_t base = 0;            

        void init(uint32_t cap2) {
            cap = cap2;
            keys.assign(cap2, 0u);
            cnts.assign(cap2, 0u);
            occ.assign(cap2, 0);
            order.reserve(cap2 / 2);
        }
        
        static uint32_t mix(uint32_t x) {
            x ^= x >> 16;
            x *= 0x7FEB352Du;
            x ^= x >> 15;
            x *= 0x846CA68Bu;
            x ^= x >> 16;
            return x;
        }
        int64_t find(uint32_t k) const {
            uint32_t mask = cap - 1;
            uint32_t i = mix(k) & mask;
            while (occ[i] != 0) {
                if (keys[i] == k) return (int64_t)i;
                i = (i + 1) & mask;
            }
            return -1;
        }
        
        void insert_new(uint32_t k, uint32_t c) {
            uint32_t mask = cap - 1;
            uint32_t i = mix(k) & mask;
            while (occ[i] != 0) i = (i + 1) & mask;
            keys[i] = k;
            cnts[i] = c;
            occ[i] = 1;
            n++;
        }
        
        
        
        void erase(int64_t i) {
            uint32_t mask = cap - 1;
            uint32_t cur = (uint32_t)i;
            occ[cur] = 0;
            n--;
            uint32_t nxt = (cur + 1) & mask;
            while (occ[nxt] != 0) {
                uint32_t h = mix(keys[nxt]) & mask;
                bool blocked;  
                if (cur < nxt) blocked = (h > cur && h <= nxt);
                else blocked = (h > cur || h <= nxt);
                if (!blocked) {
                    keys[cur] = keys[nxt];
                    cnts[cur] = cnts[nxt];
                    occ[cur] = 1;
                    occ[nxt] = 0;
                    cur = nxt;
                }
                nxt = (nxt + 1) & mask;
            }
        }
    };

    uint32_t C;
    Level levels[4];

    explicit RHHHCpp(int budget_kb, int n_pfx) {
        (void)n_pfx;
        
        C = (uint32_t)std::max(16, budget_kb * 1024 / (4 * 12));
        uint32_t cap2 = 8;
        while (cap2 < C * 2u) cap2 <<= 1;
        for (auto& lv : levels) lv.init(cap2);
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)pkt_i;
        (void)ts_ns;
        
        uint32_t lv = bob_hash_u32x2(s, d, 0x8100u) & 3u;
        uint32_t item = d & MASKS[lv];
        Level& L = levels[lv];
        int64_t hit = L.find(item);
        if (hit >= 0) {  
            L.cnts[hit] += 1;
            return;
        }
        if (L.n < C) {  
            L.insert_new(item, L.base + 1);
            L.order.push_back(item);
            return;
        }
        
        L.base += 1;
        uint32_t w = 0;
        bool removed = false;
        for (uint32_t k : L.order) {
            int64_t s2 = L.find(k);
            if (s2 >= 0 && L.cnts[s2] <= L.base) {
                L.erase(s2);
                removed = true;
            } else {
                L.order[w++] = k;
            }
        }
        L.order.resize(w);
        if (!removed) {
            
            
            uint32_t mi = 0;
            uint32_t mc = L.cnts[L.find(L.order[0])];
            for (uint32_t i = 1; i < L.order.size(); i++) {
                uint32_t c = L.cnts[L.find(L.order[i])];
                if (c < mc) {
                    mc = c;
                    mi = i;
                }
            }
            L.erase(L.find(L.order[mi]));
            L.order.erase(L.order.begin() + mi);
        }
        L.insert_new(item, L.base + 1);
        L.order.push_back(item);
    }

    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        
        
        const Level& L = levels[1];
        for (uint32_t i = 0; i < L.cap; i++) {
            if (L.occ[i] == 1)
                out.push_back({(uint64_t)L.keys[i], (double)(L.cnts[i] - L.base)});
        }
    }
    const char* name() const override { return "rhhh"; }
};

inline std::unique_ptr<Method> create_rhhh(int budget_kb, int n_pfx) {
    return std::make_unique<RHHHCpp>(budget_kb, n_pfx);
}
}  
