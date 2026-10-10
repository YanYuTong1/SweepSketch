












#pragma once
#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <utility>
#include <vector>
#include "bob_hash.hpp"
#include "methods.hpp"

namespace bench {

struct ElasticCpp : Method {
    
    static constexpr int CELLS = 8;
    static constexpr int SWAP_SHIFT = 3;

    int bucket_num = 0;
    int light_len = 0;
    std::vector<uint32_t> keys;  
    std::vector<uint32_t> vals;  
    std::vector<uint8_t> light;  

    ElasticCpp(int budget_kb, int n_pfx) {
        (void)n_pfx;
        
        int heavy_bytes = std::max(64, budget_kb * 1024 / 4);
        int bn = std::max(1, heavy_bytes / 64);
        int lb = std::max(64, budget_kb * 1024 - bn * 64);
        bucket_num = bn;
        keys.assign((size_t)bn * CELLS, 0);
        vals.assign((size_t)bn * CELLS, 0);
        light_len = std::max(lb, 1);  
        light.assign((size_t)light_len, 0);
    }

    
    void light_insert(uint32_t key, uint32_t f) {
        uint32_t pos = bob_hash_u32(key, 0x9200) % (uint32_t)light_len;
        light[pos] = (uint8_t)std::min(255u, (uint32_t)light[pos] + f);
    }

    
    void light_swap(uint32_t key, uint32_t f) {
        uint32_t pos = bob_hash_u32(key, 0x9200) % (uint32_t)light_len;
        if ((uint32_t)light[pos] < f) light[pos] = (uint8_t)std::min(255u, f);
    }

    
    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)s; (void)pkt_i; (void)ts_ns;
        uint32_t key = (d >> 8) << 8;  
        uint32_t pos = bob_hash_u32(key, 0x9100) % (uint32_t)bucket_num;
        uint32_t* krow = keys.data() + (size_t)pos * CELLS;
        uint32_t* vrow = vals.data() + (size_t)pos * CELLS;
        for (int i = 0; i < CELLS - 1; i++) {  
            if (krow[i] == key) { vrow[i] += 1; return; }
        }
        for (int i = 0; i < CELLS - 1; i++) {  
            if (krow[i] == 0) { krow[i] = key; vrow[i] = 1; return; }
        }
        
        int min_i = 0;                          
        uint32_t min_v = vrow[0] & 0x7FFFFFFFu;
        for (int i = 1; i < CELLS - 1; i++) {
            uint32_t v = vrow[i] & 0x7FFFFFFFu;
            if (v < min_v) { min_v = v; min_i = i; }
        }
        uint64_t guard = (uint64_t)vrow[CELLS - 1] + 1;
        if (guard <= ((uint64_t)(vrow[min_i] & 0x7FFFFFFFu) << SWAP_SHIFT)) {
            vrow[CELLS - 1] = (uint32_t)guard;  
            light_insert(key, 1);
            return;
        }
        uint32_t ev_key = krow[min_i], ev_val = vrow[min_i];  
        vrow[CELLS - 1] = 0;
        krow[min_i] = key;
        vrow[min_i] = 0x80000001u;
        if (ev_val & 0x80000000u)               
            light_insert(ev_key, ev_val & 0x7FFFFFFFu);
        else
            light_swap(ev_key, ev_val);
    }

    
    double query_one(uint32_t key) const {
        uint32_t pos = bob_hash_u32(key, 0x9100) % (uint32_t)bucket_num;
        const uint32_t* krow = keys.data() + (size_t)pos * CELLS;
        const uint32_t* vrow = vals.data() + (size_t)pos * CELLS;
        for (int i = 0; i < CELLS - 1; i++) {
            if (krow[i] == key) {
                uint32_t v = vrow[i];
                if (v & 0x80000000u)
                    return (double)(v & 0x7FFFFFFFu) +
                           (double)light[bob_hash_u32(key, 0x9200) % (uint32_t)light_len];
                return (double)v;
            }
        }
        return 0.0;
    }

    
    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        out.clear();
        std::unordered_set<uint32_t> seen;
        seen.reserve(512);
        for (int pos = 0; pos < bucket_num; pos++) {
            for (int i = 0; i < CELLS - 1; i++) {
                uint32_t key = keys[(size_t)pos * CELLS + i];
                if (key != 0 && seen.insert(key).second)
                    out.emplace_back((uint64_t)key, query_one(key));
            }
        }
    }
    const char* name() const override { return "elastic"; }
};

inline std::unique_ptr<Method> create_elastic(int budget_kb, int n_pfx) {
    return std::make_unique<ElasticCpp>(budget_kb, n_pfx);
}
}  
