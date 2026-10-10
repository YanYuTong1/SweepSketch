









#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "bob_hash.hpp"
#include "methods.hpp"

namespace bench {

namespace mrb_impl {

inline int popcount(const uint8_t* p, size_t n) {
    int ones = 0;
    for (size_t i = 0; i < n; i++) ones += __builtin_popcount(p[i]);
    return ones;
}
}  

struct MRBCpp : Method {
    static constexpr int C = 3;                
    static constexpr double RATIO = 0.93105;   

    int b;                                     
    int lastb;                                 
    int n_pfx;                                 

    
    
    
    
    struct Slot {
        uint32_t pfx = 0;
        std::vector<uint8_t> bms[C];           
    };
    std::vector<Slot> slots;
    std::vector<uint32_t> table;               
    uint32_t used = 0;                         

    explicit MRBCpp(int budget_kb, int n_pfx_arg) {
        
        n_pfx = std::max(n_pfx_arg, 1);
        int64_t per_pfx = std::max((int64_t)32, (int64_t)budget_kb * 1024 * 8 / n_pfx);
        b = std::max(8, (int)(per_pfx / 4));
        lastb = std::max(2 * b, 1);            
        slots.resize(n_pfx);
        for (Slot& sl : slots) {               
            sl.bms[0].assign((size_t)((b + 7) / 8), 0);
            sl.bms[1].assign((size_t)((b + 7) / 8), 0);
            sl.bms[2].assign((size_t)((lastb + 7) / 8), 0);
        }
        size_t cap = 64;                       
        while (cap < (size_t)4 * n_pfx) cap <<= 1;
        table.assign(cap, 0);
    }

    
    Slot& slot_for(uint32_t pfx) {
        uint32_t mask = (uint32_t)(table.size() - 1);
        uint32_t h = bob_hash_u32(pfx, 0xD100) & mask;   
        for (;;) {
            uint32_t v = table[h];
            if (v == 0) {
                uint32_t idx = used++;         
                table[h] = idx + 1;
                slots[idx].pfx = pfx;
                return slots[idx];
            }
            if (slots[v - 1].pfx == pfx) return slots[v - 1];
            h = (h + 1) & mask;
        }
    }

    
    static int loghash32(uint32_t p) {
        int t = 0;
        while (p & 1) {
            t++;
            p >>= 1;
        }
        return t + 1;
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)s;
        (void)pkt_i;
        (void)ts_ns;
        uint32_t pfx = (d >> 8) << 8;          
        Slot& sl = slot_for(pfx);              
        uint32_t p = bob_hash_u32(d, 0xB100);  
        int lvl = loghash32(p);                
        if (lvl < C - 1) {                     
            uint32_t pos = (uint32_t)(((uint64_t)p * (uint64_t)b) >> 32);   
            sl.bms[1][pos >> 3] |= (uint8_t)(0x80 >> (pos & 7));            
        } else {                               
            uint32_t pos = (uint32_t)(((uint64_t)p * (uint64_t)lastb) >> 32);
            sl.bms[2][pos >> 3] |= (uint8_t)(0x80 >> (pos & 7));
        }
    }

    
    static int zeros(const std::vector<uint8_t>& bm, int bits) {
        return bits - mrb_impl::popcount(bm.data(), bm.size());
    }

    
    double est_one(const Slot& sl) const {
        int setmax = (int)((double)b * RATIO + 0.5);             
        int factor = 1;
        int base = 0;
        for (base = 0; base < C - 1; base++) {                   
            int z = zeros(sl.bms[base], b);
            if (b - z <= setmax) break;
            factor *= 2;
        }
        if (base == C - 1) base = C - 2;   
        double m = 0.0;
        int pos = base - 1;                                      
        for (int i = base; i < C - 1; i++) {                     
            int z = zeros(sl.bms[i], b);
            if (z == 0 || b - z > setmax) {                      
                pos = i;
                m = 0.0;
            } else {
                m += (double)b * (std::log((double)b) - std::log((double)z));
            }
        }
        factor *= 1 << (pos - base + 1);                         
        int z = zeros(sl.bms[C - 1], lastb);                     
        m += (double)lastb * (std::log((double)lastb) - (z ? std::log((double)z) : 0.0));
        return (double)factor * m;                               
    }

    
    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        out.clear();
        out.reserve(used);
        for (uint32_t i = 0; i < used; i++)
            out.emplace_back((uint64_t)slots[i].pfx, est_one(slots[i]));
    }

    const char* name() const override { return "mrb"; }
};

inline std::unique_ptr<Method> create_mrb(int budget_kb, int n_pfx) {
    return std::make_unique<MRBCpp>(budget_kb, n_pfx);
}

}  
