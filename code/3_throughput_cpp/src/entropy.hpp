












#pragma once
#include "methods.hpp"
#include "bob_hash.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace bench {

struct EntropyCpp : Method {
    uint32_t z, g;
    
    std::vector<uint64_t> pfx_keys;
    std::vector<uint32_t> pfx_rows;
    std::vector<uint8_t> pfx_occ;
    uint32_t pfx_n = 0;
    uint32_t n_rows = 0;
    std::vector<uint32_t> ctrs;  

    explicit EntropyCpp(int budget_kb, int n_pfx) {
        int np = std::max(n_pfx, 1);
        
        int per_pfx = std::max(2 * 32, budget_kb * 1024 * 8 / np);
        z = (uint32_t)std::max(2, per_pfx / 32);
        g = std::min(3u, std::max(1u, z / 4));
        uint32_t cap = 8;
        while (cap < (uint32_t)np * 2u) cap <<= 1;
        pfx_keys.assign(cap, 0);
        pfx_rows.assign(cap, 0);
        pfx_occ.assign(cap, 0);
        n_rows = (uint32_t)np;
        ctrs.assign((uint64_t)np * z, 0u);
    }

    static uint32_t mix(uint64_t x) {
        x ^= x >> 33;
        x *= 0xFF51AFD7ED558CCDu;
        x ^= x >> 33;
        return (uint32_t)x;
    }

    
    uint32_t row_of(uint64_t pfx) {
        uint32_t mask = (uint32_t)(pfx_keys.size() - 1);
        uint32_t i = mix(pfx) & mask;
        while (pfx_occ[i]) {
            if (pfx_keys[i] == pfx) return pfx_rows[i];
            i = (i + 1) & mask;
        }
        if (pfx_n >= n_rows) {  
            std::vector<uint32_t> nc;
            nc.reserve((uint64_t)n_rows * 2 * z);
            nc.insert(nc.end(), ctrs.begin(), ctrs.end());
            nc.resize((uint64_t)n_rows * 2 * z, 0u);
            ctrs.swap(nc);
            n_rows *= 2;
        }
        pfx_keys[i] = pfx;
        pfx_rows[i] = pfx_n;
        pfx_occ[i] = 1;
        pfx_n++;
        return pfx_rows[i];
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)s;
        (void)pkt_i;
        (void)ts_ns;
        uint32_t pfx = (d >> 8) << 8;
        uint32_t row = row_of(pfx);
        uint32_t* c = &ctrs[(uint64_t)row * z];
        
        for (uint32_t i = 0; i < g; i++) c[bob_hash_u32(d, 0xC100u + i) % z] += 1;
    }

    
    
    
    
    
    double score_row(const uint32_t* c) const {
        uint64_t sum = 0;
        for (uint32_t j = 0; j < z; j++) sum += c[j];
        double m = (double)sum / (double)g;  
        if (m <= 0) return 0.0;
        double gz = (double)g / (double)z;
        double mgz = m * gz;  
        double fr = 0.0, comp = 0.0;  
        for (uint32_t j = 0; j < z; j++) {
            double f_item = std::pow((double)c[j] - mgz, 2.0);  
            double t = fr + f_item;
            if (std::fabs(fr) >= std::fabs(f_item)) comp += (fr - t) + f_item;
            else comp += (f_item - t) + fr;
            fr = t;
        }
        double s = fr + comp;  
        double fhat = s / (m * m * (double)g * (1.0 - gz));
        
        if (fhat < 1.0 / 65536.0) fhat = 1.0 / 65536.0;
        else if (fhat > 1.0) fhat = 1.0;
        return -std::log2(fhat);
    }

    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        
        for (uint32_t i = 0; i < pfx_keys.size(); i++) {
            if (pfx_occ[i]) {
                const uint32_t* c = &ctrs[(uint64_t)pfx_rows[i] * z];
                out.push_back({pfx_keys[i], score_row(c)});
            }
        }
    }
    const char* name() const override { return "entropy"; }
};

inline std::unique_ptr<Method> create_entropy(int budget_kb, int n_pfx) {
    return std::make_unique<EntropyCpp>(budget_kb, n_pfx);
}
}  
