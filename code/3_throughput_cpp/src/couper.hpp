










#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>
#include "bob_hash.hpp"
#include "methods.hpp"

namespace bench {

struct CouperCpp : Method {
    
    static constexpr int B = 12, T = 9, K1 = 2, K2 = 2, C = 48, HLL_BITS = 288;
    static constexpr double MU = 0.6;

    int l1 = 0, l2 = 0, tsc_len = 0;
    std::vector<uint16_t> bm;   
    std::vector<uint8_t> regs;  
    struct TscEntry {           
        uint32_t flow = 0;
        double digest = 0.0;
    };
    std::vector<TscEntry> tsc;

    CouperCpp(int budget_kb, int n_pfx) {
        (void)n_pfx;
        
        l1 = std::max(8, (int)((double)(budget_kb * 1024) * MU * 8.0 / (double)B));
        l2 = std::max(8, (int)((double)(budget_kb * 1024) * (1.0 - MU) * 8.0 / (double)HLL_BITS));
        tsc_len = std::max(64, l2);
        bm.assign((size_t)l1, 0);
        regs.assign((size_t)l2 * C, 0);
        tsc.assign((size_t)tsc_len, TscEntry{0, 0.0});
    }

    
    uint32_t cell(uint32_t f, uint32_t seed) const {
        return bob_hash_u32(f, seed) % (uint32_t)l1;
    }

    
    static double hll_est(const uint8_t* r) {
        const int m = 48;
        double s = 0.0;
        int nz = 0;
        for (int i = 0; i < m; i++) {
            if (r[i] > 0) { s += ldexp(1.0, -(int)r[i]); nz++; }
        }
        s += (double)(m - nz);
        double res = (0.7213 / (1.0 + 1.079 / m)) * m * m / s;
        if (res < 2.5 * m) {
            int z = m - nz;
            res = m * log(m / (double)std::max(z, 1));
        }
        return res;
    }

    
    void est_hll(uint32_t f, uint8_t* fgm) const {
        uint32_t g1 = bob_hash_u32(f, 0x7400) % (uint32_t)l2;
        uint32_t g2 = bob_hash_u32(f, 0x7401) % (uint32_t)l2;
        for (int i = 0; i < C; i++)
            fgm[i] = std::max(regs[(size_t)g1 * C + i], regs[(size_t)g2 * C + i]);
    }

    
    void tsc_insert(uint32_t f, double lam) {
        uint32_t i = bob_hash_u32(f, 0x7500) % (uint32_t)tsc_len;
        uint32_t j = bob_hash_u32(f, 0x7501) % (uint32_t)tsc_len;
        if (tsc[i].flow == 0 || tsc[i].flow == f) { tsc[i] = TscEntry{f, lam}; return; }
        if (tsc[j].flow == 0 || tsc[j].flow == f) { tsc[j] = TscEntry{f, lam}; return; }
        uint32_t k = (tsc[i].digest <= tsc[j].digest) ? i : j;
        if (tsc[k].digest <= lam) tsc[k] = TscEntry{f, lam};
    }

    
    void record_l2(uint32_t f, uint32_t e) {
        uint32_t h = bob_hash_u32x2(f, e, 0x7300);
        uint32_t reg = h % C;
        uint32_t rho = tz32((h / C) | 1u) + 1;   
        uint32_t offs[K2];
        for (int i = 0; i < K2; i++) offs[i] = bob_hash_u32(f, 0x7400 + i) % (uint32_t)l2;
        double lam = 0.0;
        bool first = true;
        for (int i = 0; i < K2; i++) {
            uint32_t g = offs[i];
            if (regs[(size_t)g * C + reg] < rho) regs[(size_t)g * C + reg] = (uint8_t)rho;
            uint32_t dg = 0;
            for (int j = 0; j < C; j++) dg += regs[(size_t)g * C + j];
            if (first || (double)dg < lam) { lam = (double)dg; first = false; }
        }
        tsc_insert(f, lam);
    }

    
    double estimate(uint32_t f) const {
        uint32_t c1 = cell(f, 0x7100), c2 = cell(f, 0x7101);
        uint32_t merged = bm[c1] | bm[c2];
        int coupon = __builtin_popcount(merged);          
        double base = B * log(B / (double)std::max(B - T, 1));
        if (coupon < T) return B * log(B / (double)std::max(B - coupon, 1));
        uint8_t fgm[C];
        est_hll(f, fgm);
        uint32_t bm2 = 0;                                 
        for (int r = 0; r < C; r++)
            if (fgm[r] > 0) bm2 |= 1u << (r % B);
        int tmp = __builtin_popcount(merged & bm2);
        double omega = std::min(B * log(B / (double)std::max(B - tmp, 1)), base);
        return hll_est(fgm) + base - omega;
    }

    
    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)pkt_i; (void)ts_ns;
        uint32_t f = s, e = d;
        uint32_t c1 = cell(f, 0x7100), c2 = cell(f, 0x7101);
        if (__builtin_popcount(bm[c1] | bm[c2]) < T) {
            uint32_t q = bob_hash_u32x2(f, e, 0x7200) % B;
            bm[c1] |= (uint16_t)(1u << q);
            bm[c2] |= (uint16_t)(1u << q);
            return;
        }
        record_l2(f, e);
    }

    
    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        out.clear();
        for (const TscEntry& t : tsc)
            if (t.flow != 0) out.emplace_back((uint64_t)t.flow, estimate(t.flow));
    }
    const char* name() const override { return "couper"; }
};

inline std::unique_ptr<Method> create_couper(int budget_kb, int n_pfx) {
    return std::make_unique<CouperCpp>(budget_kb, n_pfx);
}
}  
