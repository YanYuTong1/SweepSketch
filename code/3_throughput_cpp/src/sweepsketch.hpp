




















#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>

#include "bob_hash.hpp"
#include "methods.hpp"
namespace bench {

struct SweepDump {
    struct B {
        bool present = false;
        uint32_t key = 0, epoch = 0, win = 0;
        uint32_t n_new = 0, n_ewma = 0, C = 0, pkt = 0, pkt_ewma = 0;
        uint8_t d2_held = 0;
        uint8_t hll[32] = {0};
        uint64_t a1 = 0, a2 = 0;
    };
    std::vector<B> l1;  
    std::vector<B> l2;  
};

namespace sweep_detail {


static inline int64_t py_rshift(int64_t x, int s) {
    return x >= 0 ? (x >> s) : -(((-x) + ((int64_t)1 << s) - 1) >> s);
}
}  

struct SweepCpp : Method {
    
    static constexpr uint32_t N_L1 = 7936;  
    static constexpr uint32_t N_L2 = 3968;  
    static constexpr uint32_t HLL_M = 32;   
    static constexpr uint32_t RHO_BITS = 5;
    static constexpr uint32_t WIN_MASK = 7;
    
    static constexpr uint32_t C_MAX = 0xFFFF, PKT_MAX = 0xFFFF;
    static constexpr int64_t LLR_NEW = 38, LLR_REP = -26;  
    static constexpr uint32_t H_FP = 74;      
    static constexpr uint32_t K_ALARM = 8;    
    static constexpr uint32_t K_ALARM_QUIET = 12;  
    static constexpr uint32_t N_EWMA_QUIET = 4;
    static constexpr uint32_t K_FLOOD = 6;    
    static constexpr uint32_t EWMA_SHIFT = 3; 
    static constexpr uint32_t P_MIN = 200;    
    static constexpr uint32_t D2_MULT = 3;    
    static constexpr bool USE_L2 = true, USE_D1 = true, USE_D2 = true, USE_GATE = true;

    std::vector<SweepDump::B> l1_, l2_;  

    
    struct Salvage {
        uint32_t key;
        uint64_t a1, a2;
    };
    std::vector<Salvage> salvage_l1_, salvage_l2_;

    SweepCpp(int budget_kb, int n_pfx) : l1_(N_L1), l2_(N_L2) {
        (void)budget_kb;  
        (void)n_pfx;
        
        salvage_l1_.reserve(4096);
        salvage_l2_.reserve(1024);
    }

    
    
    
    
    
    static void process(SweepDump::B& b, uint32_t r, int rho, uint8_t g, bool& a1,
                        bool& a2) {
        bool rollover = (b.epoch != g);
        if (rollover) {
            
            b.d2_held = ((int64_t)b.pkt >= std::max<int64_t>((int64_t)P_MIN,
                                                             (int64_t)D2_MULT * b.pkt_ewma) &&
                         (int64_t)b.n_new >= std::max<int64_t>((int64_t)K_FLOOD,
                                                               2 * (int64_t)b.n_ewma))
                            ? 1u
                            : 0u;
            
            b.n_ewma = (uint32_t)((int64_t)b.n_ewma +
                                  sweep_detail::py_rshift((int64_t)b.n_new - (int64_t)b.n_ewma,
                                                           (int)EWMA_SHIFT));
            b.pkt_ewma = (uint32_t)((int64_t)b.pkt_ewma +
                                    sweep_detail::py_rshift((int64_t)b.pkt -
                                                                 (int64_t)b.pkt_ewma,
                                                             (int)EWMA_SHIFT));
            b.n_new = b.pkt = b.C = 0;  
            b.win = (b.win + 1) & WIN_MASK;
        }
        
        uint8_t cell = b.hll[r];
        uint32_t tag_old = cell >> RHO_BITS;
        uint32_t rho_old = cell & ((1u << RHO_BITS) - 1u);
        bool event = (tag_old != b.win) || (rho > (int)rho_old);
        if (tag_old != b.win)
            b.hll[r] = (uint8_t)((b.win << RHO_BITS) | (uint32_t)rho);
        else if (rho > (int)rho_old)
            b.hll[r] = (uint8_t)((b.win << RHO_BITS) | (uint32_t)rho);
        
        int64_t c = (int64_t)b.C + (event ? LLR_NEW : LLR_REP);
        if (c < 0) c = 0;
        if (c > (int64_t)C_MAX) c = (int64_t)C_MAX;
        b.C = (uint32_t)c;
        
        b.n_new += event ? 1u : 0u;
        if (b.n_new > 0xFFu) b.n_new = 0xFFu;
        b.pkt += 1u;
        if (b.pkt > PKT_MAX) b.pkt = PKT_MAX;
        b.epoch = g;  
        
        
        int64_t gate = (int64_t)K_ALARM;
        if (USE_GATE && 2 * (int64_t)b.n_ewma > gate) gate = 2 * (int64_t)b.n_ewma;
        if (USE_GATE && b.n_ewma < N_EWMA_QUIET && (int64_t)K_ALARM_QUIET > gate)
            gate = (int64_t)K_ALARM_QUIET;
        a1 = USE_D1 && b.C >= H_FP && (int64_t)b.n_new >= gate;
        
        a2 = USE_D2 && b.pkt >= P_MIN && (int64_t)b.pkt >= (int64_t)D2_MULT * b.pkt_ewma &&
             (int64_t)b.n_new >=
                 std::max<int64_t>((int64_t)K_FLOOD, USE_GATE ? 2 * (int64_t)b.n_ewma : 0) &&
             b.d2_held != 0;
    }

    
    static void up(std::vector<SweepDump::B>& level, std::vector<Salvage>& salvage,
                   uint32_t key, uint32_t r, int rho, uint8_t g, uint32_t seed) {
        uint32_t i = pfx_hash(key, seed) % (uint32_t)level.size();  
        SweepDump::B& b = level[i];
        if (!b.present) {  
            b = SweepDump::B{};
            b.present = true;
            b.key = key;
            b.epoch = g;
            b.win = 1;
        } else if (b.key != key) {  
            if (!(b.pkt < P_MIN && b.C < H_FP)) return;  
            salvage.push_back({b.key, b.a1, b.a2});      
            b = SweepDump::B{};
            b.present = true;
            b.key = key;
            b.epoch = g;
            b.win = 1;
        }
        bool a1, a2;
        process(b, r, rho, g, a1, a2);
        
        if (a1) b.a1++;
        if (a2) b.a2++;
    }

    
    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)s;   
        (void)pkt_i;
        uint8_t g = (uint8_t)((ts_ns >> 32) & 0xFFu);  
        
        uint32_t h = pfx_hash(d, 0x33u);
        uint32_t r = h & (HLL_M - 1u);
        uint32_t v = h >> 5;
        int rho = 27 - bit_length(v);  
        up(l1_, salvage_l1_, (d >> 8) << 8, r, rho, g, 0x11u);
        if (USE_L2) up(l2_, salvage_l2_, (d >> 16) << 16, r, rho, g, 0x22u);
    }

    void scores(std::vector<std::pair<uint64_t, double>>& out) const override { (void)out; }
    const char* name() const override { return "sweep"; }

    
    
    SweepDump dump() const {
        SweepDump d;
        d.l1 = l1_;
        d.l2 = l2_;
        for (auto& b : d.l1)
            if (b.present)
                for (const auto& sv : salvage_l1_)
                    if (sv.key == b.key) {
                        b.a1 += sv.a1;
                        b.a2 += sv.a2;
                    }
        for (auto& b : d.l2)
            if (b.present)
                for (const auto& sv : salvage_l2_)
                    if (sv.key == b.key) {
                        b.a1 += sv.a1;
                        b.a2 += sv.a2;
                    }
        return d;
    }
};

inline std::unique_ptr<SweepCpp> create_sweep(int budget_kb, int n_pfx) {
    return std::make_unique<SweepCpp>(budget_kb, n_pfx);
}
}  
