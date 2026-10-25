

















#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "hash.hpp"

namespace cppdet {


constexpr uint32_t N_L1 = 7943;
constexpr uint32_t N_L2 = 3972;
constexpr uint32_t HLL_M = 32;
constexpr uint32_t RHO_BITS = 5;
constexpr uint32_t WIN_MASK = 7;
constexpr uint32_t C_MAX = 0xFFFF;
constexpr uint32_t PKT_MAX = 0xFFFF;
constexpr int64_t LLR_NEW = 38;
constexpr int64_t LLR_REP = -26;
constexpr uint32_t H_FP = 74;
constexpr uint32_t K_ALARM = 8;
constexpr uint32_t K_ALARM_QUIET = 12;
constexpr uint32_t N_EWMA_QUIET = 4;
constexpr uint32_t K_FLOOD = 6;
constexpr uint32_t EWMA_SHIFT = 3;
constexpr uint32_t P_MIN = 200;
constexpr uint32_t D2_MULT = 3;


constexpr uint32_t AGE_WIN = 4;
constexpr uint32_t COOLDOWN_WIN = 20;
constexpr uint32_t D2_CONFIRM_WINDOWS = 3;
constexpr uint32_t D2_CONFIRM_COUNT = 2;
constexpr uint64_t Q_LOOKBACK_WIN = 1677;   
constexpr uint64_t Q_WINDOW_WIN = 20117;    
constexpr uint32_t Q_MAX_K = 16;
constexpr double Q_GROWTH_MULT = 1.25;
constexpr int CROSS_W = 4;
constexpr int CROSS_K = 2;
constexpr uint32_t CROSS_NNEW_FLOOR = 12;
constexpr uint8_t DIST_LEVEL = 3;

inline int64_t py_rshift(int64_t x, int s) {
    return x >= 0 ? (x >> s) : -(((-x) + ((int64_t)1 << s) - 1) >> s);
}

struct Bucket {
    uint32_t key = 0;
    uint32_t epoch = 0;   
    uint32_t n_ewma = 0;
    uint32_t C = 0;
    uint32_t pkt = 0;
    uint32_t pkt_ewma = 0;
    uint8_t win = 0;
    uint8_t n_new = 0;
    uint8_t d2_held = 0;
    uint8_t present = 0;
    uint8_t hll[HLL_M] = {0};
};


struct Alarm {
    uint64_t ts_ns = 0;
    uint8_t level = 0;    
    uint32_t key = 0;
    const char* reason = "";
    uint32_t n_new = 0;
    uint32_t C = 0;
    uint32_t pkt = 0;
    uint64_t epoch = 0;   
};


enum RawReason : uint8_t { R_D1 = 0, R_D2 = 1, R_N12 = 2 };
struct RawAlarm {
    uint64_t ts_ns = 0;
    uint64_t epoch = 0;
    uint32_t key = 0;
    uint32_t n_new = 0;
    uint32_t C = 0;
    uint32_t pkt = 0;
    uint8_t level = 0;
    uint8_t reason = 0;   
};


static inline void bucket_process(Bucket& b, uint32_t r, int rho, uint8_t g, bool& a1,
                                  bool& a2) {
    if (b.epoch != g) {
        b.d2_held = ((int64_t)b.pkt >=
                         std::max<int64_t>((int64_t)P_MIN, (int64_t)D2_MULT * b.pkt_ewma) &&
                     (int64_t)b.n_new >= std::max<int64_t>((int64_t)K_FLOOD,
                                                            2 * (int64_t)b.n_ewma))
                        ? 1
                        : 0;
        b.n_ewma = (uint32_t)((int64_t)b.n_ewma +
                              py_rshift((int64_t)b.n_new - (int64_t)b.n_ewma, EWMA_SHIFT));
        b.pkt_ewma = (uint32_t)((int64_t)b.pkt_ewma +
                                py_rshift((int64_t)b.pkt - (int64_t)b.pkt_ewma,
                                          EWMA_SHIFT));
        b.n_new = 0;
        b.pkt = 0;
        b.C = 0;
        b.win = (uint8_t)((b.win + 1) & WIN_MASK);
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
    b.n_new = (uint8_t)std::min<uint32_t>(0xFFu, b.n_new + (event ? 1u : 0u));
    b.pkt = std::min<uint32_t>(PKT_MAX, b.pkt + 1u);
    b.epoch = g;
    int64_t gate = (int64_t)K_ALARM;
    if (2 * (int64_t)b.n_ewma > gate) gate = 2 * (int64_t)b.n_ewma;
    if (b.n_ewma < N_EWMA_QUIET && (int64_t)K_ALARM_QUIET > gate) gate = K_ALARM_QUIET;
    a1 = (b.C >= H_FP) && ((int64_t)b.n_new >= gate);
    a2 = (b.pkt >= P_MIN) && ((int64_t)b.pkt >= (int64_t)D2_MULT * b.pkt_ewma) &&
         ((int64_t)b.n_new >= std::max<int64_t>((int64_t)K_FLOOD, 2 * (int64_t)b.n_ewma)) &&
         (b.d2_held != 0);
}


struct PrefixState {
    std::deque<uint64_t> d2;      
    uint64_t last_emit = ~0ull;   
    struct EpRec {
        uint64_t epoch;
        uint32_t k;
        uint8_t reason;           
    };
    std::deque<EpRec> eps;        
    uint64_t quarantine_until = 0;
};

struct AlarmManager {
    bool enabled = true;
    bool quarantine = true;
    std::unordered_map<uint64_t, PrefixState> st;
    uint64_t n_d1 = 0, n_d2 = 0, n_suppressed_cd = 0, n_suppressed_q = 0,
             n_quarantined = 0, n_d2_unconfirmed = 0, n_d2_confirmed = 0;

    static inline uint64_t id(uint8_t level, uint32_t key) {
        return ((uint64_t)level << 32) | key;
    }
    PrefixState& get(uint8_t level, uint32_t key) { return st[id(level, key)]; }

    bool attack_evidence(const PrefixState& ps, uint64_t E) {
        uint32_t maxk = 0;
        std::vector<uint32_t> ks;
        for (const auto& e : ps.eps) {
            if (E >= e.epoch && E - e.epoch <= Q_LOOKBACK_WIN) {
                ks.push_back(e.k);
                if (e.k > maxk) maxk = e.k;
            }
        }
        if (!ks.empty() && maxk > Q_MAX_K) return true;             
        if (ks.size() >= 3 &&
            (double)ks.back() > Q_GROWTH_MULT * (double)std::max<uint32_t>(1, ks.front()))
            return true;                                            
        return false;
    }

    void process(const RawAlarm& a, std::vector<Alarm>& out) {
        if (a.reason != R_D1 && a.reason != R_D2) return;
        PrefixState& ps = get(a.level, a.key);
        if (enabled && a.reason == R_D2) {
            ps.d2.push_back(a.epoch);
            if (ps.d2.size() > 8) ps.d2.pop_front();
            uint64_t lo = a.epoch >= (D2_CONFIRM_WINDOWS - 1)
                              ? a.epoch - (D2_CONFIRM_WINDOWS - 1)
                              : 0;
            uint64_t seen[8];
            int ns = 0;
            bool confirmed = false;
            for (uint64_t e : ps.d2) {
                if (e < lo || e > a.epoch) continue;
                bool dup = false;
                for (int i = 0; i < ns; i++)
                    if (seen[i] == e) dup = true;
                if (dup) continue;
                seen[ns++] = e;
                if (ns >= (int)D2_CONFIRM_COUNT) {
                    confirmed = true;
                    break;
                }
            }
            if (!confirmed) {
                n_d2_unconfirmed++;
                return;
            }
            n_d2_confirmed++;
        }
        if (quarantine && ps.quarantine_until > a.epoch) {
            n_suppressed_q++;
            return;
        }
        if (ps.last_emit != ~0ull && a.epoch >= ps.last_emit &&
            a.epoch - ps.last_emit < COOLDOWN_WIN) {
            n_suppressed_cd++;
            return;
        }
        ps.last_emit = a.epoch;
        ps.eps.push_back(PrefixState::EpRec{a.epoch, a.n_new,
                                            (uint8_t)(a.reason == R_D1 ? 0 : 1)});
        if (ps.eps.size() > 64) ps.eps.pop_front();
        out.push_back(Alarm{a.ts_ns, a.level, a.key,
                            (a.reason == R_D1 ? "D1" : "D2"), a.n_new, a.C, a.pkt,
                            a.epoch});
        if (a.reason == R_D1)
            n_d1++;
        else
            n_d2++;
        if (quarantine) {
            int recent = 0;
            for (const auto& e : ps.eps)
                if (a.epoch >= e.epoch && a.epoch - e.epoch <= Q_LOOKBACK_WIN) recent++;
            if (recent >= 3 && !attack_evidence(ps, a.epoch)) {
                ps.quarantine_until = a.epoch + Q_WINDOW_WIN;
                n_quarantined++;
            }
        }
    }
};


struct Cross16 {
    bool enabled = true;
    struct Slot {
        uint64_t epoch = ~0ull;
        std::vector<uint32_t> p16;
    };
    Slot slots[CROSS_W];
    std::unordered_map<uint32_t, uint64_t> last;   
    uint64_t n_n12 = 0, n_d1 = 0, n_dist = 0, n_suppressed = 0;

    static inline uint32_t pfx16_of(uint32_t key24) { return (key24 >> 16) << 16; }

    void observe(const RawAlarm& a, std::vector<Alarm>& out) {
        if (!enabled) return;
        if (a.level != 1) return;
        if (a.reason == R_N12) {
            if (a.n_new < CROSS_NNEW_FLOOR) return;
            n_n12++;
        } else if (a.reason == R_D1) {
            n_d1++;
        } else {
            return;
        }
        Slot& s = slots[a.epoch % CROSS_W];
        if (s.epoch != a.epoch) {
            s.epoch = a.epoch;
            s.p16.clear();
        }
        uint32_t p = pfx16_of(a.key);
        if (std::find(s.p16.begin(), s.p16.end(), p) == s.p16.end()) s.p16.push_back(p);
        std::vector<uint32_t> uni;
        for (int i = 0; i < CROSS_W; i++) {
            const Slot& t = slots[i];
            if (t.epoch == ~0ull) continue;
            if (a.epoch >= t.epoch && a.epoch - t.epoch < (uint64_t)CROSS_W)
                uni.insert(uni.end(), t.p16.begin(), t.p16.end());
        }
        std::sort(uni.begin(), uni.end());
        uni.erase(std::unique(uni.begin(), uni.end()), uni.end());
        if ((int)uni.size() < CROSS_K) return;
        for (uint32_t q : s.p16) {
            auto it = last.find(q);
            if (it != last.end() && a.epoch >= it->second &&
                a.epoch - it->second < COOLDOWN_WIN) {
                n_suppressed++;
                continue;
            }
            last[q] = a.epoch;
            out.push_back(Alarm{a.ts_ns, DIST_LEVEL, q, "DIST", (uint32_t)uni.size(),
                                0, 0, a.epoch});
            n_dist++;
        }
    }
};


struct Level {
    std::vector<Bucket> v;
    uint32_t seed;
    Level(uint32_t n, uint32_t sd) : v(n), seed(sd) {}
    inline Bucket& at(uint32_t key) { return v[pfx_hash(key, seed) % (uint32_t)v.size()]; }
    void clear() { std::fill(v.begin(), v.end(), Bucket{}); }
};

class Detector {
public:
    explicit Detector(bool v1 = false) : v1_(v1), l1_(N_L1, 0x11u), l2_(N_L2, 0x22u) {
        alarms_.reserve(1 << 16);
        raw_.reserve(1 << 18);
        am_.enabled = !v1;
        am_.quarantine = !v1;
        x16_.enabled = !v1;
        v1_seen_.reserve(1 << 16);
        raw_seen_.reserve(1 << 18);
    }

    void reset() {
        l1_.clear();
        l2_.clear();
        alarms_.clear();
        raw_.clear();
        am_.st.clear();
        am_.n_d1 = am_.n_d2 = am_.n_suppressed_cd = am_.n_suppressed_q = 0;
        am_.n_quarantined = am_.n_d2_unconfirmed = am_.n_d2_confirmed = 0;
        x16_.last.clear();
        for (auto& s : x16_.slots) {
            s.epoch = ~0ull;
            s.p16.clear();
        }
        x16_.n_n12 = x16_.n_d1 = x16_.n_dist = x16_.n_suppressed = 0;
        v1_seen_.clear();
        raw_seen_.clear();
        raw_d1_ = raw_d2_ = raw_n12_ = 0;
        n_pkts_ = 0;
        finalized_ = false;
    }

    inline void process(uint64_t ts_ns, uint32_t dst, uint32_t src) {
        (void)src;
        uint8_t g = (uint8_t)((ts_ns >> 32) & 0xFFu);
        uint64_t E = ts_ns >> 32;
        uint32_t h = pfx_hash(dst, 0x33u);
        uint32_t r = h & (HLL_M - 1u);
        uint32_t v = h >> 5;
        int rho = 27 - bit_length(v);
        up(l1_, 1, (dst >> 8) << 8, r, rho, g, E, ts_ns);
        up(l2_, 2, (dst >> 16) << 16, r, rho, g, E, ts_ns);
        n_pkts_++;
    }

    void finalize() {
        if (v1_ || finalized_) return;
        finalized_ = true;
        std::stable_sort(raw_.begin(), raw_.end(),
                         [](const RawAlarm& a, const RawAlarm& b) {
                             if (a.ts_ns != b.ts_ns) return a.ts_ns < b.ts_ns;
                             if (a.epoch != b.epoch) return a.epoch < b.epoch;
                             if (a.level != b.level) return a.level < b.level;
                             if (a.key != b.key) return a.key < b.key;
                             return a.reason < b.reason;
                         });
        for (const auto& a : raw_) {
            x16_.observe(a, alarms_);
            am_.process(a, alarms_);
        }
        std::stable_sort(alarms_.begin(), alarms_.end(),
                         [](const Alarm& a, const Alarm& b) {
                             if (a.ts_ns != b.ts_ns) return a.ts_ns < b.ts_ns;
                             if (a.level != b.level) return a.level < b.level;
                             return a.key < b.key;
                         });
    }

    const std::vector<Alarm>& alarms() {
        finalize();
        return alarms_;
    }
    uint64_t n_pkts() const { return n_pkts_; }
    bool v1() const { return v1_; }
    size_t n_raw() const { return raw_.size(); }
    size_t n_raw_d1() const { return raw_d1_; }
    size_t n_raw_d2() const { return raw_d2_; }
    size_t n_raw_n12() const { return raw_n12_; }
    uint64_t n_d1() const { return am_.n_d1; }
    uint64_t n_d2() const { return am_.n_d2; }
    uint64_t n_dist() const { return x16_.n_dist; }
    uint64_t n_suppressed_cd() const { return am_.n_suppressed_cd + x16_.n_suppressed; }
    uint64_t n_suppressed_q() const { return am_.n_suppressed_q; }
    uint64_t n_quarantined() const { return am_.n_quarantined; }
    uint64_t n_d2_unconfirmed() const { return am_.n_d2_unconfirmed; }

private:
    struct V1Key {
        uint64_t epoch;
        uint32_t key;
        uint8_t level;
        bool operator==(const V1Key& o) const {
            return epoch == o.epoch && key == o.key && level == o.level;
        }
    };
    struct V1Hash {
        size_t operator()(const V1Key& k) const {
            uint64_t x = k.epoch * 0x9E3779B97F4A7C15ull;
            x ^= ((uint64_t)k.key << 1) ^ k.level;
            return (size_t)(x ^ (x >> 29));
        }
    };
    struct RawKey {
        uint64_t epoch;
        uint32_t key;
        uint8_t level;
        uint8_t reason;
        bool operator==(const RawKey& o) const {
            return epoch == o.epoch && key == o.key && level == o.level &&
                   reason == o.reason;
        }
    };
    struct RawHash {
        size_t operator()(const RawKey& k) const {
            uint64_t x = k.epoch * 0x9E3779B97F4A7C15ull;
            x ^= ((uint64_t)k.key << 3) ^ ((uint64_t)k.level << 1) ^ k.reason;
            return (size_t)(x ^ (x >> 29));
        }
    };

    void v1_emit(uint8_t level, uint32_t key, uint64_t E, uint64_t ts, uint32_t n_new,
                 uint32_t C, uint32_t pkt, const char* reason) {
        V1Key k{E, key, level};
        if (!v1_seen_.insert(k).second) return;
        alarms_.push_back(Alarm{ts, level, key, reason, n_new, C, pkt, E});
        if (reason[0] == 'D' && reason[1] == '1') am_.n_d1++;
        else if (reason[0] == 'D' && reason[1] == '2') am_.n_d2++;
    }

    void raw_add(uint8_t level, uint32_t key, uint64_t E, uint64_t ts, uint32_t n_new,
                 uint32_t C, uint32_t pkt, uint8_t reason) {
        RawKey k{E, key, level, reason};
        if (!raw_seen_.insert(k).second) return;
        raw_.push_back(RawAlarm{ts, E, key, n_new, C, pkt, level, reason});
        if (reason == R_D1) raw_d1_++;
        else if (reason == R_D2) raw_d2_++;
        else raw_n12_++;
    }

    void up(Level& lv, uint8_t lev, uint32_t key, uint32_t r, int rho, uint8_t g,
            uint64_t E, uint64_t ts) {
        Bucket& b = lv.at(key);
        if (!b.present) {
            b = Bucket{};
            b.present = 1;
            b.key = key;
            b.epoch = g;
            b.win = 1;
        } else if (b.key != key) {
            bool replace = (b.pkt < P_MIN && b.C < H_FP);
            if (!replace && !v1_) replace = (((g - b.epoch) & 0x1Fu) >= AGE_WIN);
            if (!replace) return;
            b = Bucket{};
            b.present = 1;
            b.key = key;
            b.epoch = g;
            b.win = 1;
        }
        uint8_t prev = b.n_new;
        bool a1, a2;
        bucket_process(b, r, rho, g, a1, a2);
        if (v1_) {
            if (a1) v1_emit(lev, key, E, ts, b.n_new, b.C, b.pkt, "D1");
            if (a2) v1_emit(lev, key, E, ts, b.n_new, b.C, b.pkt, "D2");
            return;
        }
        if (lev == 1 && prev < CROSS_NNEW_FLOOR && b.n_new >= CROSS_NNEW_FLOOR)
            raw_add(1, key, E, ts, b.n_new, b.C, b.pkt, R_N12);
        if (a1) raw_add(lev, key, E, ts, b.n_new, b.C, b.pkt, R_D1);
        if (a2) raw_add(lev, key, E, ts, b.n_new, b.C, b.pkt, R_D2);
    }

    bool v1_;
    Level l1_, l2_;
    AlarmManager am_;
    Cross16 x16_;
    std::vector<Alarm> alarms_;
    std::vector<RawAlarm> raw_;
    std::unordered_set<V1Key, V1Hash> v1_seen_;
    std::unordered_set<RawKey, RawHash> raw_seen_;
    size_t raw_d1_ = 0, raw_d2_ = 0, raw_n12_ = 0;
    uint64_t n_pkts_ = 0;
    bool finalized_ = false;
};

}  
