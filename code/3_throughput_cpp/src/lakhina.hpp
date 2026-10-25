









#pragma once
#include "methods.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace bench {
namespace lk_detail {




template <class V>
struct FlatMap {
    std::vector<uint64_t> keys;
    std::vector<V> vals;
    std::vector<uint8_t> occ;  
    uint64_t n = 0;

    explicit FlatMap(uint32_t init_cap = 64) {
        uint64_t cap = 8;
        while (cap < init_cap) cap <<= 1;
        keys.assign(cap, 0);
        vals.resize(cap);
        occ.assign(cap, 0);
    }
    static uint32_t mix(uint64_t x) {
        x ^= x >> 33;
        x *= 0xFF51AFD7ED558CCDu;
        x ^= x >> 33;
        return (uint32_t)x;
    }
    int64_t find(uint64_t k) const {
        uint32_t mask = (uint32_t)(keys.size() - 1);
        uint32_t i = mix(k) & mask;
        while (occ[i] != 0) {
            if (keys[i] == k) return (int64_t)i;
            i = (i + 1) & mask;
        }
        return -1;
    }
    V get(uint64_t k) const { return vals[find(k)]; }  
    int64_t insert(uint64_t k, V v) {
        if ((n + 1) * 2 > keys.size()) grow();  
        uint32_t mask = (uint32_t)(keys.size() - 1);
        uint32_t i = mix(k) & mask;
        while (occ[i] != 0) {
            if (keys[i] == k) {
                vals[i] = v;
                return (int64_t)i;
            }
            i = (i + 1) & mask;
        }
        keys[i] = k;
        vals[i] = v;
        occ[i] = 1;
        n++;
        return (int64_t)i;
    }
    void grow() {
        FlatMap tmp((uint32_t)keys.size() * 2);
        for (uint64_t i = 0; i < keys.size(); i++)
            if (occ[i] == 1) tmp.insert(keys[i], vals[i]);
        *this = std::move(tmp);
    }
};

}  

struct LakhinaCpp : Method {
    struct Row {
        std::vector<uint32_t> order;  
    };

    lk_detail::FlatMap<uint32_t> pfx2row;  
    lk_detail::FlatMap<uint64_t> counts;   
    std::vector<Row> rows;

    explicit LakhinaCpp(int budget_kb, int n_pfx) : pfx2row(512), counts(65536) {
        (void)budget_kb;  
        int np = std::max(n_pfx, 1);
        
        pfx2row = lk_detail::FlatMap<uint32_t>((uint32_t)std::min((uint64_t)np * 2 + 1,
                                                                 (uint64_t)0x80000000u));
        rows.reserve((size_t)np);
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)s;
        (void)pkt_i;
        (void)ts_ns;
        
        uint32_t pfx = (d >> 8) << 8;
        int64_t pi = pfx2row.find(pfx);
        uint32_t row;
        if (pi >= 0) {
            row = pfx2row.vals[pi];
        } else {
            row = (uint32_t)rows.size();
            rows.push_back({});
            pfx2row.insert(pfx, row);
        }
        int64_t ci = counts.find(d);
        if (ci >= 0) {
            counts.vals[ci] += 1;
        } else {
            counts.insert(d, 1);
            rows[row].order.push_back(d);
        }
    }

    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        
        
        
        
        for (uint64_t i = 0; i < pfx2row.keys.size(); i++) {
            if (pfx2row.occ[i] != 1) continue;
            uint32_t pfx = (uint32_t)pfx2row.keys[i];
            const Row& r = rows[pfx2row.vals[i]];
            uint64_t tot = 0;
            for (uint32_t dd : r.order) tot += counts.get(dd);  
            double fr = 0.0, comp = 0.0;  
            for (uint32_t dd : r.order) {
                double f_item = (double)counts.get(dd) / (double)tot;
                f_item *= std::log2(f_item);  
                double t = fr + f_item;
                if (std::fabs(fr) >= std::fabs(f_item)) comp += (fr - t) + f_item;
                else comp += (f_item - t) + fr;
                fr = t;
            }
            double s = fr + comp;  
            out.push_back({(uint64_t)pfx, -s});
        }
    }
    const char* name() const override { return "lakhina"; }
};

inline std::unique_ptr<Method> create_lakhina(int budget_kb, int n_pfx) {
    return std::make_unique<LakhinaCpp>(budget_kb, n_pfx);
}
}  
