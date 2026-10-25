
















#pragma once
#include "methods.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace bench {
namespace trw_detail {




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
    bool contains(uint64_t k) const { return find(k) >= 0; }
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
    
    
    
    void erase(uint64_t k) {
        int64_t i = find(k);
        if (i < 0) return;
        uint32_t mask = (uint32_t)(keys.size() - 1);
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
                vals[cur] = vals[nxt];
                occ[cur] = 1;
                occ[nxt] = 0;
                cur = nxt;
            }
            nxt = (nxt + 1) & mask;
        }
    }
    
    void inc(uint64_t k) {
        int64_t i = find(k);
        if (i >= 0) {
            vals[i] += 1;
            return;
        }
        insert(k, 1);
    }
    void grow() {
        FlatMap tmp((uint32_t)keys.size() * 2);
        for (uint64_t i = 0; i < keys.size(); i++)
            if (occ[i] == 1) tmp.insert(keys[i], vals[i]);
        *this = std::move(tmp);
    }
};

}  

struct TRWCpp : Method {
    
    static constexpr double TH0 = 0.8, TH1 = 0.2;
    static constexpr double ETA1 = 5.0, ETA0 = -5.0;
    
    inline static const double D_NEW = std::log((1.0 - TH1) / (1.0 - TH0));
    inline static const double D_REP = std::log(TH1 / TH0);

    
    struct HNode {
        double lam;
        uint64_t ver;
        uint32_t src;
    };
    
    static bool node_before(const HNode& a, const HNode& b) {
        if (a.lam != b.lam) return a.lam < b.lam;
        if (a.ver != b.ver) return a.ver < b.ver;
        return a.src < b.src;
    }
    struct HMin {  
        bool operator()(const HNode& a, const HNode& b) const { return node_before(b, a); }
    };

    int max_entries;
    trw_detail::FlatMap<double> lam;    
    trw_detail::FlatMap<uint64_t> ver;  
    trw_detail::FlatMap<uint8_t> pairs; 
    trw_detail::FlatMap<uint8_t> seen;  
                                        
                                        
    std::vector<HNode> heap;

    static uint64_t ceil_pow2(uint64_t v) {
        uint64_t p = 8;
        while (p < v) p <<= 1;
        return p;
    }

    explicit TRWCpp(int budget_kb, int n_pfx)
        : max_entries(std::max(16, budget_kb * 1024 / 8)),
          lam((uint32_t)ceil_pow2((uint64_t)max_entries * 2)),
          ver(65536),
          pairs(65536),
          seen(65536) {
        (void)n_pfx;
        
        heap.reserve((size_t)max_entries * 4 + 2);
    }

    
    
    void rebuild_heap() {
        heap.clear();
        for (uint64_t i = 0; i < lam.keys.size(); i++) {
            if (lam.occ[i] == 1)
                heap.push_back({lam.vals[i], ver.get(lam.keys[i]),
                                (uint32_t)lam.keys[i]});
        }
        std::make_heap(heap.begin(), heap.end(), HMin{});
    }

    
    void push_lam(uint32_t s) {
        heap.push_back({lam.get(s), ver.get(s), s});
        std::push_heap(heap.begin(), heap.end(), HMin{});
        uint64_t th = 4 * std::max<uint64_t>(lam.n, 1);
        if (heap.size() > th) rebuild_heap();
    }

    
    void evict() {
        while (true) {
            if (heap.empty()) rebuild_heap();  
            std::pop_heap(heap.begin(), heap.end(), HMin{});
            HNode nd = heap.back();
            heap.pop_back();
            int64_t v = ver.find(nd.src);
            if (v >= 0 && ver.vals[v] == nd.ver && lam.contains(nd.src)) {
                lam.erase(nd.src);
                return;  
            }
        }
    }

    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)pkt_i;
        (void)ts_ns;
        uint64_t pk = ((uint64_t)s << 32) | d;
        if (pairs.contains(pk)) return;  
        pairs.insert(pk, 1);
        int64_t li = lam.find(s);
        if (li >= 0) {
            
            
            double nlam = lam.vals[li] + (seen.contains(pk) ? D_REP : D_NEW);
            if (nlam <= ETA0) {  
                lam.erase(s);
            } else {
                lam.vals[li] = nlam;
                ver.inc(s);          
                seen.insert(pk, 1);  
                push_lam(s);
            }
            return;
        }
        if (lam.n >= (uint64_t)max_entries) evict();  
        lam.insert(s, D_NEW);
        ver.inc(s);                  
        seen.insert(pk, 1);          
        push_lam(s);
    }

    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        
        for (uint64_t i = 0; i < lam.keys.size(); i++)
            if (lam.occ[i] == 1) out.push_back({lam.keys[i], lam.vals[i]});
    }
    const char* name() const override { return "trw"; }
};

inline std::unique_ptr<Method> create_trw(int budget_kb, int n_pfx) {
    return std::make_unique<TRWCpp>(budget_kb, n_pfx);
}
}  
