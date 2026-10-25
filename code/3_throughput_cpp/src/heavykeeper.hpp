











#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>
#include "bob_hash.hpp"
#include "methods.hpp"

namespace bench {

struct HeavyKeeperCpp : Method {
    
    static constexpr int D = 3;
    static constexpr int K = 512;
    static constexpr double DECAY = 1.0 / 1.08;  

    
    
    struct PosMap {
        static constexpr uint32_t CAP = 2048, MASK = CAP - 1, EMPTY = 0xFFFFFFFFu;
        uint32_t keys_[CAP];
        uint32_t vals_[CAP];
        PosMap() {
            for (uint32_t& k : keys_) k = EMPTY;
        }
        const uint32_t* find(uint32_t k) const {
            uint32_t i = bob_hash_u32(k, 0x7B11u) & MASK;
            while (keys_[i] != EMPTY && keys_[i] != k) i = (i + 1) & MASK;
            return keys_[i] == k ? &vals_[i] : nullptr;
        }
        void set(uint32_t k, uint32_t v) {
            uint32_t i = bob_hash_u32(k, 0x7B11u) & MASK;
            while (keys_[i] != EMPTY && keys_[i] != k) i = (i + 1) & MASK;
            keys_[i] = k;
            vals_[i] = v;
        }
        void erase(uint32_t k) {
            uint32_t i = bob_hash_u32(k, 0x7B11u) & MASK;
            while (keys_[i] != EMPTY && keys_[i] != k) i = (i + 1) & MASK;
            keys_[i] = EMPTY;
            
            uint32_t j = (i + 1) & MASK;
            while (keys_[j] != EMPTY) {
                uint32_t kk = keys_[j], vv = vals_[j];
                keys_[j] = EMPTY;
                uint32_t p = bob_hash_u32(kk, 0x7B11u) & MASK;
                while (keys_[p] != EMPTY) p = (p + 1) & MASK;
                keys_[p] = kk;
                vals_[p] = vv;
                j = (j + 1) & MASK;
            }
        }
    };

    struct Bucket {  
        uint32_t fp = 0;
        uint32_t cnt = 0;
    };
    struct HeapEntry {  
        uint32_t count = 0;
        uint32_t key = 0;
    };
    static bool hlt(const HeapEntry& a, const HeapEntry& b) {  
        return a.count != b.count ? a.count < b.count : a.key < b.key;
    }

    int width = 0;
    std::vector<Bucket> buckets;  
    std::vector<HeapEntry> heap;  
    PosMap pos;                   

    HeavyKeeperCpp(int budget_kb, int n_pfx) {
        (void)n_pfx;
        
        width = std::max(2, budget_kb * 1024 / (D * 8));
        buckets.assign((size_t)D * width, Bucket{0, 0});
        heap.reserve(K);  
    }

    
    void hswap(int i, int j) {
        uint32_t ki = heap[i].key, kj = heap[j].key;
        pos.set(ki, (uint32_t)j);
        pos.set(kj, (uint32_t)i);
        std::swap(heap[i], heap[j]);
    }
    void sift_up(int i) {
        while (i > 0) {
            int p = (i - 1) >> 1;
            if (hlt(heap[i], heap[p])) {
                hswap(i, p);
                i = p;
            } else {
                break;
            }
        }
    }
    void sift_down(int i) {
        int n = (int)heap.size();
        while (true) {
            int l = 2 * i + 1, r = 2 * i + 2, m = i;
            if (l < n && hlt(heap[l], heap[m])) m = l;
            if (r < n && hlt(heap[r], heap[m])) m = r;
            if (m == i) break;
            hswap(i, m);
            i = m;
        }
    }
    void push(uint32_t count, uint32_t key) {
        heap.push_back(HeapEntry{count, key});
        pos.set(key, (uint32_t)heap.size() - 1);
        sift_up((int)heap.size() - 1);
    }
    void replace_min(uint32_t count, uint32_t key) {
        pos.erase(heap[0].key);
        heap[0] = HeapEntry{count, key};
        pos.set(key, 0);
        sift_down(0);
    }
    void fix(uint32_t key, uint32_t count) {
        uint32_t i = *pos.find(key);
        uint32_t old = heap[i].count;
        heap[i] = HeapEntry{count, key};
        if (count < old) sift_up((int)i);
        else sift_down((int)i);
    }

    
    void insert(uint32_t s, uint32_t d, uint64_t pkt_i, uint64_t ts_ns) override {
        (void)s; (void)ts_ns;
        uint32_t key = (d >> 8) << 8;
        bool in_heap = pos.find(key) != nullptr;   
        uint32_t hmin = heap.empty() ? 0 : heap[0].count;
        uint32_t max_count = 0;
        for (int i = 0; i < D; i++) {
            Bucket& b = buckets[(size_t)i * width +
                                bob_hash_u32(key, 0xA100 + i) % (uint32_t)width];
            if (b.cnt == 0) {
                b.fp = key;
                b.cnt = 1;
                if (1 > max_count) max_count = 1;
            } else if (b.fp == key) {
                if (in_heap || b.cnt <= hmin) b.cnt += 1;  
                if (b.cnt > max_count) max_count = b.cnt;
            } else {
                
                uint8_t k[12] = {(uint8_t)key,        (uint8_t)(key >> 8),
                                 (uint8_t)(key >> 16), (uint8_t)(key >> 24),
                                 (uint8_t)pkt_i,        (uint8_t)(pkt_i >> 8),
                                 (uint8_t)(pkt_i >> 16), (uint8_t)(pkt_i >> 24),
                                 (uint8_t)i,           (uint8_t)(i >> 8),
                                 (uint8_t)(i >> 16),   (uint8_t)(i >> 24)};
                double r = (double)bob_hash(k, 12, 0xA200) / 4294967296.0;  
                if (r < std::pow(DECAY, (double)b.cnt)) {  
                    b.cnt -= 1;
                    if (b.cnt == 0) {
                        b.fp = key;
                        b.cnt = 1;
                        if (1 > max_count) max_count = 1;
                    }
                }
            }
        }
        if (in_heap) fix(key, max_count);
        else if ((int)heap.size() < K) push(max_count, key);
        else if (max_count > heap[0].count) replace_min(max_count, key);
    }

    
    void scores(std::vector<std::pair<uint64_t, double>>& out) const override {
        out.clear();
        for (const HeapEntry& e : heap) out.emplace_back((uint64_t)e.key, (double)e.count);
    }
    const char* name() const override { return "heavykeeper"; }
};

inline std::unique_ptr<Method> create_heavykeeper(int budget_kb, int n_pfx) {
    return std::make_unique<HeavyKeeperCpp>(budget_kb, n_pfx);
}
}  
