





#pragma once
#include <cstdint>
#include <cstring>

namespace bench {

constexpr uint32_t GOLDEN = 0x9E3779B9u;

inline uint32_t bob_hash(const uint8_t* key, size_t n, uint32_t seed) {
    uint32_t a = GOLDEN, b = GOLDEN, c = seed;
    size_t i = 0;
    while (i + 12 <= n) {
        a += (uint32_t)key[i] | ((uint32_t)key[i + 1] << 8) |
             ((uint32_t)key[i + 2] << 16) | ((uint32_t)key[i + 3] << 24);
        b += (uint32_t)key[i + 4] | ((uint32_t)key[i + 5] << 8) |
             ((uint32_t)key[i + 6] << 16) | ((uint32_t)key[i + 7] << 24);
        c += (uint32_t)key[i + 8] | ((uint32_t)key[i + 9] << 8) |
             ((uint32_t)key[i + 10] << 16) | ((uint32_t)key[i + 11] << 24);
        a = (a - b - c) ^ (c >> 13);
        b = (b - c - a) ^ (a << 8);
        c = (c - a - b) ^ (b >> 13);
        a = (a - b - c) ^ (c >> 12);
        b = (b - c - a) ^ (a << 16);
        c = (c - a - b) ^ (b >> 5);
        a = (a - b - c) ^ (c >> 3);
        b = (b - c - a) ^ (a << 10);
        c = (c - a - b) ^ (b >> 15);
        i += 12;
    }
    c += (uint32_t)n;
    const uint8_t* t = key + i;
    size_t tl = n - i;
    if (tl >= 11) c += (uint32_t)t[10] << 24;
    if (tl >= 10) c += (uint32_t)t[9] << 16;
    if (tl >= 9)  c += (uint32_t)t[8] << 8;
    if (tl >= 8)  b += (uint32_t)t[7] << 24;
    if (tl >= 7)  b += (uint32_t)t[6] << 16;
    if (tl >= 6)  b += (uint32_t)t[5] << 8;
    if (tl >= 5)  b += (uint32_t)t[4];
    if (tl >= 4)  a += (uint32_t)t[3] << 24;
    if (tl >= 3)  a += (uint32_t)t[2] << 16;
    if (tl >= 2)  a += (uint32_t)t[1] << 8;
    if (tl >= 1)  a += (uint32_t)t[0];
    a = (a - b - c) ^ (c >> 13);
    b = (b - c - a) ^ (a << 8);
    c = (c - a - b) ^ (b >> 13);
    a = (a - b - c) ^ (c >> 12);
    b = (b - c - a) ^ (a << 16);
    c = (c - a - b) ^ (b >> 5);
    a = (a - b - c) ^ (c >> 3);
    b = (b - c - a) ^ (a << 10);
    c = (c - a - b) ^ (b >> 15);
    return c;
}


inline uint32_t bob_hash_u32(uint32_t v, uint32_t seed) {
    uint8_t k[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    return bob_hash(k, 4, seed);
}

inline uint32_t bob_hash_u32x2(uint32_t a, uint32_t b, uint32_t seed) {
    uint8_t k[8] = {(uint8_t)a, (uint8_t)(a >> 8), (uint8_t)(a >> 16), (uint8_t)(a >> 24),
                    (uint8_t)b, (uint8_t)(b >> 8), (uint8_t)(b >> 16), (uint8_t)(b >> 24)};
    return bob_hash(k, 8, seed);
}


inline uint64_t flow_hash64(uint32_t src_ip, uint32_t dst_ip) {
    uint8_t k[8] = {(uint8_t)src_ip, (uint8_t)(src_ip >> 8), (uint8_t)(src_ip >> 16),
                    (uint8_t)(src_ip >> 24), (uint8_t)dst_ip, (uint8_t)(dst_ip >> 8),
                    (uint8_t)(dst_ip >> 16), (uint8_t)(dst_ip >> 24)};
    uint32_t lo = bob_hash(k, 8, 0xABu);
    uint32_t hi = bob_hash(k, 8, 0xCDu);
    return ((uint64_t)hi << 32) | lo;
}

inline uint32_t pfx_hash(uint32_t pfx, uint32_t seed) { return bob_hash_u32(pfx, seed); }


inline int bit_length(uint32_t v) {
    return v ? 32 - __builtin_clz(v) : 0;
}
inline int bit_length64(uint64_t v) {
    return v ? 64 - __builtin_clzll(v) : 0;
}


inline int tz32(uint32_t v) { return __builtin_ctz(v); }

}  
