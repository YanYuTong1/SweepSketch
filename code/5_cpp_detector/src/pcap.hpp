










#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace cppdet {

struct PktRec {
    uint64_t ts_ns = 0;
    uint32_t dst = 0;
    uint32_t src = 0;
};

struct PcapStat {
    uint64_t total_records = 0;  
    uint64_t ipv4 = 0;           
    uint64_t skipped = 0;        
};

static inline uint32_t rd32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static inline uint32_t rd32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline uint64_t ns_from_ts_float(double ts) {
    
    double x = ts * 1e9;
    return (uint64_t)(x >= 0 ? (x + 0.5) : (x - 0.5));
}


static inline int parse_eth_ipv4(const uint8_t* pkt, uint32_t len, uint32_t linktype,
                                 uint32_t& s, uint32_t& d) {
    if (linktype == 101) {  
        if (len < 20 || (pkt[0] >> 4) != 4) return 0;
        s = rd32be(pkt + 12);
        d = rd32be(pkt + 16);
        return 1;
    }
    if (len < 34) return 0;
    uint32_t etype = ((uint32_t)pkt[12] << 8) | pkt[13];
    uint32_t off = 14;
    if (etype == 0x8100) {  
        if (len < 22) return 0;
        etype = ((uint32_t)pkt[16] << 8) | pkt[17];
        off = 18;
    } else if (etype == 0x88A8) {  
        if (len < 26) return 0;
        etype = ((uint32_t)pkt[20] << 8) | pkt[21];
        off = 22;
    }
    if (etype != 0x0800 || len < off + 20) return 0;
    s = rd32be(pkt + off + 12);
    d = rd32be(pkt + off + 16);
    return 1;
}



inline bool load_pcap(const std::string& path, uint64_t max_pkts, std::vector<PktRec>& out,
                      PcapStat& st) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4) {
        fclose(f);
        return false;
    }
    out.clear();
    out.reserve(1u << 20);

    if (memcmp(magic, "\x0a\x0d\x0d\x0a", 4) == 0 || memcmp(magic, "\x0d\x0a\x0d\x0a", 4) == 0) {
        
        fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> buf;
        buf.reserve(1 << 16);
        while (out.size() < max_pkts) {
            uint8_t bh[8];
            if (fread(bh, 1, 8, f) != 8) break;
            uint32_t btype = rd32le(bh);
            uint32_t blen = rd32le(bh + 4);
            if (blen < 12 || blen > (1u << 24)) break;
            uint32_t rest = blen - 8;  
            if (btype == 0x0A0D0D0Au || btype == 0x00000001u) {  
                if (rest && fseek(f, rest, SEEK_CUR) != 0) break;
                continue;
            }
            if (btype != 0x00000006u) break;  
            if (buf.size() < rest) buf.resize(rest);
            if (rest && fread(buf.data(), 1, rest, f) != rest) break;
            if (rest < 24) break;
            uint64_t ts_high = rd32le(buf.data() + 4);
            uint64_t ts_low = rd32le(buf.data() + 8);
            uint64_t ts_us = (ts_high << 32) | ts_low;
            uint32_t caplen = rd32le(buf.data() + 12);
            st.total_records++;
            if (caplen < 34 || caplen > 10000 || 20 + caplen > rest) {
                st.skipped++;
                continue;
            }
            uint32_t s, d;
            if (parse_eth_ipv4(buf.data() + 20, caplen,  0, s, d)) {
                double ts = (double)ts_us / 1e6;
                out.push_back({ns_from_ts_float(ts), d, s});
                st.ipv4++;
            } else {
                st.skipped++;
            }
        }
        fclose(f);
        return true;
    }

    
    uint32_t m = rd32le(magic);
    bool le;
    uint64_t frac_ns;  
    if (m == 0xA1B2C3D4u) {
        le = true;
        frac_ns = 1000;
    } else if (m == 0xD4C3B2A1u) {
        le = false;
        frac_ns = 1000;
    } else if (m == 0xA1B23C4Du) {
        le = true;
        frac_ns = 1;
    } else if (m == 0x4D3CB2A1u) {
        le = false;
        frac_ns = 1;
    } else {
        fclose(f);
        return false;
    }
    uint8_t gh[20];
    if (fread(gh, 1, 20, f) != 20) {
        fclose(f);
        return false;
    }
    uint32_t linktype = le ? rd32le(gh + 16) : rd32be(gh + 16);
    std::vector<uint8_t> buf;
    buf.reserve(1 << 16);
    while (out.size() < max_pkts) {
        uint8_t rh[16];
        if (fread(rh, 1, 16, f) != 16) break;
        uint32_t ts_sec = le ? rd32le(rh) : rd32be(rh);
        uint32_t ts_frac = le ? rd32le(rh + 4) : rd32be(rh + 4);
        uint32_t caplen = le ? rd32le(rh + 8) : rd32be(rh + 8);
        if (caplen > (1u << 28)) break;
        if (buf.size() < caplen) buf.resize(caplen);
        if (caplen && fread(buf.data(), 1, caplen, f) != caplen) break;
        st.total_records++;
        uint32_t s, d;
        if (caplen < 34 && linktype != 101) {
            st.skipped++;
            continue;
        }
        if (parse_eth_ipv4(buf.data(), caplen, linktype, s, d)) {
            
            double ts = frac_ns == 1000 ? ((double)ts_sec + (double)ts_frac / 1e6)
                                        : ((double)ts_sec + (double)ts_frac / 1e9);
            out.push_back({ns_from_ts_float(ts), d, s});
            st.ipv4++;
        } else {
            st.skipped++;
        }
    }
    fclose(f);
    return true;
}


inline bool load_bin(const std::string& path, uint64_t max_pkts, std::vector<PktRec>& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    size_t n = (size_t)(sz / 16);
    if (max_pkts < n) n = (size_t)max_pkts;
    out.resize(n);
    size_t got = fread(out.data(), 16, n, f);
    fclose(f);
    out.resize(got);
    return true;
}

inline bool dump_bin(const std::string& path, const std::vector<PktRec>& pkts) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t n = pkts.size();
    for (size_t i = 0; i < n; i++) {
        fwrite(&pkts[i].ts_ns, 8, 1, f);
        fwrite(&pkts[i].dst, 4, 1, f);
        fwrite(&pkts[i].src, 4, 1, f);
    }
    fclose(f);
    return true;
}




template <typename F>
inline bool stream_pcap(const std::string& path, uint64_t max_pkts, F cb, PcapStat& st) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4) {
        fclose(f);
        return false;
    }
    uint64_t n = 0;
    if (memcmp(magic, "\x0a\x0d\x0d\x0a", 4) == 0 || memcmp(magic, "\x0d\x0a\x0d\x0a", 4) == 0) {
        fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> buf;
        buf.reserve(1 << 16);
        while (n < max_pkts) {
            uint8_t bh[8];
            if (fread(bh, 1, 8, f) != 8) break;
            uint32_t btype = rd32le(bh);
            uint32_t blen = rd32le(bh + 4);
            if (blen < 12 || blen > (1u << 24)) break;
            uint32_t rest = blen - 8;
            if (btype == 0x0A0D0D0Au || btype == 0x00000001u) {
                if (rest && fseek(f, rest, SEEK_CUR) != 0) break;
                continue;
            }
            if (btype != 0x00000006u) break;
            if (buf.size() < rest) buf.resize(rest);
            if (rest && fread(buf.data(), 1, rest, f) != rest) break;
            if (rest < 24) break;
            uint64_t ts_high = rd32le(buf.data() + 4);
            uint64_t ts_low = rd32le(buf.data() + 8);
            uint64_t ts_us = (ts_high << 32) | ts_low;
            uint32_t caplen = rd32le(buf.data() + 12);
            st.total_records++;
            if (caplen < 34 || caplen > 10000 || 20 + caplen > rest) {
                st.skipped++;
                continue;
            }
            uint32_t s, d;
            if (parse_eth_ipv4(buf.data() + 20, caplen, 0, s, d)) {
                double ts = (double)ts_us / 1e6;
                cb(ns_from_ts_float(ts), d, s);
                st.ipv4++;
                n++;
            } else {
                st.skipped++;
            }
        }
        fclose(f);
        return true;
    }
    uint32_t m = rd32le(magic);
    bool le;
    uint64_t frac_ns;
    if (m == 0xA1B2C3D4u) { le = true; frac_ns = 1000; }
    else if (m == 0xD4C3B2A1u) { le = false; frac_ns = 1000; }
    else if (m == 0xA1B23C4Du) { le = true; frac_ns = 1; }
    else if (m == 0x4D3CB2A1u) { le = false; frac_ns = 1; }
    else { fclose(f); return false; }
    uint8_t gh[20];
    if (fread(gh, 1, 20, f) != 20) { fclose(f); return false; }
    uint32_t linktype = le ? rd32le(gh + 16) : rd32be(gh + 16);
    std::vector<uint8_t> buf;
    buf.reserve(1 << 16);
    while (n < max_pkts) {
        uint8_t rh[16];
        if (fread(rh, 1, 16, f) != 16) break;
        uint32_t ts_sec = le ? rd32le(rh) : rd32be(rh);
        uint32_t ts_frac = le ? rd32le(rh + 4) : rd32be(rh + 4);
        uint32_t caplen = le ? rd32le(rh + 8) : rd32be(rh + 8);
        if (caplen > (1u << 28)) break;
        if (buf.size() < caplen) buf.resize(caplen);
        if (caplen && fread(buf.data(), 1, caplen, f) != caplen) break;
        st.total_records++;
        uint32_t s, d;
        if (caplen < 34 && linktype != 101) { st.skipped++; continue; }
        if (parse_eth_ipv4(buf.data(), caplen, linktype, s, d)) {
            double ts = frac_ns == 1000 ? ((double)ts_sec + (double)ts_frac / 1e6)
                                        : ((double)ts_sec + (double)ts_frac / 1e9);
            cb(ns_from_ts_float(ts), d, s);
            st.ipv4++;
            n++;
        } else {
            st.skipped++;
        }
    }
    fclose(f);
    return true;
}


template <typename F>
inline bool stream_bin(const std::string& path, uint64_t max_pkts, F cb, uint64_t& n_out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    constexpr size_t CH = 1 << 16;
    std::vector<PktRec> buf(CH);
    uint64_t n = 0;
    while (n < max_pkts) {
        size_t want = (size_t)std::min<uint64_t>(CH, max_pkts - n);
        size_t got = fread(buf.data(), 16, want, f);
        for (size_t i = 0; i < got; i++) {
            cb(buf[i].ts_ns, buf[i].dst, buf[i].src);
            n++;
        }
        if (got < want) break;
    }
    fclose(f);
    n_out = n;
    return true;
}

}  
