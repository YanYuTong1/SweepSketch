










#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifdef __APPLE__
#include <sys/resource.h>
#else
#include <sys/resource.h>
#endif

#include "detector.hpp"
#include "pcap.hpp"

using namespace cppdet;

static double now_s() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

static double rss_mb() {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
#ifdef __APPLE__
    return (double)ru.ru_maxrss / (1024.0 * 1024.0);
#else
    return (double)ru.ru_maxrss / 1024.0;
#endif
}

static double pct(std::vector<double>& v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t i = (size_t)(q * (double)(v.size() - 1));
    return v[i];
}

struct Opts {
    std::string pcap, bin, alarms, bench_csv;
    std::string workload = "input";
    std::string gen_synth;
    uint64_t max_pkts = 1ull << 60;
    uint64_t n_synth = 10000000;
    uint32_t prefixes = 5000;
    uint64_t seed = 20261022;
    int repeats = 3;
    uint64_t warmup = 100000;
    bool v1 = false, bench = false, bench_e2e = false, quiet = false;
};

static void usage(const char* argv0) {
    fprintf(stderr,
            "usage: %s (--pcap F | --bin F | --gen-synth OUT.bin)\n"
            "       [--alarms OUT.csv] [--bench] [--bench-e2e] [--bench-csv OUT.csv]\n"
            "       [--repeats K] [--warmup N] [--max-pkts N] [--v1] [--workload NAME]\n"
            "       [--n N] [--prefixes P] [--seed S]\n",
            argv0);
}

static bool write_alarms(const std::string& path, const std::vector<Alarm>& alarms) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    fprintf(f, "ts,level,key,reason,n_new,C,pkt,epoch\n");
    for (const auto& a : alarms)
        fprintf(f, "%llu,%u,%u,%s,%u,%u,%u,%llu\n", (unsigned long long)a.ts_ns,
                (unsigned)a.level, (unsigned)a.key, a.reason, (unsigned)a.n_new,
                (unsigned)a.C, (unsigned)a.pkt, (unsigned long long)a.epoch);
    fclose(f);
    return true;
}

static void print_stats(Detector& d) {
    printf("[stats] n_pkts=%llu raw=%zu raw_d1=%zu raw_d2=%zu raw_n12=%zu "
           "episodes=%zu d1=%llu d2=%llu dist=%llu suppressed_cooldown=%llu "
           "suppressed_quarantine=%llu quarantined=%llu d2_unconfirmed=%llu "
           "rss_mb=%.1f v1=%d\n",
           (unsigned long long)d.n_pkts(), d.n_raw(), d.n_raw_d1(), d.n_raw_d2(),
           d.n_raw_n12(), d.alarms().size(), (unsigned long long)d.n_d1(),
           (unsigned long long)d.n_d2(), (unsigned long long)d.n_dist(),
           (unsigned long long)d.n_suppressed_cd(),
           (unsigned long long)d.n_suppressed_q(),
           (unsigned long long)d.n_quarantined(),
           (unsigned long long)d.n_d2_unconfirmed(), rss_mb(), d.v1() ? 1 : 0);
}

static void csv_header(FILE* f) {
    fprintf(f, "workload,input,mode,run,n_pkts,wall_s,mpps,chunk_pkts,ns_p50,ns_p99,"
               "rss_mb,alarms,v1\n");
}
static void csv_row(FILE* f, const std::string& wl, const std::string& input,
                    const char* mode, int run, uint64_t n, double wall, uint64_t chunk,
                    double p50, double p99, uint64_t alarms, int v1) {
    fprintf(f, "%s,%s,%s,%d,%llu,%.6f,%.4f,%llu,%.1f,%.1f,%.1f,%llu,%d\n", wl.c_str(),
            input.c_str(), mode, run, (unsigned long long)n, wall,
            wall > 0 ? (double)n / wall / 1e6 : 0.0, (unsigned long long)chunk, p50, p99,
            rss_mb(), (unsigned long long)alarms, v1);
}


static void bench_detect_only(const std::vector<PktRec>& pkts, const Opts& o, FILE* csv) {
    const size_t BLK = 4096;
    Detector det(o.v1);
    size_t w = (size_t)std::min<uint64_t>(o.warmup, pkts.size());
    for (size_t i = 0; i < w; i++) det.process(pkts[i].ts_ns, pkts[i].dst, pkts[i].src);
    for (int r = 0; r < o.repeats; r++) {
        det.reset();
        std::vector<double> blkns;
        blkns.reserve(pkts.size() / BLK + 2);
        double t0 = now_s();
        size_t i = 0;
        while (i < pkts.size()) {
            size_t m = std::min(BLK, pkts.size() - i);
            double b0 = now_s();
            size_t end = i + m;
            for (; i < end; i++) det.process(pkts[i].ts_ns, pkts[i].dst, pkts[i].src);
            double b1 = now_s();
            blkns.push_back((b1 - b0) * 1e9 / (double)m);
        }
        double wall = now_s() - t0;
        size_t n_alarms = det.alarms().size();
        if (!o.quiet)
            printf("[detect-only] run=%d n=%zu wall=%.4fs %.2f Mpps p50=%.1fns p99=%.1fns "
                   "alarms=%zu\n",
                   r + 1, pkts.size(), wall, (double)pkts.size() / wall / 1e6,
                   pct(blkns, 0.50), pct(blkns, 0.99), n_alarms);
        if (csv) csv_row(csv, o.workload, o.bin.empty() ? o.pcap : o.bin, "detect_only", r + 1,
                         pkts.size(), wall, BLK, pct(blkns, 0.50), pct(blkns, 0.99),
                         n_alarms, o.v1 ? 1 : 0);
    }
}


template <typename StreamFn>
static void bench_stream(StreamFn stream, const Opts& o, FILE* csv, const char* mode,
                         const std::string& input, uint64_t n_hint) {
    const uint64_t CHUNK = 1 << 16;
    for (int r = 0; r < o.repeats; r++) {
        Detector det(o.v1);
        std::vector<double> chunkns;
        uint64_t n = 0;
        PcapStat st;
        double t0 = now_s();
        double last = t0;
        uint64_t last_n = 0;
        auto cb = [&](uint64_t ts, uint32_t dst, uint32_t src) {
            det.process(ts, dst, src);
            n++;
            if ((n & (CHUNK - 1)) == 0) {
                double t = now_s();
                chunkns.push_back((t - last) * 1e9 / (double)(n - last_n));
                last = t;
                last_n = n;
            }
        };
        bool ok = stream(cb, st);
        double wall = now_s() - t0;
        if (!ok) {
            fprintf(stderr, "stream failed for %s\n", input.c_str());
            return;
        }
        if (n > last_n) chunkns.push_back((now_s() - last) * 1e9 / (double)(n - last_n));
        size_t n_alarms = det.alarms().size();
        if (!o.quiet)
            printf("[e2e] run=%d n=%llu wall=%.4fs %.2f Mpps p50=%.1fns p99=%.1fns "
                   "alarms=%zu\n",
                   r + 1, (unsigned long long)n, wall, (double)n / wall / 1e6,
                   pct(chunkns, 0.50), pct(chunkns, 0.99), n_alarms);
        if (csv) csv_row(csv, o.workload, input, mode, r + 1, n, wall, CHUNK,
                         pct(chunkns, 0.50), pct(chunkns, 0.99), n_alarms,
                         o.v1 ? 1 : 0);
        (void)n_hint;
        (void)st;
    }
}

static void gen_synth(const Opts& o) {
    uint64_t s = o.seed ? o.seed : 1;
    auto rnd = [&]() -> uint64_t {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    std::vector<PktRec> out(o.n_synth);
    const uint64_t span = 3600ull * 1000000000ull;  
    for (uint64_t i = 0; i < o.n_synth; i++) {
        uint32_t p = (uint32_t)(i % (uint64_t)o.prefixes);
        uint32_t host = 1u + (uint32_t)(rnd() % 254u);
        uint32_t dst = 0x0A000000u | (p << 8) | host;
        uint32_t src = 0x0B000000u | (uint32_t)(rnd() & 0xFFFFu);
        uint64_t ts = (uint64_t)((long double)i * (long double)span / (long double)o.n_synth);
        out[i] = PktRec{ts, dst, src};
    }
    if (!dump_bin(o.gen_synth, out)) {
        fprintf(stderr, "cannot write %s\n", o.gen_synth.c_str());
        exit(1);
    }
    printf("[gen-synth] path=%s n=%llu prefixes=%u seed=%llu span_ns=%llu\n",
           o.gen_synth.c_str(), (unsigned long long)o.n_synth, o.prefixes,
           (unsigned long long)o.seed, (unsigned long long)span);
}

int main(int argc, char** argv) {
    Opts o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--pcap") o.pcap = next();
        else if (a == "--bin") o.bin = next();
        else if (a == "--alarms") o.alarms = next();
        else if (a == "--bench-csv") o.bench_csv = next();
        else if (a == "--workload") o.workload = next();
        else if (a == "--gen-synth") o.gen_synth = next();
        else if (a == "--max-pkts") o.max_pkts = strtoull(next().c_str(), nullptr, 10);
        else if (a == "--n") o.n_synth = strtoull(next().c_str(), nullptr, 10);
        else if (a == "--prefixes") o.prefixes = (uint32_t)strtoul(next().c_str(), nullptr, 10);
        else if (a == "--seed") o.seed = strtoull(next().c_str(), nullptr, 10);
        else if (a == "--repeats") o.repeats = atoi(next().c_str());
        else if (a == "--warmup") o.warmup = strtoull(next().c_str(), nullptr, 10);
        else if (a == "--v1") o.v1 = true;
        else if (a == "--bench") o.bench = true;
        else if (a == "--bench-e2e") o.bench_e2e = true;
        else if (a == "--quiet") o.quiet = true;
        else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", a.c_str());
            usage(argv[0]);
            return 2;
        }
    }
    if (!o.gen_synth.empty()) {
        gen_synth(o);
        return 0;
    }
    if (o.pcap.empty() && o.bin.empty()) {
        usage(argv[0]);
        return 2;
    }
    if (o.repeats < 1) o.repeats = 1;
    FILE* csv = nullptr;
    if (!o.bench_csv.empty()) {
        bool newfile = false;
        FILE* t = fopen(o.bench_csv.c_str(), "r");
        if (!t)
            newfile = true;
        else
            fclose(t);
        csv = fopen(o.bench_csv.c_str(), "a");
        if (csv && newfile) csv_header(csv);
    }

    
    if (!o.alarms.empty()) {
        Detector det(o.v1);
        PcapStat st;
        if (!o.bin.empty()) {
            std::vector<PktRec> pkts;
            if (!load_bin(o.bin, o.max_pkts, pkts)) {
                fprintf(stderr, "cannot read %s\n", o.bin.c_str());
                return 1;
            }
            for (auto& p : pkts) det.process(p.ts_ns, p.dst, p.src);
        } else {
            std::vector<PktRec> pkts;
            if (!load_pcap(o.pcap, o.max_pkts, pkts, st)) {
                fprintf(stderr, "cannot read %s\n", o.pcap.c_str());
                return 1;
            }
            for (auto& p : pkts) det.process(p.ts_ns, p.dst, p.src);
        }
        write_alarms(o.alarms, det.alarms());
        print_stats(det);
    }

    
    if (o.bench) {
        std::vector<PktRec> pkts;
        PcapStat st;
        if (!o.bin.empty()) {
            if (!load_bin(o.bin, o.max_pkts, pkts)) {
                fprintf(stderr, "cannot read %s\n", o.bin.c_str());
                return 1;
            }
        } else if (!load_pcap(o.pcap, o.max_pkts, pkts, st)) {
            fprintf(stderr, "cannot read %s\n", o.pcap.c_str());
            return 1;
        }
        if (!o.quiet)
            printf("[load] n=%zu rss_mb=%.1f\n", pkts.size(), rss_mb());
        bench_detect_only(pkts, o, csv);
    }

    
    if (o.bench_e2e) {
        if (!o.bin.empty()) {
            uint64_t n = 0;
            auto fn = [&](auto cb, PcapStat&) {
                return stream_bin(o.bin, o.max_pkts, cb, n);
            };
            bench_stream(fn, o, csv, "parse_detect_bin", o.bin, n);
        } else {
            auto fn = [&](auto cb, PcapStat& st) {
                return stream_pcap(o.pcap, o.max_pkts, cb, st);
            };
            bench_stream(fn, o, csv, "parse_detect_pcap", o.pcap, 0);
        }
    }

    if (csv) fclose(csv);
    if (!o.alarms.empty() && o.bench) {
        
    }
    return 0;
}
