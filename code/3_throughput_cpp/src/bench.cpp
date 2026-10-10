














#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "bob_hash.hpp"
#include "methods.hpp"
#include "pcap.hpp"
#include "segsketch.hpp"
#include "spreadsketch.hpp"
#include "couper.hpp"
#include "rhhh.hpp"
#include "elastic.hpp"
#include "heavykeeper.hpp"
#include "trw.hpp"
#include "mrb.hpp"
#include "entropy.hpp"
#include "lakhina.hpp"
#include "sweepsketch.hpp"

using namespace bench;

struct Opts {
    std::string trace, pcap, verify, out;
    std::vector<std::string> methods = {"all"};
    std::vector<int> budgets = {512};
    uint64_t max_pkts = 5000000;
    int repeats = 3;
    size_t warmup = 200000;
    bool do_bench = false;
    bool sink = true;
};

static std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = s.find(sep, i);
        if (j == std::string::npos) j = s.size();
        if (j > i) out.push_back(s.substr(i, j - i));
        i = j + 1;
    }
    return out;
}


static bool load_trace_csv(const std::string& path, uint64_t max_pkts, std::vector<Pkt>& out) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;
    out.clear();
    uint32_t s, d;
    uint64_t ts;
    while (out.size() < max_pkts && fscanf(f, "%u,%u,%" SCNu64, &s, &d, &ts) == 3) {
        out.push_back({s, d, ts});
    }
    fclose(f);
    return true;
}

static int active_pfxs(const std::vector<Pkt>& pkts) {
    std::set<uint32_t> pfxs;
    for (auto& p : pkts) pfxs.insert((p.d >> 8) << 8);
    return (int)pfxs.size();
}


static std::unique_ptr<Method> create_generic(const std::string& m, int budget_kb, int n_pfx) {
    if (m == "segsketch") return create_segsketch(budget_kb, n_pfx);
    if (m == "spreadsketch") return create_spreadsketch(budget_kb, n_pfx);
    if (m == "couper") return create_couper(budget_kb, n_pfx);
    if (m == "rhhh") return create_rhhh(budget_kb, n_pfx);
    if (m == "elastic") return create_elastic(budget_kb, n_pfx);
    if (m == "heavykeeper") return create_heavykeeper(budget_kb, n_pfx);
    if (m == "trw") return create_trw(budget_kb, n_pfx);
    if (m == "mrb") return create_mrb(budget_kb, n_pfx);
    if (m == "entropy") return create_entropy(budget_kb, n_pfx);
    if (m == "lakhina") return create_lakhina(budget_kb, n_pfx);
    return nullptr;
}

static const char* kScoreMethods[] = {"segsketch", "spreadsketch", "couper", "rhhh",
                                      "elastic",   "heavykeeper", "trw",    "mrb",
                                      "entropy",   "lakhina"};


template <class M>
static void bench_one(const std::string& method, const std::vector<Pkt>& pkts, int budget_kb,
                      int n_pfx, const Opts& o, FILE* csv) {
    size_t n = pkts.size();
    size_t w = std::min(o.warmup, n);
    {
        M warm(budget_kb, n_pfx);
        for (size_t i = 0; i < w; i++) warm.insert(pkts[i].s, pkts[i].d, i, pkts[i].ts_ns);
    }
    std::vector<double> times;
    for (int r = 0; r < o.repeats; r++) {
        M m(budget_kb, n_pfx);
        auto t0 = std::chrono::steady_clock::now();
        for (size_t i = 0; i < n; i++) m.insert(pkts[i].s, pkts[i].d, i, pkts[i].ts_ns);
        auto t1 = std::chrono::steady_clock::now();
        times.push_back(std::chrono::duration<double>(t1 - t0).count());
        if (r == o.repeats - 1 && o.sink) {  
            std::vector<std::pair<uint64_t, double>> sc;
            m.scores(sc);
            volatile double sinkv = sc.empty() ? 0.0 : sc[0].second;
            (void)sinkv;
        }
    }
    std::sort(times.begin(), times.end());
    double med = times[times.size() / 2];
    double mpps = (double)n / med / 1e6;
    printf("  %-14s budget=%5dKB  n=%zu  median=%.3fs  %.2f Mpps\n", method.c_str(), budget_kb, n,
           med, mpps);
    if (csv) {
        fprintf(csv, "%s,%d,%zu,%.6f,%.3f\n", method.c_str(), budget_kb, n, med, mpps);
    }
}

static void run_bench(const std::string& method, const std::vector<Pkt>& pkts, const Opts& o,
                      FILE* csv) {
    int n_pfx = active_pfxs(pkts);
    for (int b : o.budgets) {
        if (method == "segsketch") bench_one<SegSketchCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "spreadsketch") bench_one<SpreadSketchCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "couper") bench_one<CouperCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "rhhh") bench_one<RHHHCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "elastic") bench_one<ElasticCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "heavykeeper") bench_one<HeavyKeeperCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "trw") bench_one<TRWCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "mrb") bench_one<MRBCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "entropy") bench_one<EntropyCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "lakhina") bench_one<LakhinaCpp>(method, pkts, b, n_pfx, o, csv);
        else if (method == "sweep") bench_one<SweepCpp>(method, pkts, b, n_pfx, o, csv);
        else { printf("unknown method: %s\n", method.c_str()); return; }
    }
}


static bool read_expected_scores(const std::string& prefix,
                                 std::map<std::string, std::map<uint64_t, double>>& out) {
    FILE* f = fopen((prefix + "_scores.txt").c_str(), "r");
    if (!f) {
        printf("  cannot open %s_scores.txt\n", prefix.c_str());
        return false;
    }
    char method[64];
    uint64_t key;
    double score;
    while (fscanf(f, "%63s %" SCNu64 " %lf", method, &key, &score) == 3) {
        out[method][key] = score;
    }
    fclose(f);
    return true;
}

static bool verify_scores(const std::string& method, const std::vector<Pkt>& pkts, int budget_kb,
                          int n_pfx, const std::map<uint64_t, double>& exp) {
    auto mk = create_generic(method, budget_kb, n_pfx);
    if (!mk) {
        printf("  %-14s SKIP (create_%s not implemented)\n", method.c_str(), method.c_str());
        return true;
    }
    for (size_t i = 0; i < pkts.size(); i++) mk->insert(pkts[i].s, pkts[i].d, i, pkts[i].ts_ns);
    std::vector<std::pair<uint64_t, double>> got;
    mk->scores(got);
    std::map<uint64_t, double> g(got.begin(), got.end());
    if (g.size() != exp.size()) {
        printf("  %-14s FAIL: entity count %zu vs expected %zu\n", method.c_str(), g.size(), exp.size());
        return false;
    }
    int bad = 0;
    for (auto& kv : exp) {
        auto it = g.find(kv.first);
        if (it == g.end()) {
            if (bad++ < 3) printf("    missing key %" PRIu64 "\n", kv.first);
            continue;
        }
        double tol = 1e-9 + 1e-9 * fabs(kv.second);
        if (fabs(it->second - kv.second) > tol) {
            if (bad++ < 3)
                printf("    key %" PRIu64 " got %.9g exp %.9g\n", kv.first, it->second, kv.second);
        }
    }
    if (bad) {
        printf("  %-14s FAIL: %d mismatches\n", method.c_str(), bad);
        return false;
    }
    printf("  %-14s OK (%zu entity scores match)\n", method.c_str(), exp.size());
    return true;
}

struct SweepExpB {
    bool present;
    uint32_t key, epoch, win, n_new, n_ewma, C, pkt, pkt_ewma;
    uint8_t d2_held, hll[32];
    uint64_t a1, a2;
};
static bool read_sweep_exp(const std::string& prefix, std::vector<SweepExpB>& l1,
                            std::vector<SweepExpB>& l2) {
    FILE* f = fopen((prefix + "_sweep.txt").c_str(), "r");
    if (!f) return false;
    int lvl, idx, present;
    SweepExpB b;
    while (fscanf(f, "%d %d %d %u %u %u %u %u %u %u %u %hhu %" SCNu64 " %" SCNu64, &lvl, &idx,
                  &present, &b.key, &b.epoch, &b.win, &b.n_new, &b.n_ewma, &b.C, &b.pkt,
                  &b.pkt_ewma, &b.d2_held, &b.a1, &b.a2) == 14) {
        b.present = present != 0;
        for (int i = 0; i < 32; i++) {
            int v;
            if (fscanf(f, " %d", &v) != 1) return false;
            b.hll[i] = (uint8_t)v;
        }
        if (lvl == 1) l1.push_back(b);
        else l2.push_back(b);
    }
    fclose(f);
    return true;
}

static bool verify_sweep(const std::vector<Pkt>& pkts, const std::vector<SweepExpB>& e1,
                          const std::vector<SweepExpB>& e2) {
    auto m = create_sweep(0, 0);
    for (size_t i = 0; i < pkts.size(); i++) m->insert(pkts[i].s, pkts[i].d, i, pkts[i].ts_ns);
    SweepDump d = m->dump();
    int bad = 0;
    auto cmp = [&](const std::vector<SweepDump::B>& got, const std::vector<SweepExpB>& exp,
                   int lvl) {
        if (got.size() != exp.size()) {
            printf("    sweep lvl%d bucket count %zu vs expected %zu\n", lvl, got.size(), exp.size());
            bad++;
            return;
        }
        for (size_t i = 0; i < got.size(); i++) {
            const auto& g = got[i];
            const auto& e = exp[i];
            if (g.present != e.present || g.key != e.key || g.epoch != e.epoch || g.win != e.win ||
                g.n_new != e.n_new || g.n_ewma != e.n_ewma || g.C != e.C || g.pkt != e.pkt ||
                g.pkt_ewma != e.pkt_ewma || g.d2_held != e.d2_held || g.a1 != e.a1 ||
                g.a2 != e.a2 || memcmp(g.hll, e.hll, 32) != 0) {
                if (bad++ < 5)
                    printf("    sweep lvl%d idx%zu mismatch (got key=%u e=%u C=%u pkt=%u)\n", lvl,
                           i, g.key, g.epoch, g.C, g.pkt);
            }
        }
    };
    cmp(d.l1, e1, 1);
    cmp(d.l2, e2, 2);
    if (bad) {
        printf("  sweep          FAIL: %d mismatches\n", bad);
        return false;
    }
    printf("  sweep          OK (%zu+%zu buckets bit-identical)\n", e1.size(), e2.size());
    return true;
}

int main(int argc, char** argv) {
    Opts o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--trace") o.trace = next();
        else if (a == "--pcap") o.pcap = next();
        else if (a == "--verify") o.verify = next();
        else if (a == "--out") o.out = next();
        else if (a == "--method") o.methods = {next()};
        else if (a == "--budget") o.budgets = {atoi(next())};
        else if (a == "--budgets") {
            o.budgets.clear();
            for (auto& t : split(next(), ',')) o.budgets.push_back(atoi(t.c_str()));
        }
        else if (a == "--max-pkts") o.max_pkts = strtoull(next(), nullptr, 10);
        else if (a == "--repeats") o.repeats = atoi(next());
        else if (a == "--warmup") o.warmup = (size_t)strtoull(next(), nullptr, 10);
        else if (a == "--bench") o.do_bench = true;
        else if (a == "--no-sink") o.sink = false;
        else if (a == "--help") {
            printf("usage: %s [--pcap f | --trace f] [--bench|--verify prefix]\n"
                   "       [--method m | --method all] [--budget kb | --budgets a,b]\n"
                   "       [--max-pkts N] [--repeats K] [--warmup N] [--out csv]\n",
                   argv[0]);
            return 0;
        }
        else {
            printf("unknown arg: %s\n", a.c_str());
            return 2;
        }
    }
    if (o.trace.empty() && o.pcap.empty()) {
        printf("need --pcap or --trace\n");
        return 2;
    }
    if (o.verify.empty() && !o.do_bench) {
        printf("need --verify <prefix> or --bench\n");
        return 2;
    }

    
    std::vector<Pkt> pkts;
    double parse_ms = 0;
    if (!o.trace.empty()) {
        if (!load_trace_csv(o.trace, o.max_pkts, pkts)) {
            printf("cannot read trace %s\n", o.trace.c_str());
            return 1;
        }
    } else {
        PcapStat st;
        auto t0 = std::chrono::steady_clock::now();
        if (!load_pcap(o.pcap, o.max_pkts, pkts, st)) {
            printf("cannot read pcap %s\n", o.pcap.c_str());
            return 1;
        }
        auto t1 = std::chrono::steady_clock::now();
        parse_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        printf("pcap: %" PRIu64 " records, %" PRIu64 " IPv4, %zu taken, parsed in %.0f ms\n",
               st.total_pkts, st.ipv4, pkts.size(), parse_ms);
    }
    if (pkts.empty()) {
        printf("no packets\n");
        return 1;
    }
    printf("trace: %zu packets, active /24 = %d\n", pkts.size(), active_pfxs(pkts));

    
    if (!o.verify.empty()) {
        int budget = o.budgets[0];
        bool ok = true;
        if (o.methods[0] == "all") {
            std::map<std::string, std::map<uint64_t, double>> exp;
            if (!read_expected_scores(o.verify, exp)) return 1;
            for (auto& m : kScoreMethods) {
                auto it = exp.find(m);
                if (it == exp.end()) continue;
                ok &= verify_scores(m, pkts, budget, active_pfxs(pkts), it->second);
            }
            std::vector<SweepExpB> l1, l2;
            if (read_sweep_exp(o.verify, l1, l2)) ok &= verify_sweep(pkts, l1, l2);
            else printf("  sweep           SKIP (no expected file)\n");
        } else {
            std::string m = o.methods[0];
            if (m == "sweep") {
                std::vector<SweepExpB> l1, l2;
                if (!read_sweep_exp(o.verify, l1, l2)) return 1;
                ok = verify_sweep(pkts, l1, l2);
            } else {
            } else {
                std::map<std::string, std::map<uint64_t, double>> exp;
                if (!read_expected_scores(o.verify, exp)) return 1;
                auto it = exp.find(m);
                if (it == exp.end()) {
                    printf("no expected data for %s\n", m.c_str());
                    return 1;
                }
                ok = verify_scores(m, pkts, budget, active_pfxs(pkts), it->second);
            }
        }
        printf(ok ? "VERIFY PASS\n" : "VERIFY FAIL\n");
        return ok ? 0 : 1;
    }

    
    FILE* csv = nullptr;
    if (!o.out.empty()) {
        csv = fopen(o.out.c_str(), "w");
        if (csv) fprintf(csv, "method,budget_kb,n_pkts,median_s,mpps\n");
    }
    std::vector<std::string> methods;
    if (o.methods[0] == "all") {
        for (auto& m : kScoreMethods) methods.push_back(m);
        methods.push_back("lmc");
        methods.push_back("sweep");
    } else {
        methods = o.methods;
    }
    for (auto& m : methods) run_bench(m, pkts, o, csv);
    if (csv) fclose(csv);
    return 0;
}
