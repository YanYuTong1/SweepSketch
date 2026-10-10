
import csv
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sweepsketch.pcapio import is_trace, iter_pcap, trace_name          # noqa: E402

DB = os.path.normpath(os.path.join(HERE, "..", "..", "database"))
RES = os.path.normpath(os.path.join(HERE, "..", "..", "results", "csv"))


def profile_file(path):
    
    cnt = {}
    flows = {}
    first = last = None
    n = 0
    for s, d, proto, sp, dp, ts in iter_pcap(path, 10 ** 9, with_flow=True):
        n += 1
        cnt[d] = cnt.get(d, 0) + 1
        key = (s, d, proto, sp, dp)
        flows[key] = flows.get(key, 0) + 1
        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts
    span = (last - first) if first is not None else 0.0
    segs = len({(d >> 8) << 8 for d in cnt})
    pfm = statistics.median(flows.values()) if flows else 0.0
    return n, span, cnt, segs, pfm


def main():
    parts = [
        ("single24", os.path.join(DB, "attack", "normal_single24")),
        ("natural", os.path.join(DB, "attack", "natural_multi24")),
        ("byts", os.path.join(DB, "attack", "synthetic_multi24_by_timestamp")),
        ("shuffled", os.path.join(DB, "attack", "synthetic_multi24_shuffled")),
    ]
    rows = []
    for kind, d in parts:
        files = sorted(f for f in os.listdir(d) if is_trace(f))
        if kind == "single24":
            
            groups = {}
            for f in files:
                typ = trace_name(f).split("_")[1]
                n, span, cnt, segs, pfm = profile_file(os.path.join(d, f))
                g = groups.setdefault(typ, {"n": 0, "pkts": 0, "spans": [],
                                            "dst": set(), "pd": [], "pf": []})
                g["n"] += 1
                g["pkts"] += n
                g["spans"].append(span)
                g["dst"] |= set(cnt)
                g["pd"] += list(cnt.values())
                g["pf"].append(pfm)
                print("%-42s %7d pkts  %6.1fs  %5d dst" %
                      (f, n, span, len(cnt)))
            for typ in sorted(groups):
                g = groups[typ]
                rows.append((kind, typ, g["n"], g["pkts"],
                             round(statistics.median(g["spans"]), 1),
                             len(g["dst"]),
                             round(statistics.median(g["pd"]), 1),
                             round(statistics.median(g["pf"]), 1), ""))
        else:
            for f in files:
                typ = trace_name(f).split("_")[1]
                n, span, cnt, segs, pfm = profile_file(os.path.join(d, f))
                rows.append((kind, typ, 1, n, round(span, 1), len(cnt),
                             round(statistics.median(cnt.values()), 1),
                             round(pfm, 1), segs))
                print("%-10s %-42s %7d pkts  %6.1fs  %5d dst  %3d segs" %
                      (kind, f, n, span, len(cnt), segs))
    
    
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "01_dataset_profile.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["kind", "type", "n_files", "n_packets", "span_s_med",
                    "dst_distinct", "pkts_per_dst_med", "pkts_per_flow_med",
                    "n_segments"])
        w.writerows(rows)
    print("\nprofiling done → results/csv/01_dataset_profile.csv (%d rows)" % len(rows))


if __name__ == "__main__":
    main()
