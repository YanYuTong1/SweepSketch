from __future__ import annotations
import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.normpath(os.path.join(HERE, '..', '..'))
RES = os.path.join(REV, 'results', 'cpp')
LOG = os.path.join(REV, 'logs', 'cpp')
THREADS = 1
HOST_CORES = os.cpu_count() or 0
BUDGET = 0.7
TARGETS = [200000, 500000, 1000000, 2000000]
ACCEPT = {'detect_only_Mpps': 1.0, 'parse_detect_Mpps': 0.5}

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def rel(p):
    try:
        return os.path.relpath(p, REV)
    except ValueError:
        return p

def size_mb(p):
    return round(os.path.getsize(p) / 1000000.0, 2) if os.path.exists(p) else None

def read_bench():
    rows = list(csv.DictReader(open(os.path.join(RES, 'cpp_bench.csv'), encoding='utf-8')))
    for r in rows:
        for k in ('run', 'n_pkts'):
            r[k] = int(r[k])
        for k in ('wall_s', 'mpps', 'ns_p50', 'ns_p99', 'rss_mb'):
            r[k] = float(r[k])
        r['alarms'] = int(r['alarms'])
        r['v1'] = int(r['v1'])
    return rows

def summary_rows(bench):
    groups = {}
    for r in bench:
        groups.setdefault((r['workload'], r['mode']), []).append(r)
    out = []
    for (wl, mode), rs in sorted(groups.items()):
        m = [r['mpps'] for r in rs]
        out.append({'workload': wl, 'mode': mode, 'repeats': len(rs), 'n_pkts': rs[0]['n_pkts'], 'median_Mpps': round(statistics.median(m), 3), 'min_Mpps': round(min(m), 3), 'max_Mpps': round(max(m), 3), 'spread_pct': round((max(m) - min(m)) / statistics.median(m) * 100, 1), 'p50_ns_med': round(statistics.median([r['ns_p50'] for r in rs]), 1), 'p99_ns_med': round(statistics.median([r['ns_p99'] for r in rs]), 1), 'rss_mb_max': round(max((r['rss_mb'] for r in rs)), 1), 'episodes': rs[0]['alarms'], 'v1': rs[0]['v1']})
    return out

def cores_rows(summary):
    per = {}
    for r in summary:
        if r['workload'] == 'cic_full':
            per[r['mode']] = r['median_Mpps']
    out = []
    for mode, mpps in per.items():
        per_core_pps = mpps * 1000000.0
        for target in TARGETS:
            raw = max(1, -(-target // int(per_core_pps)))
            c70 = max(1, -(-target // int(per_core_pps * BUDGET)))
            out.append({'mode': mode, 'per_core_Mpps': round(mpps, 3), 'target_pps': target, 'cores_raw': raw, 'cores_70pct_budget': c70, 'fits_single_core': c70 <= 1, 'note': 'cores_* CIC median;70% = 0.70x '})
    return out

def codetect_rows():
    cases = [('cic_full_official_implv2', os.path.join(REV, 'results', 'v2', 'cpp_pyref_full.csv'), os.path.join(RES, 'cpp_alarms_cic_full.csv'), os.path.join(RES, 'codetect_official_full.json')), ('cic_1m_official_implv2', os.path.join(REV, 'results', 'v2', 'cpp_pyref_1m.csv'), os.path.join(RES, 'cpp_alarms_cic_1m_pcap.csv'), os.path.join(RES, 'codetect_official_1m.json')), ('cic_1m_official_vs_bin', os.path.join(REV, 'results', 'v2', 'cpp_pyref_1m.csv'), os.path.join(RES, 'cpp_alarms_cic_1m.csv'), os.path.join(RES, 'codetect_official_1m_bin.json')), ('synthetic_all_paths_implv2', os.path.join(REV, 'results', 'v2', 'cpp_pyref_paths.csv'), os.path.join(RES, 'cpp_alarms_paths.csv'), os.path.join(RES, 'codetect_paths.json')), ('cic_1m_v1_local_ref', os.path.join(RES, 'py_alarms_cic_1m_v1.csv'), os.path.join(RES, 'cpp_alarms_cic_1m_v1.csv'), os.path.join(RES, 'codetect_1m_v1.json'))]
    out = []
    for name, py, cpp, rep in cases:
        if not all((os.path.exists(p) for p in (py, cpp, rep))):
            out.append({'case': name, 'py_rows': None, 'cpp_rows': None, 'n_diff': None, 'match': None, 'report': rel(rep), 'note': 'missing input'})
            continue
        d = json.load(open(rep, encoding='utf-8'))
        out.append({'case': name, 'py_rows': d.get('py_rows'), 'cpp_rows': d.get('cpp_rows'), 'n_diff': d.get('n_diff'), 'match': d.get('match'), 'report': rel(rep), 'py_csv': rel(py), 'cpp_csv': rel(cpp)})
    return out
V2_FILES = ['sweepsketch/config.py', 'sweepsketch/alarm.py', 'sweepsketch/cross16.py', 'sweepsketch/sketch.py', 'sweepsketch/v2run.py', 'sweepsketch/digest.py', 'replay_v2.py']
DETECTOR_CONST_RE = {'AGE_WIN': 'constexpr uint32_t AGE_WIN = (\\d+);', 'COOLDOWN_WIN': 'constexpr uint32_t COOLDOWN_WIN = (\\d+);', 'D2_CONFIRM_WINDOWS': 'constexpr uint32_t D2_CONFIRM_WINDOWS = (\\d+);', 'D2_CONFIRM_COUNT': 'constexpr uint32_t D2_CONFIRM_COUNT = (\\d+);', 'Q_LOOKBACK_WIN': 'constexpr uint64_t Q_LOOKBACK_WIN = (\\d+);', 'Q_WINDOW_WIN': 'constexpr uint64_t Q_WINDOW_WIN = (\\d+);', 'Q_MAX_K': 'constexpr uint32_t Q_MAX_K = (\\d+);', 'Q_GROWTH_MULT': 'constexpr double Q_GROWTH_MULT = ([\\d.]+);', 'CROSS_W': 'constexpr int CROSS_W = (\\d+);', 'CROSS_K': 'constexpr int CROSS_K = (\\d+);', 'CROSS_NNEW_FLOOR': 'constexpr uint32_t CROSS_NNEW_FLOOR = (\\d+);'}

def v2_snapshot():
    import re
    impl = os.path.join(REV, 'code', '1_reference_implementation')
    files = {}
    for f in V2_FILES:
        p = os.path.join(impl, f)
        files[f] = sha256(p) if os.path.exists(p) else None
    manifest_path = os.path.join(REV, 'results', 'v2', 'v2_final_manifest.json')
    manifest = None
    manifest_sha = None
    if os.path.exists(manifest_path):
        manifest_sha = sha256(manifest_path)
        manifest = json.load(open(manifest_path, encoding='utf-8'))
    det = open(os.path.join(HERE, 'src', 'detector.hpp'), encoding='utf-8').read()
    det_const = {}
    for name, pat in DETECTOR_CONST_RE.items():
        m = re.search(pat, det)
        det_const[name] = (float(m.group(1)) if name == 'Q_GROWTH_MULT' else int(m.group(1))) if m else None
    return {'v2_final_manifest': {'path': rel(manifest_path) if os.path.exists(manifest_path) else None, 'sha256': manifest_sha, 'build': manifest.get('build') if manifest else None, 'files': manifest.get('files') if manifest else None, 'constants': manifest.get('constants') if manifest else None}, 'impl_v2_files_sha256': files, 'detector_hpp_constants': det_const, 'constants_note': 'manifest.constants Q_LOOKBACK_WIN=1676 / Q_WINDOW_WIN=20112 alarm.py docstring;runtime config.py WIN_PER_2H/WIN_PER_24H = 1677/20117,detector.hpp runtime ( ;alarm.py bfbf4feb... 21c41768... docstring , 11.6M 0 diff )'}

def two_core_rows():
    out = []
    p = os.path.join(RES, 'cpp_bench_2core_detect.csv')
    if os.path.exists(p):
        rows = list(csv.DictReader(open(p, encoding='utf-8')))
        m = [float(r['mpps']) for r in rows]
        out.append({'mode': 'detect_only', 'scenario': '2_processes_disjoint_state', 'processes': len(m), 'per_process_Mpps': ';'.join(('%.3f' % v for v in m)), 'aggregate_Mpps': round(sum(m), 3), 'target_pps': 2000000, 'cores_needed_70pct_linear': max(1, -(-2000000 // int(0.7 * sum(m) * 1000000.0 / max(1, len(m)))) * 1), 'meets_2Mpps': sum(m) >= 2.0, 'note': ' , ( CIC ); CPU '})
    p2 = os.path.join(RES, 'cpp_bench_2core.csv')
    if os.path.exists(p2):
        rows = list(csv.DictReader(open(p2, encoding='utf-8')))
        m = [float(r['mpps']) for r in rows]
        out.append({'mode': 'parse_detect_pcap', 'scenario': '2_processes_same_pcap_file', 'processes': len(m), 'per_process_Mpps': ';'.join(('%.3f' % v for v in m)), 'aggregate_Mpps': round(sum(m), 3), 'target_pps': 2000000, 'cores_needed_70pct_linear': None, 'meets_2Mpps': sum(m) >= 2.0, 'note': ' 10 GB pcap:page-cache/ , ; flow/prefix trace'})
    single = 1.482
    out.append({'mode': 'parse_detect_pcap', 'scenario': 'linear_extrapolation_2cores', 'processes': 2, 'per_process_Mpps': '%.3f' % single, 'aggregate_Mpps': round(2 * single, 3), 'target_pps': 2000000, 'cores_needed_70pct_linear': max(1, -(-2000000 // int(0.7 * single * 1000000.0))), 'meets_2Mpps': 2 * single >= 2.0, 'note': ' CIC e2e ;2 Mpps 2 (70% )'})
    return out

def write_csv(path, rows):
    if not rows:
        open(path, 'w').close()
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

def write_meta(csv_path, **payload):
    meta = {'created': datetime.now().astimezone().isoformat(), 'experiment': 'V7-cpp-detector', 'argv': sys.argv, 'host': {'platform': platform.platform(), 'machine': platform.machine(), 'cores': HOST_CORES, 'python': sys.version.split()[0]}, 'threads': THREADS, 'budget_70pct': BUDGET, 'acceptance': ACCEPT, 'source': {'main.cpp': sha256(os.path.join(HERE, 'src', 'main.cpp')), 'detector.hpp': sha256(os.path.join(HERE, 'src', 'detector.hpp')), 'hash.hpp': sha256(os.path.join(HERE, 'src', 'hash.hpp')), 'pcap.hpp': sha256(os.path.join(HERE, 'src', 'pcap.hpp'))}}
    meta.update(payload)
    with open(os.path.splitext(csv_path)[0] + '.meta.json', 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2, sort_keys=True)

def main():
    os.makedirs(RES, exist_ok=True)
    t0 = time.time()
    bench = read_bench()
    summary = summary_rows(bench)
    cores = cores_rows(summary)
    cdet = codetect_rows()
    snap = v2_snapshot()
    two = two_core_rows()
    p1 = os.path.join(RES, 'cpp_summary.csv')
    write_csv(p1, summary)
    write_meta(p1, inputs={'bench': 'results/cpp/cpp_bench.csv'}, commands=['cd code/cpp_detector && make', './build/detector --pcap <CIC> --bench --repeats 3 --bench-csv results/cpp/cpp_bench.csv --workload cic_full', './build/detector --pcap <CIC> --bench-e2e --repeats 3 --bench-csv results/cpp/cpp_bench.csv --workload cic_full', './build/detector --bin results/cpp/synth_5k_10m.bin --bench --bench-e2e --repeats 3 --bench-csv results/cpp/cpp_bench.csv --workload synth5k_10m'], v2_snapshot=snap, note='detect-only= ( IO);parse_detect_pcap= + ;p50/p99 ns/ (detect 4096,e2e 65536)')
    print('[make_results] wrote', p1, len(summary))
    p2 = os.path.join(RES, 'cpp_cores.csv')
    write_csv(p2, cores)
    write_meta(p2, inputs={'summary': 'results/cpp/cpp_summary.csv'}, formula='cores = ceil(target_pps / (budget * per_core_pps)); per_core CIC median Mpps')
    print('[make_results] wrote', p2, len(cores))
    p3 = os.path.join(RES, 'cpp_codetect.csv')
    write_csv(p3, cdet)
    write_meta(p3, inputs={'official_ground_truth': 'results/v2/cpp_pyref_1m.csv', 'synthetic_ground_truth': 'results/v2/cpp_pyref_paths.csv'}, v2_snapshot=snap, note='official = impl_v2/replay_v2.py(detector-v2 ); (ts_ns, epoch_full, level, key_int, reason, n_new, C, pkt)')
    print('[make_results] wrote', p3, len(cdet))
    p4 = os.path.join(RES, 'cpp_2core.csv')
    write_csv(p4, two)
    write_meta(p4, v2_snapshot=snap, inputs={'detect_2proc': 'results/cpp/cpp_bench_2core_detect.csv', 'e2e_2proc_same_file': 'results/cpp/cpp_bench_2core.csv'}, note='2 :detect-only ;e2e trace IO ;2M pps 1.482 Mpps 2 ')
    print('[make_results] wrote', p4, len(two))
    extra = [('cpp_alarms_cic_full.csv', {'input': 'CIC-IDS-2017-Benign.pcap( 11,624,871 IPv4)', 'command': './build/detector --pcap <CIC> --alarms results/cpp/cpp_alarms_cic_full.csv'}), ('cpp_alarms_cic_1m.csv', {'input': 'results/cpp/trace_cic_1m.bin(CIC 1M IPv4,16B/ )', 'command': './build/detector --bin results/cpp/trace_cic_1m.bin --alarms results/cpp/cpp_alarms_cic_1m.csv'}), ('cpp_alarms_cic_1m_pcap.csv', {'input': 'CIC 1M IPv4(pcap )', 'command': './build/detector --pcap <CIC> --max-pkts 1000000 --alarms ...'}), ('cpp_alarms_cic_1m_v1.csv', {'input': 'results/cpp/trace_cic_1m.bin', 'command': './build/detector --bin ... --v1 --alarms ...'}), ('cpp_alarms_paths.csv', {'input': 'results/cpp/synth_paths_test.pcap(D1/D2/N12/DIST )', 'command': './build/detector --pcap ... --alarms ...'}), ('trace_cic_1m.bin', {'input': 'CIC-IDS-2017-Benign.pcap 1,000,000 IPv4', 'command': 'python3 pyref_v2.py export --pcap <CIC> --n 1000000 --bin ...'}), ('synth_5k_10m.bin', {'input': ' 5k /24 x 10M x 1h', 'command': './build/detector --gen-synth results/cpp/synth_5k_10m.bin --n 10000000 --prefixes 5000 --seed 20261022'}), ('synth_paths_test.pcap', {'input': ' pcap(7,712 ;D1/D2 2-of-3/N12/DIST)', 'command': 'python3 gen_test_pcap.py --pcap ... --bin ...'})]
    for name, payload in extra:
        p = os.path.join(RES, name)
        if not os.path.exists(p):
            continue
        mp = os.path.splitext(p)[0] + '.meta.json'
        d = {'created': datetime.now().astimezone().isoformat(), 'experiment': 'V7-cpp-detector', 'file': rel(p), 'size_bytes': os.path.getsize(p), 'sha256': sha256(p)}
        d.update(payload)
        with open(mp, 'w', encoding='utf-8') as f:
            json.dump(d, f, ensure_ascii=False, indent=2, sort_keys=True)
    for p in sorted((os.path.join(RES, f) for f in os.listdir(RES) if f.endswith('.csv'))):
        mp = os.path.splitext(p)[0] + '.meta.json'
        if os.path.exists(mp):
            continue
        with open(mp, 'w', encoding='utf-8') as f:
            json.dump({'created': datetime.now().astimezone().isoformat(), 'experiment': 'V7-cpp-detector', 'file': rel(p), 'size_bytes': os.path.getsize(p), 'sha256': sha256(p), 'note': ' / ; make_results.py meta'}, f, ensure_ascii=False, indent=2, sort_keys=True)
    all_meta = os.path.join(RES, 'cpp_all.meta.json')
    with open(all_meta, 'w', encoding='utf-8') as f:
        json.dump({'created': datetime.now().astimezone().isoformat(), 'experiment': 'V7-cpp-detector', 'acceptance': ACCEPT, 'meets_acceptance': {'detect_only': all((r['median_Mpps'] >= ACCEPT['detect_only_Mpps'] for r in summary if r['mode'] == 'detect_only')), 'parse_detect_cic': all((r['median_Mpps'] >= ACCEPT['parse_detect_Mpps'] for r in summary if r['workload'] == 'cic_full' and r['mode'] == 'parse_detect_pcap'))}, 'summary': summary, 'cores': cores, 'codetect': cdet, 'two_core': two, 'v2_snapshot': snap, 'e7_python_comparison': {'python_control_plane_kpps': 141.7, 'python_end2end_kpps': 108.4, 'cpp_detect_only_Mpps': next((r['median_Mpps'] for r in summary if r['workload'] == 'cic_full' and r['mode'] == 'detect_only'), None), 'cpp_end2end_Mpps': next((r['median_Mpps'] for r in summary if r['workload'] == 'cic_full' and r['mode'] == 'parse_detect_pcap'), None)}, 'wall_s': round(time.time() - t0, 1)}, f, ensure_ascii=False, indent=2, sort_keys=True)
    print('[make_results] wrote', all_meta)
    return 0
if __name__ == '__main__':
    sys.exit(main())
