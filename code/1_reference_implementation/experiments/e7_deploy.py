from __future__ import annotations
import argparse
import csv
import hashlib
import math
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rev_common as rc
rc.add_impl_path()
from sweepsketch import config as sscfg
from sweepsketch.digest import Collector
from sweepsketch.pcapio import iter_pcap
from sweepsketch.sketch import SweepSketch
EXP = 'e7'
RES = rc.ensure(EXP)
LOG = os.path.join(rc.LOGS, EXP)
REPEATS = 3
BUDGET_KB = 512
PKT_BYTES_DIGEST = 16
SYNTH_N = 1000000
SYNTH_ACTIVE = 5000
SYNTH_SPAN_S = 3600.0
SYNTH_SEED = 20261021
CIC = os.path.join(rc.DB, 'benign', 'CIC-IDS-2017-Benign.pcap')
CPP_DIR = os.path.join(rc.REV, 'code', '3_throughput_cpp')

def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def rel(path: str) -> str:
    return rc.rel(path)

def median_range(values):
    return (statistics.median(values), min(values), max(values))

def synth_packets(n=SYNTH_N, active=SYNTH_ACTIVE, span_s=SYNTH_SPAN_S, seed=SYNTH_SEED):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        p = rng.randrange(active)
        dst = 167772160 | p << 8 | rng.randrange(1, 255)
        src = 3232235520 | rng.randrange(1 << 16)
        ts = i * span_s / n
        out.append((src, dst, ts))
    return out

def bench_python_synth(pkts, repeats=REPEATS):
    rows = []
    for r in range(repeats):
        sk = SweepSketch(sscfg.THETA0)
        col = Collector()
        t0 = time.perf_counter()
        for s, d, ts in pkts:
            sk.process(s, d, ts, col)
        dt = time.perf_counter() - t0
        rows.append({'impl': 'python-ref', 'workload': 'synthetic-1M-5kpfx', 'repeat': r + 1, 'n_pkts': len(pkts), 'wall_s': round(dt, 6), 'kpps': round(len(pkts) / dt / 1000.0, 1), 'alerts': len(col.alerts)})
        print('  python synth rep%d: %.3fs -> %.1f kpps' % (r + 1, dt, len(pkts) / dt / 1000.0), flush=True)
    return rows

def bench_python_real(path, repeats=REPEATS):
    n = rc.packet_count(path)
    parse_rows = []
    for r in range(2):
        t0 = time.perf_counter()
        cnt = 0
        for _ in iter_pcap(path, 1 << 60, with_flow=False):
            cnt += 1
        dt = time.perf_counter() - t0
        parse_rows.append((cnt, dt))
        print('  python parse-only rep%d: %d pkts %.2fs -> %.0f kpps' % (r + 1, cnt, dt, cnt / dt / 1000.0), flush=True)
    parse_med = statistics.median([d for _, d in parse_rows])
    rows = []
    for r in range(repeats):
        sk = SweepSketch(sscfg.THETA0)
        col = Collector()
        cnt = 0
        t0 = time.perf_counter()
        for s, d, ts in iter_pcap(path, 1 << 60, with_flow=False):
            sk.process(s, d, ts, col)
            cnt += 1
        dt = time.perf_counter() - t0
        sm_only = max(dt - parse_med, 1e-09)
        rows.append({'impl': 'python-ref', 'workload': 'CIC-IDS-2017-full', 'repeat': r + 1, 'n_pkts': cnt, 'wall_s': round(dt, 3), 'kpps': round(cnt / dt / 1000.0, 1), 'kpps_state_machine_only_est': round(cnt / sm_only / 1000.0, 1), 'alerts': len(col.alerts)})
        print('  python CIC rep%d: %d pkts %.2fs -> %.1f kpps (estimated %.1f kpps excluding parsing)' % (r + 1, cnt, dt, cnt / dt / 1000.0, cnt / sm_only / 1000.0), flush=True)
    return (n, parse_rows, rows)

def bench_cpp(path, n_pkts, repeats=REPEATS):
    out = {'available': False, 'compiled': False, 'reason': '', 'patched_copy': None}
    if not os.path.isdir(CPP_DIR):
        out['reason'] = 'the C++ throughput source directory is missing'
        return (out, [])
    compiler = shutil.which('clang++') or shutil.which('g++')
    if not compiler:
        out['reason'] = 'no clang++ or g++ available on this machine'
        return (out, [])
    build_dir = os.path.join(LOG, 'cpp_build')
    src_dir = os.path.join(build_dir, 'src')
    if os.path.isdir(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(build_dir)
    shutil.copytree(os.path.join(CPP_DIR, 'src'), src_dir)
    orig_bench = os.path.join(CPP_DIR, 'src', 'bench.cpp')
    bench_cpp = os.path.join(src_dir, 'bench.cpp')
    src_txt = open(bench_cpp, encoding='utf-8').read()
    bad = '            } else {\n            } else {\n'
    patch_applied = bad in src_txt
    if patch_applied:
        src_txt = src_txt.replace(bad, '            } else {\n', 1)
        open(bench_cpp, 'w', encoding='utf-8').write(src_txt)
    out.update({'patched_copy': rel(build_dir), 'source_sha256': sha256(orig_bench), 'patched_sha256': sha256(bench_cpp), 'patch_applied': patch_applied, 'patch_note': 'the archived bench.cpp contains a duplicated `} else {` (lines 366-367); a copy removes the redundant branch wrapper without changing semantics' if patch_applied else 'no fix needed'})
    exe = os.path.join(build_dir, 'bench')
    build_log = os.path.join(LOG, 'cpp_build.log')
    cmd = [compiler, '-O3', '-std=c++17', '-Wall']
    if platform.system() == 'Darwin' and platform.machine() in ('arm64', 'aarch64'):
        cmd.append('-march=native')
    cmd += ['-o', exe, bench_cpp]
    with open(build_log, 'w') as f:
        f.write('$ ' + ' '.join(cmd) + '\n')
        f.flush()
        pr = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    if pr.returncode != 0 or not os.path.exists(exe):
        out['reason'] = 'compilation failed (see logs/e7/cpp_build.log)'
        return (out, [])
    out['compiled'] = True
    out['compiler'] = compiler
    raw = os.path.join(RES, 'e7_cpp_bench_raw.csv')
    log = os.path.join(LOG, 'cpp_bench.log')
    cmd = [exe, '--pcap', path, '--bench', '--budget', str(BUDGET_KB), '--method', 'sweep', '--repeats', str(repeats), '--warmup', '200000', '--max-pkts', str(n_pkts + 1000), '--out', raw]
    with open(log, 'w') as f:
        f.write('$ ' + ' '.join(cmd) + '\n')
        f.flush()
        q = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    inprocess = None
    if os.path.exists(raw):
        with open(raw) as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 5 and parts[0] == 'sweep':
                    inprocess = float(parts[4])
    rows = []
    rep_path = os.path.join(RES, 'e7_cpp_repeats.csv')
    with open(rep_path, 'w', newline='') as rf:
        rw = csv.writer(rf)
        rw.writerow(['run', 'n_pkts', 'median_s', 'mpps'])
        ok = True
        for i in range(1, repeats + 1):
            rcsv = os.path.join(LOG, 'cpp_rep%d.csv' % i)
            c = [exe, '--pcap', path, '--bench', '--budget', str(BUDGET_KB), '--method', 'sweep', '--repeats', '1', '--warmup', '200000', '--max-pkts', str(n_pkts + 1000), '--out', rcsv]
            with open(log, 'a') as f:
                f.write('$ ' + ' '.join(c) + '\n')
                f.flush()
                qq = subprocess.run(c, stdout=f, stderr=subprocess.STDOUT, text=True)
            ok = ok and qq.returncode == 0 and os.path.exists(rcsv)
            if os.path.exists(rcsv):
                with open(rcsv) as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) == 5 and parts[0] == 'sweep':
                            mpps = float(parts[4])
                            rw.writerow([i, int(parts[2]), round(float(parts[3]), 6), mpps])
                            rows.append({'impl': 'cpp-insert', 'workload': 'CIC-IDS-2017-full', 'repeat': i, 'n_pkts': int(parts[2]), 'wall_s': round(float(parts[3]), 6), 'kpps': round(mpps * 1000.0, 1), 'raw_mpps': mpps})
    out['available'] = ok and bool(rows)
    out['harness_inprocess_median_mpps'] = inprocess
    out['repeats_csv'] = rel(rep_path)
    if not out['available']:
        out['reason'] = 'the harness run failed (see logs/e7/cpp_bench.log)'
    return (out, rows)

def envelope(py_kpps, cpp_mpps, py_kpps_e2e=None):
    rows = []
    for prefixes in (5000, 10000, 20000):
        for pps in (40, 100):
            agg = prefixes * pps
            mbps = agg * PKT_BYTES_DIGEST / 1000000.0
            py_cores = math.ceil(agg / (py_kpps * 1000.0))
            cpp_cores = math.ceil(agg / (cpp_mpps * 1000000.0)) if cpp_mpps else None
            rows.append({'active_prefixes': prefixes, 'per_prefix_pps': pps, 'aggregate_pps': agg, 'digest_bytes_per_pkt': PKT_BYTES_DIGEST, 'digest_MBps': round(mbps, 3), 'digest_Gbps': round(mbps * 8 / 1000, 4), 'py_single_core_kpps': py_kpps, 'py_cores_needed': py_cores, 'py_single_core_kpps_e2e': py_kpps_e2e, 'py_cores_needed_e2e': math.ceil(agg / (py_kpps_e2e * 1000.0)) if py_kpps_e2e else None, 'py_fits_15core_host_70pct': py_cores <= 10, 'cpp_mpps_per_core': cpp_mpps, 'cpp_cores_needed': cpp_cores})
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['all', 'throughput', 'envelope'])
    ap.add_argument('--repeats', type=int, default=REPEATS)
    args = ap.parse_args()
    t_start = time.time()
    py_kpps = cpp_mpps = py_e2e = None
    control_rows: list = []
    env_rows: list = []
    if args.cmd in ('all', 'throughput'):
        print('[E7] Q1a Python reference implementation: synthetic 1M packets (5000 active /24s, 1 h timeline)', flush=True)
        pkts = synth_packets()
        synth_rows = bench_python_synth(pkts, args.repeats)
        del pkts
        print('[E7] Q1a Python reference implementation: full real stream %s (%d packets)' % (os.path.basename(CIC), rc.packet_count(CIC)), flush=True)
        n_cic, parse_rows, real_rows = bench_python_real(CIC, args.repeats)
        parse_med = statistics.median([d for _, d in parse_rows])
        parse_kpps = statistics.median([c / d / 1000.0 for c, d in parse_rows])
        py_real_med, py_real_min, py_real_max = median_range([r['kpps'] for r in real_rows])
        py_synth_med, py_synth_min, py_synth_max = median_range([r['kpps'] for r in synth_rows])
        n_ipv4 = real_rows[0]['n_pkts'] if real_rows else n_cic
        py_e2e_med = py_real_med
        py_e2e = py_e2e_med
        py_kpps = py_synth_med
        print('[E7] Q1b C++ insertion path (throughput harness)', flush=True)
        cpp_info, cpp_rows = bench_cpp(CIC, n_cic, args.repeats)
        if cpp_rows:
            cpp_mpps = statistics.median([r['raw_mpps'] for r in cpp_rows])
            cpp_min = min((r['raw_mpps'] for r in cpp_rows))
            cpp_max = max((r['raw_mpps'] for r in cpp_rows))
        else:
            cpp_min = cpp_max = None
        print('[E7] C++ status: compiled=%s available=%s %s' % (cpp_info.get('compiled'), cpp_info.get('available'), cpp_info.get('reason', '')), flush=True)

        def summ(impl, workload, rows, n, units='kpps'):
            if not rows:
                return None
            vals = [r[units] for r in rows]
            med, lo, hi = median_range(vals)
            row = {'impl': impl, 'workload': workload, 'repeats': len(rows), 'n_pkts': n, 'median_kpps': round(med, 2), 'min_kpps': round(lo, 2), 'max_kpps': round(hi, 2), 'spread_pct_of_median': round((hi - lo) / med * 100, 2) if med else 0.0, 'per_repeat_kpps': ';'.join(('%.1f' % v for v in vals)), 'note': ''}
            return row
        control_rows = [r for r in (summ('python-ref', 'synthetic-1M-5kpfx', synth_rows, SYNTH_N), summ('python-ref', 'CIC-IDS-2017-full', real_rows, n_ipv4), summ('cpp-insert', 'CIC-IDS-2017-full', cpp_rows, n_ipv4, units='raw_mpps')) if r]
        control_rows.append({'impl': 'python-parse-only', 'workload': 'CIC-IDS-2017-full', 'repeats': len(parse_rows), 'n_pkts': n_ipv4, 'median_kpps': round(parse_kpps, 2), 'min_kpps': round(min((c / d / 1000.0 for c, d in parse_rows)), 2), 'max_kpps': round(max((c / d / 1000.0 for c, d in parse_rows)), 2), 'spread_pct_of_median': 0.0, 'per_repeat_kpps': ';'.join(('%.1f' % (c / d / 1000.0) for c, d in parse_rows)), 'note': 'pcap parsing only, detector state machine skipped (upper bound)'})
        control_rows[0]['note'] = 'state machine only (in-memory replay, no pcap parsing) = control-plane deployment basis'
        if real_rows:
            control_rows[1]['note'] = 'end to end (pcap parsing + two-level state machine + alarm dedup); estimated %.1f kpps for the state machine alone; the file holds %d EPB records and %d IPv4 packets reach the state machine' % (statistics.median([r['kpps_state_machine_only_est'] for r in real_rows]), n_cic, n_ipv4)
        if cpp_rows:
            control_rows[2]['repeats'] = args.repeats
            control_rows[2]['note'] = '%d independent process repeats (each harness run uses --repeats 1), median; in-process median over %d repeats %.2f Mpps (warm-cache upper bound); structure N1=7936/N2=3968 (earlier layout), 7/4 buckets below the Python 7943/3972; single-core insertion path in Mpps' % (args.repeats, args.repeats, cpp_info.get('harness_inprocess_median_mpps') or 0.0)
        csv_cp = os.path.join(RES, 'e7_controlplane.csv')
        rc.write_csv(csv_cp, control_rows)
        rc.write_meta(csv_cp, experiment='E7-controlplane', repeats=args.repeats, workers=os.environ.get('SWEEPSKETCH_WORKERS', '4'), host_cores=os.cpu_count(), workloads={'synthetic': {'n': SYNTH_N, 'active_prefixes': SYNTH_ACTIVE, 'span_s': SYNTH_SPAN_S, 'seed': SYNTH_SEED}, 'real': {'path': rel(CIC), 'n_records': n_cic, 'n_ipv4_processed': n_ipv4, 'sampling': False}}, parse_only_rows=[{'n': c, 'wall_s': round(d, 3)} for c, d in parse_rows], cpp=cpp_info, wall_s=round(time.time() - t_start, 1))
        print('[E7] wrote', csv_cp, flush=True)
        env_rows = envelope(py_kpps, cpp_mpps, py_kpps_e2e=py_e2e_med)
        csv_env = os.path.join(RES, 'e7_envelope.csv')
        rc.write_csv(csv_env, env_rows)
        rc.write_meta(csv_env, experiment='E7-envelope', digest_bytes_per_pkt=PKT_BYTES_DIGEST, single_core={'python_kpps_state_machine': py_kpps, 'python_kpps_end2end_incl_parse': py_e2e_med, 'cpp_mpps': cpp_mpps}, premise='16 B digest per packet; aggregate pps = prefixes x per-prefix pps; cores = ceil(aggregate pps / single-core throughput); state-machine kpps is the primary basis', wall_s=round(time.time() - t_start, 1))
        print('[E7] wrote', csv_env, flush=True)
    if args.cmd in ('all', 'envelope'):
        if py_kpps is None:
            cp = os.path.join(RES, 'e7_controlplane.csv')
            if os.path.exists(cp):
                py_e2e = None
                for row in csv.DictReader(open(cp, encoding='utf-8')):
                    if row['impl'] == 'python-ref' and row['workload'] == 'synthetic-1M-5kpfx':
                        py_kpps = float(row['median_kpps'])
                    if row['impl'] == 'python-ref' and row['workload'] == 'CIC-IDS-2017-full':
                        py_e2e = float(row['median_kpps'])
                    if row['impl'] == 'cpp-insert' and row['workload'] == 'CIC-IDS-2017-full':
                        cpp_mpps = float(row['median_kpps']) / 1000.0
        if py_kpps is None:
            print('[E7] missing control-plane throughput; run the throughput command first', file=sys.stderr)
            return 2
        env_rows = envelope(py_kpps, cpp_mpps, py_kpps_e2e=py_e2e)
        csv_env = os.path.join(RES, 'e7_envelope.csv')
        rc.write_csv(csv_env, env_rows)
        rc.write_meta(csv_env, experiment='E7-envelope', digest_bytes_per_pkt=PKT_BYTES_DIGEST, single_core={'python_kpps_state_machine': py_kpps, 'python_kpps_end2end_incl_parse': py_e2e, 'cpp_mpps': cpp_mpps}, premise='16 B digest per packet; aggregate pps = prefixes x per-prefix pps; cores = ceil(aggregate pps / single-core throughput); state-machine kpps is the primary basis', wall_s=round(time.time() - t_start, 1))
        print('[E7] wrote', csv_env, flush=True)
    print('[E7] done in %.1fs' % (time.time() - t_start), flush=True)
    return 0
if __name__ == '__main__':
    sys.exit(main())
