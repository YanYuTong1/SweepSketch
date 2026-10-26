from __future__ import annotations
import argparse
import csv
from array import array
import json
import os
import random
import sys
import time
from datetime import datetime
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rev_common as rc
rc.add_impl_path()
from sweepsketch import config
from sweepsketch.digest import Collector
from sweepsketch.epoch import epoch_full, epoch_of
from sweepsketch.pcapio import iter_pcap
from common import make_sketch
EXP = 'e4'
RES = os.path.join(rc.RESULTS, EXP)
TMP = os.path.join(RES, 'tmp')
B = rc.BENIGN_DIR
DATASETS = {'cic': ['CIC-IDS-2017-Benign.pcap'], 'iot': ['CIC-IoT-2023-Benign.pcap', 'CIC-IoT-2023-Benign1.pcap', 'CIC-IoT-2023-Benign2.pcap', 'CIC-IoT-2023-Benign3.pcap'], 'backbone': ['202607051400.pcap']}
THRESH = (8, 10, 12, 14, 16, 20)
FILE_SHIFT = 1000000000.0
P_BUSY = 50

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)
REC_N = 24

def _new_rec():
    return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, None, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

def _record(rec, distinct, pkt, hll_new=None):
    rec[0] += 1
    rec[2] += distinct
    if distinct > rec[3]:
        rec[3] = distinct
    if pkt >= P_BUSY:
        rec[1] += 1
        if distinct > rec[4]:
            rec[4] = distinct
        if distinct >= 12:
            rec[20] += 1
    for j, th in enumerate(THRESH):
        if distinct >= th:
            rec[14 + j] += 1
    if distinct < 8:
        rec[5 + distinct] += 1
    else:
        h = rec[13]
        if h is None:
            h = rec[13] = array('H', [0]) * 256
        h[min(distinct, 255)] += 1
    if hll_new is not None:
        rec[21] += 1
        if pkt >= P_BUSY:
            rec[22] += 1
            if hll_new > rec[23]:
                rec[23] = hll_new

def _record_hll(rec, hll_new, pkt):
    rec[21] += 1
    if pkt >= P_BUSY:
        rec[22] += 1
        if hll_new > rec[23]:
            rec[23] = hll_new

def _median(rec):
    n = rec[0]
    if n == 0:
        return 0.0
    half = (n + 1) // 2
    cum = 0
    for v in range(8):
        cum += rec[5 + v]
        if cum >= half:
            return float(v)
    h = rec[13]
    if h is None:
        return 7.0
    for v in range(256):
        cum += h[v]
        if cum >= half:
            return float(v)
    return 255.0

def run_config(dataset, mem_kb, gate, profile, outdir):
    files = DATASETS[dataset]
    config.USE_GATE = bool(gate)
    sk = make_sketch(config.THETA0, mem_kb)
    col = Collector()
    n = 0
    t_start = time.time()
    file_rows = []
    per_pfx = {}
    win_sets = {}
    win_pkts = {}
    cur = {}
    cur_win = None
    stat_win = {'n_windows': 0}

    def flush_win():
        for pfx2, st in win_sets.items():
            pkt2 = win_pkts.get(pfx2, 0)
            rec = per_pfx.get(pfx2)
            if rec is None:
                rec = per_pfx[pfx2] = _new_rec()
            r = cur.pop(pfx2, None)
            _record(rec, len(st), pkt2, r[0] if r else None)
        for pfx2, r in cur.items():
            rec = per_pfx.get(pfx2)
            if rec is None:
                rec = per_pfx[pfx2] = _new_rec()
            _record_hll(rec, r[0], r[1])
        win_sets.clear()
        win_pkts.clear()
        cur.clear()
        stat_win['n_windows'] += 1
    for fi, fn in enumerate(files):
        path = os.path.join(B, fn)
        shift = fi * FILE_SHIFT if len(files) > 1 else 0.0
        fmin = fmax = None
        fpk = 0
        for s, d, ts in iter_pcap(path, config.BENIGN_MAX, with_flow=False):
            n += 1
            fpk += 1
            ts2 = ts + shift
            if fmin is None or ts2 < fmin:
                fmin = ts2
            if fmax is None or ts2 > fmax:
                fmax = ts2
            if profile:
                w = epoch_full(ts2)
                if cur_win is None:
                    cur_win = w
                elif w > cur_win:
                    flush_win()
                    cur_win = w
                pfx_key = d >> 8 << 8
                st = win_sets.get(pfx_key)
                if st is None:
                    st = win_sets[pfx_key] = set()
                st.add(d)
                win_pkts[pfx_key] = win_pkts.get(pfx_key, 0) + 1
                key1 = sk.l1.key_of(d)
                i1 = sk.l1.idx(key1)
                sk.process(s, d, ts2, col)
                b = sk.l1.buckets[i1]
                if b is not None and b.key == key1:
                    cur[key1] = [b.n_new, b.pkt]
            else:
                sk.process(s, d, ts2, col)
        file_rows.append({'file': fn, 'packets': fpk, 'dur_s': round(fmax - fmin if fmin is not None else 0.0, 2)})
    if profile:
        flush_win()
    wall = time.time() - t_start
    hours = sum((r['dur_s'] for r in file_rows)) / 3600.0
    alerts = [a for a in col.alerts if a.level == 1]
    by_pfx = {}
    for a in alerts:
        by_pfx.setdefault(a.key, []).append(a.ts)
    active = set(by_pfx) | set(per_pfx)
    n_active = len(per_pfx) if profile else None
    n_alerted = len(by_pfx)
    ev = len(alerts)
    payload = {'dataset': dataset, 'mem_kb': mem_kb, 'gate': bool(gate), 'profile': profile, 'files': file_rows, 'n_files': len(files), 'n_packets': n, 'wall_s': round(wall, 1), 'throughput_kpps': round(n / wall / 1000, 1), 'hours_total': round(hours, 4), 'n_active_pfx': n_active, 'n_alerted_pfx': n_alerted, 'n_events_l1': ev, 'events_per_pfx_hour': round(ev / max(n_active or n_alerted or 1, 1) / max(hours, 1e-09), 6) if n_active else None, 'n_windows_profile': stat_win['n_windows'] if profile else None, 'alerted_prefixes': {pfx_str(k): len(v) for k, v in sorted(by_pfx.items())}, 'n_l2_alerts': len([a for a in col.alerts if a.level == 2]), 'started': datetime.now().astimezone().isoformat()}
    os.makedirs(outdir, exist_ok=True)
    tag = f"{dataset}_{mem_kb}_{('on' if gate else 'off')}"
    p = os.path.join(outdir, tag + '.json')
    json.dump(payload, open(p, 'w'), indent=1)
    if profile:
        _write_profile(dataset, mem_kb, gate, per_pfx, outdir, file_rows, hours)
    print(f"[{tag}] {n:,} pkts  {wall:.0f}s ({payload['throughput_kpps']} kpps)  alerted /24={n_alerted}  events={ev}  hours={hours:.2f}", flush=True)
    return payload

def _write_profile(dataset, mem_kb, gate, per_pfx, outdir, file_rows, hours):
    tag = f"{dataset}_{mem_kb}_{('on' if gate else 'off')}"
    p = os.path.join(outdir, tag + '_profile.csv')
    fields = ['prefix', 'n_windows', 'n_windows_busy', 'max_distinct', 'max_distinct_busy', 'median_distinct', 'mean_distinct'] + [f'n_ge{k}' for k in THRESH] + ['n_ge12_busy', 'max_hll_busy', 'alerted']
    alerted = {}
    aj = os.path.join(outdir, tag + '.json')
    if os.path.exists(aj):
        alerted = json.load(open(aj)).get('alerted_prefixes', {})
    with open(p, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for pfx, rec in per_pfx.items():
            w.writerow({'prefix': pfx_str(pfx), 'n_windows': rec[0], 'n_windows_busy': rec[1], 'max_distinct': rec[3], 'max_distinct_busy': rec[4], 'median_distinct': _median(rec), 'mean_distinct': round(rec[2] / rec[0], 3) if rec[0] else 0, 'alerted': 1 if pfx_str(pfx) in alerted else 0, **{f'n_ge{k}': rec[14 + j] for j, k in enumerate(THRESH)}, 'n_ge12_busy': rec[20], 'max_hll_busy': rec[23]})
    flo_all = {k: sum((1 for r in per_pfx.values() if r[3] >= k)) for k in THRESH}
    flo_busy = {k: sum((1 for r in per_pfx.values() if r[4] >= k)) for k in THRESH}
    flo_hll = {k: sum((1 for r in per_pfx.values() if r[23] >= k)) for k in THRESH}
    med = sorted((_median(r) for r in per_pfx.values()))
    summ = {'dataset': dataset, 'mem_kb': mem_kb, 'gate': bool(gate), 'n_active_pfx': len(per_pfx), 'n_windows': None, 'hours_total': round(hours, 4), 'files': file_rows, 'flo_all': {str(k): v for k, v in flo_all.items()}, 'flo_busy': {str(k): v for k, v in flo_busy.items()}, 'flo_hll_busy': {str(k): v for k, v in flo_hll.items()}, 'median_distinct_p50': med[len(med) // 2] if med else 0, 'median_distinct_p99': med[int(0.99 * (len(med) - 1))] if med else 0, 'max_distinct_overall': max((r[3] for r in per_pfx.values()), default=0)}
    json.dump(summ, open(os.path.join(outdir, tag + '_profile_summary.json'), 'w'), indent=1)
    print(f'  profile -> {p}  active /24={len(per_pfx)}  flo_busy>=12={flo_busy[12]}  flo_hll>=12={flo_hll[12]}', flush=True)

def diag_cic(outdir, mem_kb=512, gate=True, target='192.168.10.0/24'):
    parts = target.split('/')[0].split('.')
    key = int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8
    config.USE_GATE = bool(gate)
    sk = make_sketch(config.THETA0, mem_kb)
    col = Collector()
    wins = {}
    cur_win = None
    alert_rows = []
    n_pkt_total = n_pkt_target = 0
    seen_alerts = 0
    i1 = sk.l1.idx(key)
    for s, d, ts in iter_pcap(os.path.join(B, 'CIC-IDS-2017-Benign.pcap'), config.BENIGN_MAX, with_flow=False):
        n_pkt_total += 1
        w = epoch_full(ts)
        if cur_win is None:
            cur_win = w
        elif w > cur_win:
            cur_win = w
        if d >> 8 << 8 == key:
            n_pkt_target += 1
            e = wins.get(w)
            if e is None:
                e = wins[w] = [set(), 0]
            e[0].add(d)
            e[1] += 1
        sk.process(s, d, ts, col)
        if len(col.alerts) > seen_alerts:
            for al in col.alerts[seen_alerts:]:
                if al.level == 1 and al.key == key:
                    bk = sk.l1.buckets[i1]
                    alert_rows.append({'ts': round(al.ts, 6), 'reason': al.reason, 'k_n_new_at_alarm': al.k, 'C': al.C, 'pkt': al.pkt, 'bucket_key': '%d.%d.%d.0/24' % (bk.key >> 24 & 255, bk.key >> 16 & 255, bk.key >> 8 & 255) if bk else '', 'bucket_n_new': bk.n_new if bk else '', 'bucket_C': bk.C if bk else '', 'bucket_pkt': bk.pkt if bk else '', 'bucket_pkt_ewma': bk.pkt_ewma if bk else '', 'bucket_n_ewma': bk.n_ewma if bk else '', 'bucket_win': bk.win if bk else ''})
            seen_alerts = len(col.alerts)
    os.makedirs(outdir, exist_ok=True)
    rows = []
    for w, (st, pkt) in sorted(wins.items()):
        rows.append({'window_id': w, 'window_start': round(w * config.EPOCH_NS / 1000000000.0, 6), 'distinct': len(st), 'packets': pkt})
    rc.write_csv(os.path.join(outdir, 'diag_cic_192_168_10_0_windows.csv'), rows)
    rc.write_csv(os.path.join(outdir, 'diag_cic_192_168_10_0_alerts.csv'), alert_rows)
    dist = sorted((len(st) for st, _ in wins.values()))
    busy = sorted((len(st) for st, pkt in wins.values() if pkt >= P_BUSY))
    print(f'[diag] CIC full: {n_pkt_total:,} pkts; target {target}: {n_pkt_target:,} pkts in {len(wins)} windows', flush=True)
    if dist:
        q = lambda arr, p: arr[min(len(arr) - 1, int(p * (len(arr) - 1)))]
        print(f'[diag] window distinct (all windows): p50={q(dist, 0.5)} p95={q(dist, 0.95)} p99={q(dist, 0.99)} max={dist[-1]}', flush=True)
    if busy:
        q = lambda arr, p: arr[min(len(arr) - 1, int(p * (len(arr) - 1)))]
        print(f'[diag] window distinct (busy pkt>=50, n={len(busy)}): p50={q(busy, 0.5)} p99={q(busy, 0.99)} max={busy[-1]}', flush=True)
    l1 = [a for a in col.alerts if a.level == 1]
    l2 = [a for a in col.alerts if a.level == 2]
    byp = {}
    for al in l1:
        byp[al.key] = byp.get(al.key, 0) + 1
    print(f'[diag] fresh Collector: L1={len(l1)} events across {len(byp)} prefixes, L2={len(l2)}; target L1={byp.get(key, 0)}', flush=True)
    for kk, v in sorted(byp.items(), key=lambda x: -x[1])[:10]:
        print(f'        {pfx_str(kk)}: {v} events', flush=True)
    if alert_rows:
        from collections import Counter
        print(f"[diag] target reasons: {dict(Counter((r['reason'] for r in alert_rows)))}", flush=True)
        r0 = alert_rows[0]
        print(f"[diag] first target alarm: ts={r0['ts']} reason={r0['reason']} k={r0['k_n_new_at_alarm']} C={r0['C']} pkt={r0['pkt']} n_ewma={r0['bucket_n_ewma']} pkt_ewma={r0['bucket_pkt_ewma']}", flush=True)
    rc.write_meta(os.path.join(outdir, 'diag_cic_192_168_10_0_windows.csv'), exp='e4-diag', target=target, mem_kb=mem_kb, gate=gate, n_packets_total=n_pkt_total, n_packets_target=n_pkt_target, n_windows=len(wins), n_alerts_l1=len(l1), n_alerts_l2=len(l2))
    return {'n_packets': n_pkt_total, 'n_target': n_pkt_target, 'n_windows': len(wins), 'dist': dist, 'alerts': alert_rows, 'l1': len(l1), 'l2': len(l2)}

def run_cdn(seeds, outdir, rate_levels=(10, 100, 1000), n_pfx=8, hosts=256, dur_s=3600):
    rows = []
    config.USE_GATE = True
    os.makedirs(outdir, exist_ok=True)
    for seed in seeds:
        rng = random.Random(seed)
        base = 3323068416
        pfx_list = [base + i * 256 for i in range(n_pfx)]
        pools = {p: [p | h for h in range(hosts)] for p in pfx_list}
        for rate in rate_levels:
            sk = make_sketch(config.THETA0, 512)
            col = Collector()
            t0 = 0.0
            n_pkts = 0
            for sec in range(dur_s):
                for p in pfx_list:
                    pool = pools[p]
                    k = min(rate, hosts)
                    hosts_sec = rng.sample(pool, k) if k < hosts else pool[:]
                    for j in range(rate):
                        d = hosts_sec[j % k]
                        ts = t0 + sec + (j + 0.5) / rate
                        sk.process(0, d, ts, col)
                        n_pkts += 1
            alerts = [a for a in col.alerts if a.level == 1]
            by_pfx = {}
            for a in alerts:
                by_pfx.setdefault(a.key, []).append(a.ts)
            alerted = len(by_pfx)
            ev = len(alerts)
            rows.append({'seed': seed, 'rate_pps_per_pfx': rate, 'n_pfx': n_pfx, 'hosts_per_pfx': hosts, 'dur_s': dur_s, 'n_packets': n_pkts, 'alerted_pfx': alerted, 'fpr_prefix': round(alerted / n_pfx, 6), 'n_events': ev, 'events_per_pfx_hour': round(ev / n_pfx / (dur_s / 3600), 6)})
            print(f'[cdn] seed={seed} rate={rate} pps/pfx  alerted={alerted}/{n_pfx} events={ev}  ({n_pkts:,} pkts)', flush=True)
    p = os.path.join(outdir, 'e4_cdn.csv')
    rc.write_csv(p, rows)
    rc.write_meta(p, exp=EXP, seeds=list(seeds), rate_levels=list(rate_levels), n_pfx=n_pfx, hosts_per_pfx=hosts, dur_s=dur_s, budget_kb=512, gate=True, note='synthetic CDN-shaped uniform flow; each /24 spreads min(rate,hosts) distinct hosts per second uniformly; no benign background')
    return rows

def aggregate():
    import glob
    outdir = TMP
    files = sorted(glob.glob(os.path.join(outdir, '*_*.json')))
    files = [f for f in files if not f.endswith('_profile_summary.json')]
    runs = [json.load(open(f)) for f in files]
    runs = [r for r in runs if 'dataset' in r and 'mem_kb' in r]
    runs.sort(key=lambda r: (r['dataset'], r['mem_kb'], r['gate']))
    summ_files = sorted(glob.glob(os.path.join(outdir, '*_profile_summary.json')))
    prof = [json.load(open(f)) for f in summ_files]
    prof_map = {(r['dataset'], r['mem_kb'], r['gate']): r for r in prof}
    prof_any = {}
    for k, r in prof_map.items():
        if k[1] == 512 and k[2]:
            prof_any[k[0]] = r
    allrows = []
    for r in runs:
        key = (r['dataset'], r['mem_kb'], r['gate'])
        pr = prof_map.get(key) or prof_any.get(r['dataset'])
        act = r['n_active_pfx'] if r['n_active_pfx'] is not None else (pr or {}).get('n_active_pfx', '')
        epa = r['events_per_pfx_hour']
        if not epa and act:
            epa = round(r['n_events_l1'] / act / max(r['hours_total'], 1e-09), 6)
        allrows.append({'dataset': r['dataset'], 'mem_kb': r['mem_kb'], 'gate': 'on' if r['gate'] else 'off', 'n_files': r['n_files'], 'n_packets': r['n_packets'], 'hours_total': r['hours_total'], 'n_active_pfx': act, 'n_alerted_pfx': r['n_alerted_pfx'], 'n_events_l1': r['n_events_l1'], 'n_l2_alerts': r['n_l2_alerts'], 'events_per_pfx_hour': epa, 'n_high_scatter_ge12_busy': (pr or {}).get('flo_busy', {}).get('12', ''), 'n_high_scatter_ge12_hll': (pr or {}).get('flo_hll_busy', {}).get('12', ''), 'n_high_scatter_ge16_hll': (pr or {}).get('flo_hll_busy', {}).get('16', ''), 'n_high_scatter_ge20_hll': (pr or {}).get('flo_hll_busy', {}).get('20', ''), 'wall_s': r['wall_s'], 'throughput_kpps': r['throughput_kpps']})
    for ds in ('cic', 'iot', 'backbone'):
        rows = [r for r in allrows if r['dataset'] == ds]
        if not rows:
            continue
        p = os.path.join(RES, f'e4_benign_{ds}.csv')
        rc.write_csv(p, rows)
        rc.write_meta(p, exp=EXP, dataset=ds, configs=[{'mem_kb': r['mem_kb'], 'gate': r['gate']} for r in rows], full_scale=True, sampling=False, max_pkts=False, workers=os.environ.get('SWEEPSKETCH_WORKERS', '4'), note='full benign trace(s); alerts = L1 (level-1) collector events; n_high_scatter from exact per-window distinct profile')

        def _per_alerted(r):
            ap, ev, hrs = (r['n_alerted_pfx'], r['n_events_l1'], r['hours_total'])
            return round(ev / ap / hrs, 3) if ap and hrs else ''
        srows = [{'dataset': r['dataset'], 'mem_kb': r['mem_kb'], 'gate': r['gate'], 'active_pfx': r['n_active_pfx'], 'alerted_pfx': r['n_alerted_pfx'], 'events_l1': r['n_events_l1'], 'events_per_active_pfx_hour': r['events_per_pfx_hour'], 'events_per_alerted_pfx_hour': _per_alerted(r), 'flo_busy_ge12': r['n_high_scatter_ge12_busy'], 'l2_alerts': r['n_l2_alerts']} for r in rows]
        p = os.path.join(RES, f'e4_{ds}_summary.csv')
        rc.write_csv(p, srows)
        rc.write_meta(p, exp=EXP, dataset=ds)
    p = os.path.join(RES, 'e4_longrun_summary.csv')
    rc.write_csv(p, allrows)
    rc.write_meta(p, exp=EXP, datasets=sorted({r['dataset'] for r in allrows}), full_scale=True, backbone_note='only 1 of the claimed 5 backbone traces exists locally (202607051400.pcap, 197.5M pkts/15min)')
    if prof:
        prow = []
        for r in sorted(prof, key=lambda x: (x['dataset'], x['mem_kb'], x['gate'])):
            row = {'dataset': r['dataset'], 'mem_kb': r['mem_kb'], 'gate': 'on' if r['gate'] else 'off', 'n_active_pfx': r['n_active_pfx'], 'hours_total': r['hours_total'], 'median_distinct_p50': r['median_distinct_p50'], 'median_distinct_p99': r['median_distinct_p99'], 'max_distinct_overall': r['max_distinct_overall']}
            for k in THRESH:
                row[f'flo_all_ge{k}'] = r['flo_all'][str(k)]
                row[f'flo_busy_ge{k}'] = r['flo_busy'][str(k)]
                row[f'flo_hll_ge{k}'] = r['flo_hll_busy'][str(k)]
            prow.append(row)
        p = os.path.join(RES, 'e4_profile_summary.csv')
        rc.write_csv(p, prow)
        rc.write_meta(p, exp=EXP, note='exact per-window distinct (4.294967296 s windows) + HLL n_new (pkt>=50 busy-window max) per /24; flo_* = counts of prefixes above threshold')
        for r in prof:
            if r['dataset'] == 'backbone':
                src = os.path.join(outdir, 'backbone_%d_%s_profile.csv' % (r['mem_kb'], 'on' if r['gate'] else 'off'))
                if os.path.exists(src):
                    import shutil
                    shutil.copy(src, os.path.join(RES, 'backbone_profile.csv'))
                    summ = dict(r)
                    json.dump(summ, open(os.path.join(RES, 'backbone_profile.meta.json'), 'w'), indent=1)
                    break
    arows = []
    for r in runs:
        for pfx, cnt in r.get('alerted_prefixes', {}).items():
            arows.append({'dataset': r['dataset'], 'mem_kb': r['mem_kb'], 'gate': 'on' if r['gate'] else 'off', 'prefix': pfx, 'events': cnt})
    if arows:
        p = os.path.join(RES, 'e4_alerted_prefixes.csv')
        rc.write_csv(p, arows)
        rc.write_meta(p, exp=EXP)
    print(f'[aggregate] {len(runs)} configs -> {RES}/e4_*.csv')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', choices=list(DATASETS), default=None)
    ap.add_argument('--configs', default='512:on', help='comma-separated mem:gate pairs, e.g. 512:on,512:off,1024:on,1024:off')
    ap.add_argument('--profile', action='store_true', help='also compute the per-/24 per-window dispersion profile (slower)')
    ap.add_argument('--cdn', action='store_true')
    ap.add_argument('--diag-cic', action='store_true', help='full CIC stream plus targeted diagnostics for 192.168.10.0/24 (per-window distinct counts and alarm state)')
    ap.add_argument('--seeds', default='0,1,2,3,4')
    ap.add_argument('--aggregate', action='store_true')
    args = ap.parse_args()
    os.makedirs(TMP, exist_ok=True)
    if args.aggregate:
        aggregate()
        return
    if args.diag_cic:
        diag_cic(TMP)
        return
    if args.cdn:
        run_cdn([int(x) for x in args.seeds.split(',')], RES)
        return
    cfgs = []
    for tok in args.configs.split(','):
        mem, gate = tok.split(':')
        cfgs.append((int(mem), gate == 'on'))
    for mem, gate in cfgs:
        do_prof = args.profile and mem == 512 and gate
        run_config(args.dataset, mem, gate, do_prof, TMP)
if __name__ == '__main__':
    main()
