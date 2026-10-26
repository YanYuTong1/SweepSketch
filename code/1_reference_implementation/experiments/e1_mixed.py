from __future__ import annotations
import argparse
import csv
import heapq
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
from sweepsketch.pcapio import iter_pcap
from common import make_sketch, ip24
from baselines.step02_baselines import _build
EXP = 'e1'
RES = os.path.join(rc.RESULTS, EXP)
TMP = os.path.join(RES, 'tmp')
CIC = os.path.join(rc.BENIGN_DIR, 'CIC-IDS-2017-Benign.pcap')
SEEDS = [0, 1, 2, 3, 4]
BUDGET_KB = 512
EPOCH_S = config.EPOCH_NS / 1000000000.0
ROUND_GAP = 12.0
GAP_RESERVE = 600.0
TAU_CSV = os.environ.get('SWEEPSKETCH_TAU_CSV', '')
TAU_FALLBACK = {'entropy': 4.37, 'mrb': 36.07, 'rhhh': 13727.88, 'elastic': 67694.14, 'heavykeeper': 67694.14}
DST_METHODS = ('entropy', 'mrb', 'rhhh', 'elastic', 'heavykeeper')

def load_tau():
    tau = dict(TAU_FALLBACK)
    if os.path.exists(TAU_CSV):
        with open(TAU_CSV, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                m = row.get('method')
                if m in tau and row.get('tau'):
                    tau[m] = float(row['tau'])
    return tau

def cic_profile():
    cache = os.path.join(RES, 'e1_cic_profile.json')
    if os.path.exists(cache):
        return json.load(open(cache))
    t0 = time.time()
    n = 0
    tmin = tmax = None
    pfx = set()
    for s, d, ts in iter_pcap(CIC, config.BENIGN_MAX, with_flow=False):
        n += 1
        if tmin is None or ts < tmin:
            tmin = ts
        if tmax is None or ts > tmax:
            tmax = ts
        pfx.add(d >> 8 << 8)
    out = {'file': os.path.basename(CIC), 'packets': n, 'n_prefixes': len(pfx), 'tmin': tmin, 'tmax': tmax, 'span_s': tmax - tmin, 'parse_s': round(time.time() - t0, 1), 'stat': rc.file_stat(CIC), 'prefixes': sorted(pfx)}
    os.makedirs(RES, exist_ok=True)
    json.dump(out, open(cache, 'w'), indent=1)
    print(f"[cic] {n:,} pkts  span={tmax - tmin:.1f}s  /24={len(pfx)}  ({out['parse_s']}s)", flush=True)
    return out

def attack_meta():
    cache = os.path.join(RES, 'e1_attack_meta.json')
    if os.path.exists(cache):
        return json.load(open(cache))
    t0 = time.time()
    rows = []
    for f in rc.attack_files():
        path = os.path.join(rc.ATTACK_DIR, f)
        n = 0
        first = last = None
        pfxs = set()
        for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
            n += 1
            if first is None or ts < first:
                first = ts
            if last is None or ts > last:
                last = ts
            pfxs.add(d >> 8 << 8)
        rows.append({'file': f, 'packets': n, 't0': first, 't1': last, 'dur_s': last - first if n else 0.0, 'gt_prefix': ip24(f.split('_')[0]), 'n_distinct_24': len(pfxs), 'stat': rc.file_stat(path)})
    out = {'files': rows, 'n_files': len(rows), 'n_packets': sum((r['packets'] for r in rows)), 'parse_s': round(time.time() - t0, 1)}
    os.makedirs(RES, exist_ok=True)
    json.dump(out, open(cache, 'w'), indent=1)
    print(f"[attack] {len(rows)} files, {out['n_packets']:,} pkts ({out['parse_s']}s)", flush=True)
    return out

def _win(f, t0, round_i, scale=1.0, jitter=0.0):
    return {'file': f['file'], 'gt_prefix': f['gt_prefix'], 'orig_dur_s': f['dur_s'], 'win_dur_s': f['dur_s'] * scale, 'scale': scale, 'jitter_s': jitter, 't0': t0, 't1': t0 + f['dur_s'] * scale, 'packets': f['packets'], 'round': round_i}

def build_rounds(meta, cic, seed):
    span = cic['span_s']
    tmin = cic['tmin']
    files = meta['files']
    cap = span - GAP_RESERVE
    groups, cur, cursum = ([], [], 0.0)
    for f in files:
        d = f['dur_s']
        if cur and cursum + d > cap:
            groups.append(cur)
            cur, cursum = ([], 0.0)
        cur.append(f)
        cursum += d
    groups.append(cur)
    assert len(groups) <= 4, f'requires {len(groups)} rounds > 4'
    rng = random.Random(10000 + seed)
    rounds = []
    for r, g in enumerate(groups):
        r0 = tmin + r * (span + ROUND_GAP)
        tot = sum((f['dur_s'] for f in g))
        slack = span - tot
        assert slack > 0, (r, tot, span)
        n = len(g)
        w = [rng.uniform(0.5, 1.5) for _ in range(n + 1)]
        sw = sum(w)
        gaps = [x / sw * slack for x in w]
        t = r0
        wins = []
        for f, gp in zip(g, gaps):
            t += gp
            wins.append(_win(f, t, r, 1.0, gp))
            t += f['dur_s']
        rounds.append({'round': r, 't0': r0, 't1': r0 + span, 'n_files': n, 'n_packets': sum((f['packets'] for f in g)), 'sum_dur_s': round(tot, 1), 'slack_s': round(slack, 1), 'min_gap_s': round(min(gaps), 2), 'max_end_slack_s': round(span - (wins[-1]['t1'] - r0), 2), 'wins': wins})
    return rounds

def build_slot(meta, cic, seed):
    span = cic['span_s']
    tmin = cic['tmin']
    slot = span / len(meta['files'])
    rng = random.Random(seed)
    wins = []
    for i, f in enumerate(meta['files']):
        base = tmin + i * slot
        dur = f['dur_s']
        fit = min(dur, slot)
        scale = fit / dur if dur > 0 else 1.0
        jitter = rng.random() * (slot - fit)
        wins.append(_win(f, base + jitter, 0, scale, jitter))
    for a, b in zip(wins, wins[1:]):
        assert a['t1'] <= b['t0'] + 1e-09
    return wins

def _attack_gen(w):
    first = None
    for s, d, ts in iter_pcap(os.path.join(rc.ATTACK_DIR, w['file']), config.ATTACK_MAX, with_flow=False):
        if first is None:
            first = ts
        yield (s, d, w['t0'] + (ts - first) * w['scale'])

def _benign_gen(shift):
    for s, d, ts in iter_pcap(CIC, config.BENIGN_MAX, with_flow=False):
        yield (s, d, ts + shift)

def stream_round(wins, shift):
    streams = [_benign_gen(shift)] + [_attack_gen(w) for w in wins]
    return heapq.merge(*streams, key=lambda x: x[2])

def stream_slot(wins):
    streams = [_benign_gen(0.0)] + [_attack_gen(w) for w in wins]
    return heapq.merge(*streams, key=lambda x: x[2])

def pct(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    k = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[k]

def _prf(tp, fp, fn):
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': round(tp / (tp + fp), 6) if tp + fp else 0.0, 'recall': round(tp / (tp + fn), 6) if tp + fn else 0.0, 'f1': round(2 * tp / (2 * tp + fp + fn), 6) if 2 * tp + fp + fn else 0.0}

def _summ_sweep(gt_attack, by_pfx, alerts_range, wins):
    flagged = set(by_pfx)
    tp = len(gt_attack & flagged)
    fp = len(flagged - gt_attack)
    fn = len(gt_attack) - tp
    out = _prf(tp, fp, fn)
    tp_ev = sum((len(by_pfx[k]) for k in gt_attack if k in by_pfx))
    fp_ev = sum((len(v) for k, v in by_pfx.items() if k not in gt_attack))
    out.update({'tp_events': tp_ev, 'fp_events': fp_ev, 'alarm_precision': round(tp_ev / (tp_ev + fp_ev), 6) if tp_ev + fp_ev else 0.0, 'n_alerts_l1': len(alerts_range), 'fp_prefixes': sorted(flagged - gt_attack)})
    lat = []
    det = 0
    for w in wins:
        hits = [t for t in by_pfx.get(w['gt_prefix'], []) if w['t0'] - EPOCH_S <= t <= w['t1'] + EPOCH_S]
        if hits:
            det += 1
            lat.append(min(hits) - w['t0'])
    out.update({'n_files': len(wins), 'n_files_detected': det, 'lat_n': len(lat), 'lat_p50': pct(lat, 0.5), 'lat_p95': pct(lat, 0.95), 'lat_p99': pct(lat, 0.99), 'lat_max': max(lat) if lat else None, 'lat_mean': round(sum(lat) / len(lat), 3) if lat else None})
    return out

def _all_gt(rounds):
    return {w['gt_prefix'] for r in rounds for w in r['wins']}

def run_seed(seed, mode, meta, cic, tau, methods=DST_METHODS):
    t_start = time.time()
    gt_benign = set(cic['prefixes'])
    if mode == 'rounds':
        rounds = build_rounds(meta, cic, seed)
        all_wins = [w for r in rounds for w in r['wins']]
        gt_attack = _all_gt(rounds)
    else:
        wins = build_slot(meta, cic, seed)
        all_wins = wins
        gt_attack = {w['gt_prefix'] for w in wins}
    assert not gt_attack & gt_benign, 'attack /24 conflicts with a CIC benign /24'
    n_pfx = len(gt_attack | gt_benign)
    sk = make_sketch(config.THETA0, BUDGET_KB)
    col = Collector()
    bases, binfo, round_snaps = ({}, {}, [])
    for m in methods:
        b, mem, struct = _build(m, BUDGET_KB, n_pfx)
        bases[m] = b
        binfo[m] = {'memory_kb': round(mem, 1), 'structure': struct}
    n = 0
    if mode == 'rounds':
        for r in rounds:
            shift = r['t0'] - cic['tmin']
            for s, d, ts in stream_round(r['wins'], shift):
                sk.process(s, d, ts, col)
                for b in bases.values():
                    b.insert(s, d, n)
                n += 1
            snap = {}
            g = {w['gt_prefix'] for w in r['wins']}
            for m, b in bases.items():
                sc = b.query()
                fset = {p for p, v in sc.items() if v > tau[m]}
                snap[m] = _prf(len(g & fset), len(fset - g), len(g - fset))
                snap[m]['n_entities'] = len(sc)
            round_snaps.append(snap)
            print(f"  [seed {seed}] round {r['round']} done  {r['n_files']} files  n={n:,}  {time.time() - t_start:.0f}s", flush=True)
    else:
        for s, d, ts in stream_slot(wins):
            sk.process(s, d, ts, col)
            for b in bases.values():
                b.insert(s, d, n)
            n += 1
    wall = time.time() - t_start
    alerts = [a for a in col.alerts if a.level == 1]
    by_pfx = {}
    for a in alerts:
        by_pfx.setdefault(a.key, []).append(a.ts)
    glob = _summ_sweep(gt_attack, by_pfx, alerts, all_wins)
    prows = []
    for r in rounds if mode == 'rounds' else []:
        g = {w['gt_prefix'] for w in r['wins']}
        ts_lo = r['t0'] - 2 * EPOCH_S
        ts_hi = min(r['wins'][-1]['t1'] + 2 * EPOCH_S, r['t1'] + EPOCH_S)
        al_r = [a for a in alerts if ts_lo <= a.ts <= ts_hi]
        bp = {}
        for a in al_r:
            bp.setdefault(a.key, []).append(a.ts)
        sm = _summ_sweep(g, bp, al_r, r['wins'])
        sm['fp'] = sum((1 for k in bp if k not in gt_attack))
        sm['fp_events'] = sum((len(v) for k, v in bp.items() if k not in gt_attack))
        prows.append({'round': r['round'], 'n_files': r['n_files'], 'n_packets_round': r['n_packets'], **sm})
    brow_round = []
    for ri, snap in enumerate(round_snaps):
        for m in methods:
            row = dict(snap.get(m, {}))
            row['round'] = ri
            row['method'] = m
            brow_round.append(row)
    hourly = []
    if mode == 'rounds':
        n_hours = int((rounds[-1]['t1'] - cic['tmin']) // 3600) + 2
        for h in range(n_hours):
            lo = cic['tmin'] + h * 3600
            hi = lo + 3600
            al_h = [a for a in alerts if lo <= a.ts < hi]
            bp = {}
            for a in al_h:
                bp.setdefault(a.key, []).append(a.ts)
            files_h = [w for w in all_wins if lo <= w['t0'] < hi]
            det_h = 0
            for w in files_h:
                if any((w['t0'] - EPOCH_S <= t <= w['t1'] + EPOCH_S for t in bp.get(w['gt_prefix'], []))):
                    det_h += 1
            hourly.append({'seed': seed, 'hour': h, 'n_alerts': len(al_h), 'tp_events': sum((len(v) for k, v in bp.items() if k in gt_attack)), 'fp_events': sum((len(v) for k, v in bp.items() if k not in gt_attack)), 'fp_prefixes': len([k for k in bp if k not in gt_attack]), 'files_started': len(files_h), 'files_detected': det_h})
    brows = []
    for m, b in bases.items():
        sc = b.query()
        fset = {p for p, v in sc.items() if v > tau[m]}
        r = _prf(len(gt_attack & fset), len(fset - gt_attack), len(gt_attack - fset))
        brows.append({'seed': seed, 'method': m, 'tau': tau[m], 'n_entities': len(sc), **r, **binfo[m]})
    per_file = []
    for w in all_wins:
        hits = [t for t in by_pfx.get(w['gt_prefix'], []) if w['t0'] - EPOCH_S <= t <= w['t1'] + EPOCH_S]
        first = min(hits) - w['t0'] if hits else None
        per_file.append({'seed': seed, 'round': w['round'], 'file': w['file'], 'gt_prefix': '%d.%d.%d.0/24' % (w['gt_prefix'] >> 24 & 255, w['gt_prefix'] >> 16 & 255, w['gt_prefix'] >> 8 & 255), 'packets': w['packets'], 'orig_dur_s': round(w['orig_dur_s'], 2), 'win_dur_s': round(w['win_dur_s'], 2), 'scale': round(w['scale'], 6), 'jitter_s': round(w['jitter_s'], 3), 't0': round(w['t0'], 3), 't1': round(w['t1'], 3), 'n_alerts': len(by_pfx.get(w['gt_prefix'], [])), 'first_alert_s': None if first is None else round(first, 3), 'detected': 1 if first is not None else 0})
    out = {'seed': seed, 'mode': mode, 'n_pkts': n, 'wall_s': round(wall, 1), 'throughput_kpps': round(n / wall / 1000, 2), 'n_attack_files': len(all_wins), 'n_attack_packets': meta['n_packets'], 'n_cic_packets': cic['packets'], 'n_cic_rounds': 4 if mode == 'rounds' else 1, 'timeline_s': round(rounds[-1]['t1'] - cic['tmin'], 1) if mode == 'rounds' else round(cic['span_s'], 1), 'n_gt_attack': len(gt_attack), 'n_gt_benign': len(gt_benign), 'n_pfx_universe': n_pfx, 'round_layout': [] if mode != 'rounds' else [{'round': r['round'], 'n_files': r['n_files'], 'n_packets': r['n_packets'], 'sum_dur_s': r['sum_dur_s'], 'slack_s': r['slack_s'], 'min_gap_s': r['min_gap_s']} for r in rounds], 'methods': list(methods), 'sweep': glob, 'rounds': prows, 'baselines': brows, 'baselines_round_cumulative': brow_round, 'per_file': per_file, 'hourly': hourly}
    if mode == 'slot':
        out.update({'n_compressed': sum((1 for w in all_wins if w['scale'] < 1.0)), 'max_compress_ratio': round(1.0 / min((w['scale'] for w in all_wins), default=1.0), 2)})
    out['started'] = datetime.now().astimezone().isoformat()
    out['elapsed_s'] = round(time.time() - t_start, 1)
    out['argv'] = sys.argv
    out['host'] = {'platform': sys.platform, 'python': sys.version.split()[0]}
    out['tau'] = tau
    out['cic'] = {k: cic[k] for k in ('file', 'packets', 'n_prefixes', 'tmin', 'tmax', 'span_s')}
    out['attack'] = {'n_files': meta['n_files'], 'n_packets': meta['n_packets']}
    return out

def _read_tmp(prefix):
    import glob
    out = []
    for f in sorted(glob.glob(os.path.join(TMP, prefix + '_seed*.json'))):
        out.append(json.load(open(f)))
    return out

def aggregate(tau):
    runs = _read_tmp('rounds')
    runslot = _read_tmp('slot')
    main = runs if runs else runslot
    if not main:
        raise SystemExit('no tmp/{rounds,slot}_seed*.json found; run --seed k first')
    summ = []
    for r in main:
        sd = r['sweep']
        summ.append({'detector': 'sweepsketch', 'seed': r['seed'], 'tp': sd['tp'], 'fp': sd['fp'], 'fn': sd['fn'], 'precision': sd['precision'], 'recall': sd['recall'], 'f1': sd['f1'], 'tp_events': sd['tp_events'], 'fp_events': sd['fp_events'], 'alarm_precision': sd['alarm_precision'], 'n_alerts_l1': sd['n_alerts_l1'], 'fp_prefixes': len(sd['fp_prefixes']), 'n_files': sd['n_files'], 'n_files_detected': sd['n_files_detected'], 'lat_n': sd['lat_n'], 'lat_p50_s': sd['lat_p50'], 'lat_p95_s': sd['lat_p95'], 'lat_p99_s': sd['lat_p99'], 'lat_max_s': sd['lat_max'], 'n_pkts': r['n_pkts'], 'wall_s': r['wall_s']})
        for b in r['baselines']:
            summ.append({'detector': b['method'], 'seed': r['seed'], 'tp': b['tp'], 'fp': b['fp'], 'fn': b['fn'], 'precision': b['precision'], 'recall': b['recall'], 'f1': b['f1'], 'tp_events': '', 'fp_events': '', 'alarm_precision': '', 'n_alerts_l1': '', 'fp_prefixes': '', 'n_files': '', 'n_files_detected': '', 'lat_n': '', 'lat_p50_s': '', 'lat_p95_s': '', 'lat_p99_s': '', 'lat_max_s': '', 'n_pkts': r['n_pkts'], 'wall_s': r['wall_s']})
    fields = ['detector', 'seed', 'tp', 'fp', 'fn', 'precision', 'recall', 'f1', 'tp_events', 'fp_events', 'alarm_precision', 'n_alerts_l1', 'fp_prefixes', 'n_files', 'n_files_detected', 'lat_n', 'lat_p50_s', 'lat_p95_s', 'lat_p99_s', 'lat_max_s', 'n_pkts', 'wall_s']
    p = os.path.join(RES, 'e1_mixed_summary.csv')
    rc.write_csv(p, summ, fields)
    rc.write_meta(p, exp=EXP, protocol='rounds_no_compression', seeds=[r['seed'] for r in main], n_attack_files=main[0]['n_attack_files'], n_attack_packets=main[0]['n_attack_packets'], n_cic_packets=main[0]['n_cic_packets'], n_cic_rounds=main[0].get('n_cic_rounds'), n_pkts_per_run=main[0]['n_pkts'], n_gt_attack=main[0]['n_gt_attack'], n_gt_benign=main[0]['n_gt_benign'], n_pfx_universe=main[0]['n_pfx_universe'], round_layout=main[0].get('round_layout'), budget_kb=BUDGET_KB, tau=tau, window_mode='4x CIC replay; 71 attacks greedy-packed by filename order into 4 rounds; original durations preserved; no compression; 12s inter-round gap', methods_per_seed={str(r['seed']): r.get('methods', list(DST_METHODS)) for r in main}, sampling=False, max_pkts=False, full_attack_set=True, workers=os.environ.get('SWEEPSKETCH_WORKERS', '4'), note='attack dst/src preserved; 5 seeds vary gap jitter only')
    agg = []
    for det in ['sweepsketch'] + list(DST_METHODS):
        rows = [x for x in summ if x['detector'] == det]
        if not rows:
            continue
        f1s = [x['f1'] for x in rows]
        agg.append({'detector': det, 'n_seeds': len(rows), 'f1_mean': round(sum(f1s) / len(f1s), 6), 'f1_min': min(f1s), 'f1_max': max(f1s), 'tp_mean': round(sum((x['tp'] for x in rows)) / len(rows), 2), 'fp_mean': round(sum((x['fp'] for x in rows)) / len(rows), 2), 'fn_mean': round(sum((x['fn'] for x in rows)) / len(rows), 2)})
    p2 = os.path.join(RES, 'e1_mixed_seed_agg.csv')
    rc.write_csv(p2, agg)
    rc.write_meta(p2, exp=EXP, seeds=[r['seed'] for r in main])
    prow = []
    for r in main:
        for x in r['rounds']:
            prow.append({'seed': r['seed'], 'detector': 'sweepsketch', 'round': x['round'], 'n_files': x['n_files'], 'n_packets_round': x['n_packets_round'], 'tp': x['tp'], 'fp': x['fp'], 'fn': x['fn'], 'precision': x['precision'], 'recall': x['recall'], 'f1': x['f1'], 'tp_events': x['tp_events'], 'fp_events': x['fp_events'], 'alarm_precision': x['alarm_precision'], 'n_files_detected': x['n_files_detected'], 'lat_n': x['lat_n'], 'lat_p50_s': x['lat_p50'], 'lat_p95_s': x['lat_p95'], 'lat_p99_s': x['lat_p99'], 'lat_max_s': x['lat_max']})
        for x in r.get('baselines_round_cumulative', []):
            prow.append({'seed': r['seed'], 'detector': x['method'], 'round': x['round'], 'n_files': '', 'n_packets_round': '', 'tp': x['tp'], 'fp': x['fp'], 'fn': x['fn'], 'precision': x['precision'], 'recall': x['recall'], 'f1': x['f1'], 'tp_events': '', 'fp_events': '', 'alarm_precision': '', 'n_files_detected': '', 'lat_n': '', 'lat_p50_s': '', 'lat_p95_s': '', 'lat_p99_s': '', 'lat_max_s': ''})
    if prow:
        p3 = os.path.join(RES, 'e1_per_round.csv')
        rc.write_csv(p3, prow)
        rc.write_meta(p3, exp=EXP, seeds=[r['seed'] for r in main], note='SweepSketch = per-round metrics; baselines = cumulative snapshot at round end (no native time semantics)')
    latrows = [x for r in main for x in r['per_file']]
    p4 = os.path.join(RES, 'e1_mixed_latency.csv')
    rc.write_csv(p4, latrows)
    rc.write_meta(p4, exp=EXP, seeds=[r['seed'] for r in main], n_files=len(latrows), latency_basis='first L1 alert ts - window t0 (event time)')
    hrows = [x for r in main for x in r['hourly']]
    p5 = os.path.join(RES, 'e1_hourly.csv')
    rc.write_csv(p5, hrows)
    rc.write_meta(p5, exp=EXP, seeds=[r['seed'] for r in main])
    brows = [dict(b) for r in main for b in r['baselines']]
    p6 = os.path.join(RES, 'e1_mixed_baselines.csv')
    rc.write_csv(p6, brows)
    rc.write_meta(p6, exp=EXP, seeds=[r['seed'] for r in main], tau=tau, budget_kb=BUDGET_KB)
    p7 = os.path.join(RES, 'e1_windows.csv')
    rc.write_csv(p7, latrows)
    rc.write_meta(p7, exp=EXP, seeds=[r['seed'] for r in main], round_layout=main[0].get('round_layout'))
    if runslot:
        srows = []
        for r in runslot:
            sd = r['sweep']
            srows.append({'detector': 'sweepsketch', 'seed': r['seed'], 'n_compressed': r.get('n_compressed'), 'max_compress_ratio': r.get('max_compress_ratio'), 'tp': sd['tp'], 'fp': sd['fp'], 'fn': sd['fn'], 'precision': sd['precision'], 'recall': sd['recall'], 'f1': sd['f1'], 'tp_events': sd['tp_events'], 'fp_events': sd['fp_events'], 'alarm_precision': sd['alarm_precision'], 'lat_p50_s': sd['lat_p50'], 'lat_p95_s': sd['lat_p95'], 'lat_p99_s': sd['lat_p99'], 'lat_max_s': sd['lat_max']})
            for b in r['baselines']:
                srows.append({'detector': b['method'], 'seed': r['seed'], 'n_compressed': '', 'max_compress_ratio': '', 'tp': b['tp'], 'fp': b['fp'], 'fn': b['fn'], 'precision': b['precision'], 'recall': b['recall'], 'f1': b['f1'], 'tp_events': '', 'fp_events': '', 'alarm_precision': '', 'lat_p50_s': '', 'lat_p95_s': '', 'lat_p99_s': '', 'lat_max_s': ''})
        p8 = os.path.join(RES, 'e1_sensitivity_slot.csv')
        rc.write_csv(p8, srows)
        rc.write_meta(p8, exp=EXP, protocol='slot_compressed_sensitivity', seeds=[r['seed'] for r in runslot], note='legacy 71-slot protocol with time compression; sensitivity only, NOT the main table')
    print(f'[aggregate] main={len(main)} seeds, slot={len(runslot)} seeds -> {RES}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seed', type=int, default=None)
    ap.add_argument('--mode', choices=['rounds', 'slot'], default='rounds')
    ap.add_argument('--all-seeds', action='store_true')
    ap.add_argument('--aggregate', action='store_true')
    ap.add_argument('--skip-baselines', action='store_true')
    ap.add_argument('--methods', default=','.join(DST_METHODS), help='destination-side baseline subset (comma separated; default all 5)')
    args = ap.parse_args()
    os.makedirs(TMP, exist_ok=True)
    tau = load_tau()
    if args.aggregate:
        aggregate(tau)
        return
    meta = attack_meta()
    cic = cic_profile()
    seeds = SEEDS if args.all_seeds else [args.seed if args.seed is not None else 0]
    methods = () if args.skip_baselines else tuple((m for m in args.methods.split(',') if m))
    for seed in seeds:
        out = run_seed(seed, args.mode, meta, cic, tau, methods)
        p = os.path.join(TMP, f'{args.mode}_seed{seed}.json')
        json.dump(out, open(p, 'w'), indent=1)
        print(f'[seed {seed}] mode={args.mode} -> {p}', flush=True)
if __name__ == '__main__':
    main()
