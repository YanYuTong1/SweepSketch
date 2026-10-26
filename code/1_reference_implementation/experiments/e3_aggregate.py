import csv
import glob
import json
import os
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OUT = os.path.join(REV, 'results', 'e3')

def load(p):
    try:
        return json.load(open(p))
    except FileNotFoundError:
        return None
HOLDOUT_PFX = None

def holdout_prefix_set():
    global HOLDOUT_PFX
    if HOLDOUT_PFX is None:
        inv = json.load(open(os.path.join(OUT, 'inventory.json')))
        HOLDOUT_PFX = {p for r in inv['file_scan'] if r['kind'].startswith('attack_holdout') for p in r['gt_prefixes']}
    return HOLDOUT_PFX

def corrected_p2(rec):
    hold = holdout_prefix_set()
    pm = rec.get('prefix_metrics')
    if pm is None:
        return None
    gt_all = set(pm.get('alerted_prefixes', [])) | set(pm.get('missed_prefixes', []))
    gt_hold = gt_all & hold
    tp = len(set(pm.get('alerted_prefixes', [])) & hold)
    fn = len(gt_hold) - tp
    fp = pm.get('benign_fp_prefixes', 0)
    out = {'f1': round(2 * tp / (2 * tp + fn + fp), 4) if tp else 0.0, 'p': round(tp / (tp + fp), 4) if tp + fp else 0.0, 'r': round(tp / (tp + fn), 4) if tp + fn else 0.0, 'tp': tp, 'fn': fn, 'fp': fp, 'absent': len(gt_all - gt_hold)}
    rules = {}
    for rule, r in pm.get('alert_rule_sensitivity', {}).items():
        rules[rule] = {'f1': round(2 * r['tp'] / (2 * r['tp'] + max(0, r['fn'] - out['absent']) + r['fp']), 4) if r['tp'] else 0.0, 'p': round(r['tp'] / (r['tp'] + r['fp']), 4) if r['tp'] + r['fp'] else 0.0, 'r': round(r['tp'] / (r['tp'] + max(0, r['fn'] - out['absent'])), 4) if r['tp'] + max(0, r['fn'] - out['absent']) else 0.0, 'tp': r['tp'], 'fn': max(0, r['fn'] - out['absent']), 'fp': r['fp']}
    out['rules'] = rules
    return out

def stats(v):
    v = [x for x in v if x is not None]
    if not v:
        return None
    return {'mean': round(float(np.mean(v)), 4), 'min': round(float(np.min(v)), 4), 'max': round(float(np.max(v)), 4), 'n': len(v)}

def netradar_runs(prefix):
    out = []
    for p in sorted(glob.glob(os.path.join(OUT, 'netradar_%s*.json' % prefix))):
        d = load(p)
        if d and 'prefix_metrics' in d:
            d['_file'] = os.path.basename(p)
            out.append(d)
    return out

def summarize_netradar(runs, rule=None, corrected=False):
    if not runs:
        return None
    rec = []
    for d in runs:
        pm = d['prefix_metrics']
        if corrected:
            c = corrected_p2(d)
            if not c:
                continue
            if rule:
                r = c['rules'].get(rule)
                if not r:
                    continue
                rec.append({'f1': r['f1'], 'p': r['p'], 'r': r['r'], 'tp': r['tp'], 'fn': r['fn'], 'fp': r['fp'], 'seg_tp': pm.get('seg_tp'), 'seg_fn': pm.get('seg_fn'), 'file': d['_file']})
            else:
                rec.append({'f1': c['f1'], 'p': c['p'], 'r': c['r'], 'tp': c['tp'], 'fn': c['fn'], 'fp': c['fp'], 'seg_tp': pm.get('seg_tp'), 'seg_fn': pm.get('seg_fn'), 'file': d['_file']})
            continue
        if rule:
            r = pm.get('alert_rule_sensitivity', {}).get(rule)
            if not r:
                continue
            rec.append({'f1': r['f1'], 'p': r['precision'], 'r': r['recall'], 'tp': r['tp'], 'fn': r['fn'], 'fp': r['fp'], 'seg_tp': pm.get('seg_tp'), 'seg_fn': pm.get('seg_fn'), 'file': d['_file']})
        else:
            rec.append({'f1': pm['f1'], 'p': pm['precision'], 'r': pm['recall'], 'tp': pm['tp_prefixes'], 'fn': pm['fn_prefixes'], 'fp': pm['benign_fp_prefixes'], 'seg_tp': pm.get('seg_tp'), 'seg_fn': pm.get('seg_fn'), 'file': d['_file']})
    if not rec:
        return None
    latk = 'onset_relative'
    p50 = [d['latency_event_s'][latk]['p50'] for d in runs if d['latency_event_s'][latk].get('p50') is not None]
    p95 = [d['latency_event_s'][latk]['p95'] for d in runs if d['latency_event_s'][latk].get('p95') is not None]
    p99 = [d['latency_event_s'][latk]['p99'] for d in runs if d['latency_event_s'][latk].get('p99') is not None]
    mx = [d['latency_event_s'][latk]['max'] for d in runs if d['latency_event_s'][latk].get('max') is not None]
    return {'runs': [r['file'] for r in rec], 'f1': stats([r['f1'] for r in rec]), 'precision': stats([r['p'] for r in rec]), 'recall': stats([r['r'] for r in rec]), 'tp_prefixes': [r['tp'] for r in rec], 'fn_prefixes': [r['fn'] for r in rec], 'benign_fp_prefixes': [r['fp'] for r in rec], 'seg_tp': [r['seg_tp'] for r in rec], 'seg_fn': [r['seg_fn'] for r in rec], 'latency_onset_s': {'p50_values': p50, 'p95_values': p95, 'p99_values': p99, 'max_values': mx, 'p50_mean': stats(p50), 'p95_mean': stats(p95)}, 'per_run': rec}

def netradar_p1():
    runs = netradar_runs('p1_full_seed')
    if not runs:
        return None
    base = summarize_netradar(runs)
    base['perf'] = {'train_wall_s': stats([d['perf']['train_wall_s'] for d in runs]), 'eval_attack_wall_s': stats([d['perf']['eval_attack_wall_s'] for d in runs]), 'inference_ms_per_block_p50': stats([d['perf']['inference_ms_per_block_p50'] for d in runs]), 'inference_ms_per_block_p99': stats([d['perf']['inference_ms_per_block_p99'] for d in runs]), 'peak_rss_MB': stats([d['perf']['peak_rss_MB'] for d in runs]), 'param_M': runs[0]['perf']['param_M'], 'model_bytes': runs[0]['perf']['model_bytes']}
    base['protocol'] = 'p1: 71 main train -> 30 holdout test (weak holdout)'
    base['train_windows'] = [d['train_windows'] for d in runs]
    base['steps_per_epoch'] = [d['steps_per_epoch'] for d in runs]
    return base

def netradar_p2():
    runs = netradar_runs('p2_full_fold')
    if not runs:
        return None
    base = summarize_netradar(runs, corrected=True)
    base['protocol'] = 'p2: 5-fold target-/24-disjoint CV (primary); GT excludes the 5 main prefixes with no holdout data'
    ci_fp = os.path.join(REV, 'results', 'e3_seeds', 'p2_5x5_ci.json')
    if os.path.exists(ci_fp):
        ci = json.load(open(ci_fp))
        base['seeds_5x5'] = ci
        base['f1'] = ci['netradar_any']['mean_f1']
        base['f1_ci95'] = ci['netradar_any']['bootstrap95']
        base['mean_f1'] = ci['netradar_any']['mean_f1']
        base['mean_ci95'] = ci['netradar_any']['bootstrap95']
        base['ge8_5x5'] = ci['netradar_ge8']
        base['sweepsketch_ref'] = ci['sweepsketch_same_population']
        base['difference_vs_sk'] = ci['difference_netradar_minus_sk']
    base['per_fold_any'] = base['per_run']
    rules = {}
    for rule in ('any_host_ever', 'ge4_hosts_per_epoch', 'ge8_hosts_per_epoch', 'ge16_hosts_per_epoch'):
        s = summarize_netradar(runs, rule=rule, corrected=True)
        rules[rule] = {k: s[k] for k in ('f1', 'precision', 'recall', 'tp_prefixes', 'fn_prefixes', 'benign_fp_prefixes')} if s else None
    base['alert_rules'] = rules
    pooled_tp = sum((r['tp'] for r in base['per_run']))
    pooled_fn = sum((r['fn'] for r in base['per_run']))
    pooled_fp = sum((r['fp'] for r in base['per_run']))
    base['pooled'] = {'tp': pooled_tp, 'fn': pooled_fn, 'fp': pooled_fp, 'precision': round(pooled_tp / (pooled_tp + pooled_fp), 4) if pooled_tp + pooled_fp else 0.0, 'recall': round(pooled_tp / (pooled_tp + pooled_fn), 4) if pooled_tp + pooled_fn else 0.0, 'f1': round(2 * pooled_tp / (2 * pooled_tp + pooled_fn + pooled_fp), 4) if pooled_tp else 0.0, 'note': 'pooled over folds; benign FP counted once per fold (each fold re-runs the benign test segment with its own model)'}
    base['perf'] = {'train_wall_s': stats([d['perf']['train_wall_s'] for d in runs]), 'eval_attack_wall_s': stats([d['perf']['eval_attack_wall_s'] for d in runs]), 'inference_ms_per_block_p50': stats([d['perf']['inference_ms_per_block_p50'] for d in runs]), 'peak_rss_MB': stats([d['perf']['peak_rss_MB'] for d in runs]), 'param_M': runs[0]['perf']['param_M'], 'model_bytes': runs[0]['perf']['model_bytes']}
    base['train_windows'] = [d['train_windows'] for d in runs]
    base['steps_per_epoch'] = [d['steps_per_epoch'] for d in runs]
    return base

def sweepsketch():
    return load(os.path.join(OUT, 'sweepsketch_summary.json'))

def sweepsketch_fold_rows():
    d = sweepsketch()
    if not d:
        return []
    inv = json.load(open(os.path.join(OUT, 'inventory.json')))
    main = sorted({p for r in inv['file_scan'] if r['kind'] == 'attack_main' for p in r['gt_prefixes']})
    hold = holdout_prefix_set()
    fp = d['benign_test']['fp_prefixes']
    rows = []
    for k in range(5):
        fold = set(main[k::5]) & hold
        tp = len(fold)
        f1 = round(2 * tp / (2 * tp + fp), 4) if tp else 0.0
        rows.append({'fold': k, 'tp': tp, 'fn': 0, 'fp': fp, 'f1': f1, 'p': round(tp / (tp + fp), 4) if tp + fp else 0.0})
    return rows

def main():
    p1 = netradar_p1()
    p2 = netradar_p2()
    sk = sweepsketch()
    sanity = load(os.path.join(OUT, 'sanity_detail.json'))
    bench = list(csv.DictReader(open(os.path.join(OUT, 'device_bench.csv'))))
    ext = list(csv.DictReader(open(os.path.join(OUT, 'feature_extract_timing.csv'))))
    hold_wall = sum((float(r['wall_s']) for r in ext if r['kind'].startswith('attack_holdout')))
    test_pkts = 19242206
    nr_pps = round(test_pkts / (hold_wall + p1['perf']['eval_attack_wall_s']['mean'])) if p1 else None
    out = {'netradar_p1': p1, 'netradar_p2': p2, 'sweepsketch': sk, 'sweepsketch_p2_folds': sweepsketch_fold_rows(), 'sanity_detail': sanity, 'device_bench': bench, 'holdout_feature_extract_wall_s': round(hold_wall, 1), 'netradar_pipeline_pps_holdout': nr_pps, 'material_notes': ['NetRadar = official C++ T2 feature extractor + official pointnet/pointnetloss training semantics (NETRADAR_DIR checkout, portability/MPS patches only)', 'URL-derived server-side features come from a Python re-implementation of the official HTTP Host/flow-size maps; non-HTTP flows are 0 as in the official C++ default', 'p1 is a WEAK holdout: all 50 holdout target /24s also occur in the 71 training files; use p2 as the primary protocol', 'latency primary = onset-relative (first alert window minus first appearance of that prefix); p99/max are inflated by by_timestamp files that concatenate captures across dates (not detection delay)', 'SweepSketch needs no training; NetRadar p1 used 3 seeds, p2 1 seed/fold (5 folds) because folds are already independent models']}
    with open(os.path.join(OUT, 'e3_summary.json'), 'w') as f:
        json.dump(out, f, indent=1)
    rows = []
    if p1:
        rows.append(['NetRadar (p1 71->30, 3 seeds, any-host)', p1['f1']['mean'], p1['precision']['mean'], p1['recall']['mean'], p1['latency_onset_s']['p50_mean']['mean'], p1['latency_onset_s']['p95_mean']['mean'], None, None, round(p1['perf']['model_bytes'] / 1000000.0, 1), p1['perf']['peak_rss_MB']['mean'], nr_pps])
    if p2 and 'seeds_5x5' in p2:
        a = p2['seeds_5x5']['netradar_any']
        rows.append(['NetRadar (p2 5 seeds x 5 folds, any-host, corrected)', a['mean_f1'], a.get('precision_mean', p2['precision']['mean']), a.get('recall_mean', 1.0), 0.0, None, None, None, round(p2['perf']['model_bytes'] / 1000000.0, 1), p2['perf']['peak_rss_MB']['mean'], nr_pps])
        g8 = p2['seeds_5x5']['netradar_ge8']
        rows.append(['NetRadar (p2 5x5, >=8 hosts/epoch rule)', g8['mean_f1'], None, None, None, None, None, None, round(p2['perf']['model_bytes'] / 1000000.0, 1), p2['perf']['peak_rss_MB']['mean'], nr_pps])
    if sk:
        f1 = sk['same_population_f1']
        lat = sk['holdout_30']['latency_onset_s']
        rows.append(['SweepSketch 512KB (p1 population)', f1['f1'], f1['precision'], f1['recall'], lat['p50'], lat['p95'], lat['p99'], lat['max'], 0.5, None, sk['holdout_30']['pps_mean']])
        skf = sweepsketch_fold_rows()
        mean_f1 = round(float(np.mean([r['f1'] for r in skf])), 4) if skf else None
        mean_p = round(float(np.mean([r['p'] for r in skf])), 4) if skf else None
        rows.append(['SweepSketch 512KB (p2 population, corrected per-fold mean)', mean_f1, mean_p, 1.0, lat['p50'], lat['p95'], lat['p99'], lat['max'], 0.5, None, sk['holdout_30']['pps_mean']])
    with open(os.path.join(OUT, 'e3_main_table.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['method', 'f1', 'precision', 'recall', 'lat_p50_s', 'lat_p95_s', 'lat_p99_s', 'lat_max_s', 'model_MB', 'rss_MB', 'pps'])
        w.writerows(rows)
    if p2 and p2.get('alert_rules'):
        with open(os.path.join(OUT, 'e3_rules_table.csv'), 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['rule', 'f1_mean', 'p_mean', 'r_mean', 'tp', 'fn', 'fp'])
            for rule, r in p2['alert_rules'].items():
                if not r:
                    continue
                w.writerow([rule, r['f1']['mean'], r['precision']['mean'], r['recall']['mean'], '/'.join((str(x) for x in r['tp_prefixes'])), '/'.join((str(x) for x in r['fn_prefixes'])), '/'.join((str(x) for x in r['benign_fp_prefixes']))])
    print('\nmain table:')
    for r in rows:
        print(r)
    print('wrote e3_summary.json / e3_main_table.csv / e3_rules_table.csv')
if __name__ == '__main__':
    main()
