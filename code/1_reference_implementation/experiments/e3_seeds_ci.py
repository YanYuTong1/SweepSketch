import csv
import glob
import json
import os
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
E3 = os.path.join(REV, 'results', 'e3')
OUT = os.path.join(REV, 'results', 'e3_seeds')

def holdout_pfx():
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    return {p for r in inv['file_scan'] if r['kind'].startswith('attack_holdout') for p in r['gt_prefixes']}

def main_pfx():
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    return sorted({p for r in inv['file_scan'] if r['kind'] == 'attack_main' for p in r['gt_prefixes']})

def corrected(pm, hold, fold):
    gt_all = set(pm.get('alerted_prefixes', [])) | set(pm.get('missed_prefixes', []))
    gt = gt_all & hold
    tp = len(set(pm.get('alerted_prefixes', [])) & hold)
    fn = len(gt) - tp
    fp = pm.get('benign_fp_prefixes', 0)
    f1 = round(2 * tp / (2 * tp + fn + fp), 4) if tp + fn + fp else 0.0
    p = round(tp / (tp + fp), 4) if tp + fp else 0.0
    r = round(tp / (tp + fn), 4) if tp + fn else 0.0
    return {'fold': fold, 'gt': len(gt), 'tp': tp, 'fn': fn, 'fp': fp, 'f1_any': f1, 'p_any': p, 'r_any': r, 'absent': len(gt_all - gt)}

def main():
    hold = holdout_pfx()
    runs = []
    for f in sorted(glob.glob(os.path.join(OUT, 'netradar_p2_s*_f*.json'))):
        d = json.load(open(f))
        if d.get('protocol') != 'p2':
            continue
        r = corrected(d['prefix_metrics'], hold, d['fold'])
        r['seed'] = d['seed']
        rules = d['prefix_metrics'].get('alert_rule_sensitivity', {})
        r8 = rules.get('ge8_hosts_per_epoch')
        if r8:
            fn8 = max(0, r8['fn'] - r['absent'])
            r['f1_ge8'] = round(2 * r8['tp'] / (2 * r8['tp'] + fn8 + r8['fp']), 4) if r8['tp'] + fn8 + r8['fp'] else 0.0
            r['p_ge8'] = round(r8['tp'] / (r8['tp'] + r8['fp']), 4) if r8['tp'] + r8['fp'] else 0.0
            r['r_ge8'] = 1.0 if fn8 == 0 else round(r8['tp'] / (r8['tp'] + fn8), 4)
            r['fp_ge8'] = r8['fp']
        runs.append(r)
    if not runs:
        print('no runs yet')
        return
    seeds = sorted({r['seed'] for r in runs})
    folds = sorted({r['fold'] for r in runs})
    with open(os.path.join(OUT, 'p2_5x5_runs.csv'), 'w', newline='') as f:
        cols = list(runs[0].keys())
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(runs)
    per_fold = []
    for fold in folds:
        sel = [r for r in runs if r['fold'] == fold]
        per_fold.append({'fold': fold, 'n_seeds': len(sel), 'p_mean': round(float(np.mean([r['p_any'] for r in sel])), 4), 'r_mean': round(float(np.mean([r['r_any'] for r in sel])), 4), 'f1_mean': round(float(np.mean([r['f1_any'] for r in sel])), 4), 'f1_std': round(float(np.std([r['f1_any'] for r in sel])), 4), 'f1_ge8_mean': round(float(np.mean([r.get('f1_ge8', 0) for r in sel])), 4), 'fp_mean': round(float(np.mean([r['fp'] for r in sel])), 2)})
    with open(os.path.join(OUT, 'p2_5x5_per_fold.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(per_fold[0].keys()))
        w.writeheader()
        w.writerows(per_fold)
    rng = np.random.default_rng(0)
    f1 = np.asarray([[next((r['f1_any'] for r in runs if r['fold'] == fo and r['seed'] == sd), np.nan) for sd in seeds] for fo in folds])
    f1_8 = np.asarray([[next((r.get('f1_ge8', np.nan) for r in runs if r['fold'] == fo and r['seed'] == sd), np.nan) for sd in seeds] for fo in folds])
    B = 2000
    boot, boot8 = ([], [])
    for _ in range(B):
        fo = rng.integers(0, len(folds), len(folds))
        sd = rng.integers(0, len(seeds), len(seeds))
        sub = f1[np.ix_(fo, sd)]
        boot.append(float(np.nanmean(sub)))
        sub8 = f1_8[np.ix_(fo, sd)]
        boot8.append(float(np.nanmean(sub8)))

    def ci(v):
        return [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]
    mean = round(float(np.nanmean(f1)), 4)
    mean8 = round(float(np.nanmean(f1_8)), 4)
    sk_mean = 0.952
    out = {'runs': len(runs), 'seeds': seeds, 'folds': folds, 'corrected_population': '50 holdout-covered prefixes (5 absent main prefixes excluded)', 'netradar_any': {'mean_f1': mean, 'bootstrap95': ci(boot), 'min_fold_effect': round(float(np.min(np.nanmean(f1, axis=1))), 4), 'max_fold_effect': round(float(np.max(np.nanmean(f1, axis=1))), 4)}, 'netradar_ge8': {'mean_f1': mean8, 'bootstrap95': ci(boot8)}, 'sweepsketch_same_population': {'mean_f1': sk_mean, 'per_fold_f1': [0.9474, 0.9474, 0.9524, 0.9565, 0.9565]}, 'difference_netradar_minus_sk': {'mean': round(mean - sk_mean, 4), 'bootstrap95': [round(float(np.percentile([b - sk_mean for b in boot], 2.5)), 4), round(float(np.percentile([b - sk_mean for b in boot], 97.5)), 4)]}, 'per_fold': per_fold, 'note': 'bootstrap resamples folds and seeds with replacement (2-level, B=2000); SK has no training seed variance (its per-fold F1 only reflects the 50-prefix population and its 1 benign FP)'}
    with open(os.path.join(OUT, 'p2_5x5_ci.json'), 'w') as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))
if __name__ == '__main__':
    main()
