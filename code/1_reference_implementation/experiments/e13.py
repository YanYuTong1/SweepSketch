import csv
import json
import os
import sys
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e11_deadline as D
OUT = os.path.join(REV, 'results', 'e13')
E11 = os.path.join(REV, 'results', 'e11')
E12B = os.path.join(REV, 'results', 'e12b')
DELTAS = [0.1, 0.25, 0.5, 1.0, 2.0, 4.294967296, 10.0]
TARGETS = [0.1, 1.0, 5.0]

def pct(vals, q):
    return round(float(np.percentile(vals, q)), 3) if len(vals) else None

def main():
    os.makedirs(OUT, exist_ok=True)
    D.load_models()
    cache = D.FeatureCache()
    ben_dst, ben_ts = D.load_benign()
    NPFX = len({int(d) >> 8 << 8 for d in ben_dst})
    sk_ben = D.sk_track(ben_dst, ben_ts)
    ent_ben = D.entropy_scores(ben_dst, ben_ts)
    ben_n = {}
    for d, t in zip(ben_dst, ben_ts):
        e = int(t // D.EPOCH)
        ben_n.setdefault(e, set()).add(int(d) >> 8 << 8)
    ben_n = {e: len(v) for e, v in ben_n.items()}
    nr_ben, _ = D.nr_scores('dur0.5_S16_r40_s0', cache, need_ben=True)
    sk_vals = np.asarray(list(sk_ben.values()))
    ent_vals = np.asarray([v for k, v in ent_ben.items() if k[1] != 'z'])
    nr_vals = {tag: np.asarray(list(nr_ben[tag].values())) for tag in D.MODELS}
    print('benign scores ready', flush=True)
    cfgs = []
    for dur in D.G.DURATIONS:
        for S in D.G.SWEEPS:
            for rate in D.G.RATES:
                for seed in D.G.SEEDS:
                    cfgs.append('dur%g_S%d_r%d_s%d' % (dur, S, rate, seed))
    events = {}
    tau_nr = {tag: {b: D.choose_tau(nr_vals[tag], b * NPFX * D.T_SEC / 86400.0) for b in TARGETS} for tag in D.MODELS}
    for cfg in cfgs:
        meta = json.load(open(os.path.join(D.OUT, 'attack_' + cfg + '.json')))
        att = D.attack_stream(meta)
        dst_a = np.asarray([d for _, d in att], dtype=np.int64)
        ts_a = np.asarray([t for t, _ in att], dtype=np.float64)
        tgt = {w['target'] for w in meta['windows']}
        dst_m = np.concatenate([ben_dst, dst_a])
        ts_m = np.concatenate([ben_ts, ts_a])
        order = np.argsort(ts_m, kind='stable')
        tr = D.sk_track(dst_m[order], ts_m[order], only_keys=tgt, traj=True)
        ent = D.entropy_scores(dst_a, ts_a, extra_n_pfx=ben_n)
        nr = None
        if meta['seed'] == 0:
            _, nr = D.nr_scores(cfg, cache, need_ben=False)
        for budget in TARGETS:
            allowed = budget * NPFX * D.T_SEC / 86400.0
            tau_sk = D.choose_tau(sk_vals, allowed)
            tau_ent = D.choose_tau(ent_vals, allowed)
            keys = [('sweepsketch', budget)] + [('entropy', budget)] + [('netradar_' + t, budget) for t in D.MODELS]
            for k in keys:
                events.setdefault(k, [])
            for w in meta['windows']:
                a_sk = None
                for (e, p), traj in tr.items():
                    if p != w['target']:
                        continue
                    for c, ts in traj:
                        if c > tau_sk and (a_sk is None or ts < a_sk):
                            a_sk = ts
                a_ent = None
                e0 = int(w['start'] // D.EPOCH)
                e1 = int((w['end'] - 1e-09) // D.EPOCH)
                for e in (e0, e1):
                    if ent.get((e, w['target']), 0) > tau_ent:
                        a_ent = (e + 1) * D.EPOCH
                        break
                events['sweepsketch', budget].append((a_sk, w))
                events['entropy', budget].append((a_ent, w))
                if nr is not None:
                    for tag in D.MODELS:
                        scores = nr[tag]
                        hits = [t for (t, p), s in scores.items() if p == w['target'] and w['start'] - 0.5 <= t <= w['end'] + 1.0 and (s > tau_nr[tag][budget])]
                        a_nr = min(hits) if hits else None
                        events['netradar_' + tag, budget].append((a_nr, w))
        print('  cfg', cfg, flush=True)
    rows = []
    for (method, budget), evs in events.items():
        for delta in DELTAS:
            rec = []
            dmg = []
            lat = []
            for alarm_abs, w in evs:
                if alarm_abs is not None:
                    arel = alarm_abs - w['start']
                    if arel <= delta:
                        rec.append(1)
                        dv, _ = D.damage(w, alarm_abs)
                        dmg.append(dv)
                        lat.append(max(0.0, arel))
                        continue
                rec.append(0)
                t_abs = w['start'] + min(delta, 0.5)
                dv, _ = D.damage(w, t_abs)
                dmg.append(dv)
            rows.append({'dataset': 'e11_synth', 'method': method, 'fpr_per_pfx_day': budget, 'delta_s': round(delta, 3), 'recall': round(float(np.mean(rec)), 4), 'damage': round(float(np.mean(dmg)), 4), 'latency_p50': pct(lat, 50), 'n': len(evs)})
    e12b_files = ['sk_v1_onset.csv', 'sk_v2_onset.csv', 'entropy_onset.csv', 'netradar_onset.csv']
    if not all((os.path.exists(os.path.join(E12B, f)) for f in e12b_files)):
        print('[E13] real-71 inputs absent under results/e12b; writing the synthetic curve only', flush=True)
    else:

        def load(p):
            with open(p) as f:
                return list(csv.DictReader(f))
        sk1 = load(os.path.join(E12B, 'sk_v1_onset.csv'))
        sk2 = load(os.path.join(E12B, 'sk_v2_onset.csv'))
        ent = load(os.path.join(E12B, 'entropy_onset.csv'))
        nr = load(os.path.join(E12B, 'netradar_onset.csv'))

        def real_rows(name, alarms, spans, fpr=''):
            out = []
            for delta in [0.5, 1.0, 2.0]:
                rec, dmg, lat = ([], [], [])
                for a, span in zip(alarms, spans):
                    if a is not None and a <= delta:
                        rec.append(1)
                        dmg.append(min(1.0, a / span))
                        lat.append(a)
                    else:
                        rec.append(0)
                        dmg.append(min(1.0, delta / span))
                out.append({'dataset': 'e12_real71', 'method': name, 'fpr_per_pfx_day': fpr, 'delta_s': delta, 'recall': round(float(np.mean(rec)), 4), 'damage': round(float(np.mean(dmg)), 4), 'latency_p50': pct(lat, 50), 'n': len(rec)})
            return out
        spans = [float(r['span_s']) for r in sk1]
        al1 = [None if r['first_alert_s'] in ('', 'None') else float(r['first_alert_s']) for r in sk1]
        al2 = [None if r['first_episode_s'] in ('', 'None') else float(r['first_episode_s']) for r in sk2]
        rows += real_rows('sk_v1', al1, spans)
        rows += real_rows('sk_v2', al2, spans)
        for lab, tau_key in (('entropy_E1tau', 'E1_tau4.37'), ('entropy_op0.1', 'op0.1')):
            al = [4.294967296 if int(r['would_alarm_at_4.29_' + tau_key]) else None for r in ent]
            rows += real_rows(lab, al, spans, fpr=lab)
        al_nr = [None if r['first_flag_t'] in ('', 'None') else float(r['first_flag_t']) for r in nr]
        rows += real_rows('netradar_window_time', al_nr, spans)
        al_nr_d = [a + 1.0 if a is not None else None for a in al_nr]
        rows += real_rows('netradar_with_1s_dwell', al_nr_d, spans)
    with open(os.path.join(OUT, 'e13_deadline_curve.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    summary = {}
    for r in rows:
        if r['dataset'] == 'e11_synth' and r['fpr_per_pfx_day'] != 0.1:
            continue
        key = r['dataset'] + '|' + r['method']
        summary.setdefault(key, []).append(r)
    with open(os.path.join(OUT, 'e13_summary.json'), 'w') as f:
        json.dump(summary, f, indent=1)
    print(json.dumps({k: [(x['delta_s'], x['recall'], x['damage']) for x in v] for k, v in summary.items()}, indent=1))
    print('wall done')
if __name__ == '__main__':
    main()
