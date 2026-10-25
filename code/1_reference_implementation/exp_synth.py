import csv
import os
from sweepsketch.bucket import Bucket
from sweepsketch.llr import make_llr_table
from sweepsketch.pcapio import iter_pcap
from common import WORKERS, ATT_DIR, BENIGN, DUMMY, RES, STAGGER, attack_files, config, config_defaults, f1_of, feed, flush, h_flag, ip24, make_sketch

def run_adv(theta0):
    tbl = make_llr_table(theta0)
    rows = []
    for S in (4, 6, 8, 10, 12, 14, 16, 32):
        for lam in (8, 16, 32, 64, 128, 256, 512, 1024):
            for order in ('scan', 'burst', 'split7030'):
                b = Bucket(167772416)
                detected = None
                for e in range(40):
                    att = 20 <= e < 30
                    pkts = []
                    if att:
                        per = max(1, lam // S)
                        for i in range(lam):
                            if order == 'scan':
                                pkts.append(167772417 + i % S)
                            elif order == 'burst':
                                pkts.append(167772417 + i // per % S)
                            else:
                                pkts.append(167772417 + i % max(1, S * 7 // 10) if i % 10 < 7 else 167772673 + i % max(1, S * 3 // 10))
                    else:
                        pkts = [167772671] * 20
                    for d in pkts:
                        r = d * 2654435761 % 32
                        rho = d * 40503 % 8
                        a1, a2, _ = b.process(r, rho, e, tbl)
                        if att and detected is None and (a1 or a2):
                            detected = e
                rows.append((S, lam, order, 0 if detected is None else 1, None if detected is None else detected - 20))
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, 'EXP8_adversarial.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['S', 'lam', 'order', 'detected', 'delay_epochs'])
        w.writerows(rows)
    det = sum((r[3] for r in rows))
    pass

def _abl_one(theta0, name, overrides):
    for k, v in overrides.items():
        setattr(config, k, v)
    try:
        sk = make_sketch(overrides.get('THETA0', theta0), 512)
        stats, cur = ({}, {})
        gt_attack = {ip24(f.split('_')[0]) for f in attack_files()}
        gt_benign = set()
        for s, d, ts in iter_pcap(BENIGN, config.BENIGN_MAX, with_flow=False):
            gt_benign.add(d >> 8 << 8)
            feed(sk, stats, cur, s, d, ts, DUMMY)
        flush(stats, cur)
        cursor = 4000000000.0
        for f in attack_files():
            path = os.path.join(ATT_DIR, f)
            first = None
            for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
                if first is None:
                    first = ts
                last = ts
            for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
                feed(sk, stats, cur, s, d, ts - first + cursor, DUMMY)
            cursor += last - first + STAGGER
        flush(stats, cur)
        fl = h_flag(9.2)
        flagged = {k[1]: True for k, s in stats.items() if k[0] == 1 and fl(s)}
        tp, fp, fn, f1v = f1_of(flagged, gt_attack, gt_benign)
        return (name, tp, fp, fn, round(f1v, 4))
    finally:
        for k in overrides:
            setattr(config, k, config_defaults[k])

def run_abl(theta0):
    from multiprocessing import Pool
    variants = [('base', {}), ('m16', {'HLL_M': 16}), ('m64', {'HLL_M': 64}), ('l1only', {'USE_L2': False}), ('d1only', {'USE_D2': False}), ('d2only', {'USE_D1': False}), ('nogate', {'USE_GATE': False}), ('theta_005', {'THETA0': 0.005}), ('theta_05', {'THETA0': 0.05}), ('h6', {'H_BITS': 6, 'H_FP': 48}), ('h12', {'H_BITS': 12, 'H_FP': 96}), ('k12', {'K_ALARM': 12}), ('kf4', {'K_FLOOD': 4}), ('kf8', {'K_FLOOD': 8}), ('m2', {'D2_MULT': 2}), ('m4', {'D2_MULT': 4}), ('pmin100', {'P_MIN': 100}), ('pmin400', {'P_MIN': 400})]
    with Pool(min(WORKERS, len(variants))) as p:
        rows = p.starmap(_abl_one, [(theta0, n, o) for n, o in variants])
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, 'EXP6_ablation.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['variant', 'tp', 'fp', 'fn', 'f1'])
        w.writerows(rows)
    for r in rows:
        print('exp6 %-10s tp=%d fp=%d fn=%d F1=%s' % r)

def run_mech(theta0):
    tbl = make_llr_table(theta0)
    rows = []

    def cdn_timeline(tbl, gate):
        cdn = Bucket(3325231104)
        atk = Bucket(2130706688)
        cdn_epochs = set()
        atk_tp = 0
        for e in range(16):
            for i in range(1024):
                a1, a2, _ = cdn.process(i % 32 if i < 32 else i * 7 % 32, 1, e, tbl)
                if a1 or a2:
                    cdn_epochs.add(e)
            if e in (3, 4):
                for i in range(256):
                    a1, a2, _ = atk.process(i % 32, 1, e, tbl)
                    if a1 or a2:
                        atk_tp = 1
        return (sorted(cdn_epochs), atk_tp)
    for gate in (True, False):
        config.USE_GATE = gate
        cdn_ep, atk_tp = cdn_timeline(tbl, gate)
        rows.append(('gate_%s' % ('on' if gate else 'off'), ','.join(map(str, cdn_ep)), atk_tp))
        pass
    config.USE_GATE = True

    def staggered(tbl, l2):
        from sweepsketch.digest import Collector
        from sweepsketch.sketch import SweepSketch
        config.USE_L2 = l2
        sk = SweepSketch(config.THETA0)
        c = Collector()
        for e in range(2):
            ts = e * 4.3
            for p24 in range(4):
                for dst in range(8):
                    sk.process(0, 3232235520 + (p24 << 8) + dst, ts, c)
                    ts += 0.0001
        l1 = len({a.key for a in c.alerts if a.level == 1})
        l2n = len({a.key for a in c.alerts if a.level == 2})
        config.USE_L2 = True
        return (l1, l2n)
    for l2 in (True, False):
        l1, l2n = staggered(tbl, l2)
        rows.append(('two_level_%s' % ('on' if l2 else 'off'), l1, l2n))
        pass

    def channels(tbl, d1, d2):
        res = {}
        for name, S, per in (('scan', 32, 1), ('flood', 8, 30)):
            b = Bucket(167772416)
            det = 0
            for e in range(2):
                pkts = []
                for i in range(S * per):
                    if per == 1:
                        pkts.append(i % S)
                    else:
                        pkts.append(i // per % S)
                for d in pkts:
                    a1, a2, _ = b.process(d % 32, d % 8, e, tbl)
                    if a1 or a2:
                        det = 1
            res[name] = det
        return res
    for d1, d2 in ((True, True), (True, False), (False, True)):
        config.USE_D1, config.USE_D2 = (d1, d2)
        r = channels(tbl, d1, d2)
        rows.append(('ch_d1%s_d2%s' % (int(d1), int(d2)), r['scan'], r['flood']))
        pass
    config.USE_D1, config.USE_D2 = (True, True)
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, 'EXP7_mechanisms.csv'), 'w', newline='') as fh:
        csv.writer(fh).writerows([('variant', 'a', 'b')] + rows)
