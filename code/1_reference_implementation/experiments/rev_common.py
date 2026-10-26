from __future__ import annotations
import csv
import json
import os
import platform
import random
import statistics
import sys
import time
from datetime import datetime
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.normpath(os.path.join(HERE, '..', '..', '..'))
IMPL = os.path.join(REV, 'code', '1_reference_implementation')
DB = os.path.normpath(os.environ.get('SWEEPSKETCH_DB', os.path.join(REV, 'database')))
RESULTS = os.path.join(REV, 'results')
FIGURES = os.path.join(REV, 'figures')
LOGS = os.path.join(REV, 'logs')
ATTACK_DIR = os.path.join(DB, 'attack', 'normal_single24')
HOLDOUT_DIRS = {'natural': os.path.join(DB, 'attack', 'natural_multi24'), 'byts': os.path.join(DB, 'attack', 'synthetic_multi24_by_timestamp'), 'shuffled': os.path.join(DB, 'attack', 'synthetic_multi24_shuffled')}
BENIGN_DIR = os.path.join(DB, 'benign')
BENIGN_FILES = ['CIC-IDS-2017-Benign.pcap', 'CIC-IoT-2023-Benign.pcap', 'CIC-IoT-2023-Benign1.pcap', 'CIC-IoT-2023-Benign2.pcap', 'CIC-IoT-2023-Benign3.pcap', '202607051400.pcap']
TRACE_EXTS = ('.csv', '.csv.gz', '.pcap', '.pcapng')
SEEDS = [0, 1, 2, 3, 4]

def ensure(exp_id: str):
    for base in (os.path.join(RESULTS, exp_id), os.path.join(LOGS, exp_id)):
        os.makedirs(base, exist_ok=True)
    return os.path.join(RESULTS, exp_id)

def attack_files():
    return sorted((f for f in os.listdir(ATTACK_DIR) if f.lower().endswith(TRACE_EXTS)))

def holdout_files(kind=None):
    out = []
    for k, d in HOLDOUT_DIRS.items():
        if kind and k != kind:
            continue
        for f in sorted(os.listdir(d)):
            if f.lower().endswith(TRACE_EXTS):
                out.append((k, os.path.join(d, f)))
    return out

def rel(path: str) -> str:
    try:
        return os.path.relpath(path, REV)
    except ValueError:
        return path

def file_stat(path: str) -> dict:
    st = os.stat(path)
    return {'path': rel(path), 'bytes': st.st_size, 'mtime': int(st.st_mtime)}

def write_csv(path: str, rows, fieldnames=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not rows:
        open(path, 'w').write('')
        return
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)

def write_meta(csv_path: str, **meta):
    base = os.path.splitext(csv_path)[0]
    payload = {'created': datetime.now().astimezone().isoformat(), 'argv': sys.argv, 'host': {'platform': platform.platform(), 'python': sys.version.split()[0], 'machine': platform.machine()}, 'cwd': os.getcwd()}
    payload.update(meta)
    with open(base + '.meta.json', 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)

class Timer:

    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self.t0 = time.time()
        return self

    def __exit__(self, *exc):
        self.dt = time.time() - self.t0
        print(f'[time] {self.name}: {self.dt:.1f}s', flush=True)

def wilson(k: int, n: int, z: float=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * (p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5 / d
    return (max(0.0, c - h), min(1.0, c + h))

def f1(tp: int, fp: int, fn: int) -> float:
    return 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0

def prf(tp: int, fp: int, fn: int) -> dict:
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': prec, 'recall': rec, 'f1': f1(tp, fp, fn)}

def bootstrap_ci(values, stat=statistics.mean, n_boot=1000, seed=0, alpha=0.05):
    rng = random.Random(seed)
    n = len(values)
    if n == 0:
        return (float('nan'), float('nan'), float('nan'))
    point = stat(values)
    boots = []
    for _ in range(n_boot):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        boots.append(stat(sample))
    boots.sort()
    lo = boots[int(alpha / 2 * n_boot)]
    hi = boots[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return (point, lo, hi)

def pr_curve(scores: dict, pos: set, thresholds):
    rows = []
    all_ent = set(scores)
    for t in thresholds:
        tp = sum((1 for p in pos if scores.get(p, 0.0) > t))
        fp = sum((1 for p in all_ent if p not in pos and scores.get(p, 0.0) > t))
        fn = len(pos) - tp
        tn = len(all_ent) - len(pos) - fp
        rows.append({'tau': t, 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'precision': tp / (tp + fp) if tp + fp else 0.0, 'recall': tp / (tp + fn) if tp + fn else 0.0, 'f1': f1(tp, fp, fn), 'tpr': tp / (tp + fn) if tp + fn else 0.0, 'fpr': fp / (fp + tn) if fp + tn else 0.0})
    return rows

def add_impl_path():
    if IMPL not in sys.path:
        sys.path.insert(0, IMPL)

def packet_count(path: str) -> int:
    import struct
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic in (b'\n\r\r\n', b'M<\xb2\xa1'):
            f.seek(0)
            n = 0
            while True:
                h = f.read(8)
                if len(h) < 8:
                    break
                bt, tlen = struct.unpack_from('<II', h, 0)
                if tlen < 12:
                    break
                if bt == 6:
                    n += 1
                f.seek(tlen - 8, 1)
            return n
        if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
            f.seek(20, 1)
            n = 0
            while True:
                h = f.read(16)
                if len(h) < 16:
                    break
                _, _, cl, _ = struct.unpack_from(endian + 'IIII', h, 0)
                f.seek(cl, 1)
                n += 1
            return n
    return 0

def seed_all(s: int):
    random.seed(s)

def eprint(*a, **k):
    print(*a, file=sys.stderr, flush=True, **k)
