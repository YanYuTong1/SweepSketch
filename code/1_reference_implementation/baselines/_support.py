
import csv
import os


GOLDEN = 0x9E3779B9


def bob_hash(key: bytes, seed: int) -> int:
    a = b = GOLDEN
    c = seed & 0xFFFFFFFF
    n = len(key)
    i = 0
    while i + 12 <= n:
        a += key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24)
        b += key[i + 4] | (key[i + 5] << 8) | (key[i + 6] << 16) | (key[i + 7] << 24)
        c += key[i + 8] | (key[i + 9] << 8) | (key[i + 10] << 16) | (key[i + 11] << 24)
        a = (a - b - c) ^ ((c >> 13) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 8) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 13) & 0xFFFFFFFF); c &= 0xFFFFFFFF
        a = (a - b - c) ^ ((c >> 12) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 16) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 5) & 0xFFFFFFFF); c &= 0xFFFFFFFF
        a = (a - b - c) ^ ((c >> 3) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 10) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 15) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    while i + 4 <= n:
        a += key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24)
        i += 4
        a = (a - b - c) ^ ((c >> 16) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 12) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 14) & 0xFFFFFFFF); c &= 0xFFFFFFFF
        a = (a - b - c) ^ ((c >> 18) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 18) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 15) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    a += n
    b += n
    c += n
    while i < n:
        a += key[i]
        i += 1
    a = (a - b - c) ^ ((c >> 13) & 0xFFFFFFFF); a &= 0xFFFFFFFF
    b = (b - c - a) ^ ((a << 8) & 0xFFFFFFFF); b &= 0xFFFFFFFF
    c = (c - a - b) ^ ((b >> 13) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    a = (a - b - c) ^ ((c >> 12) & 0xFFFFFFFF); a &= 0xFFFFFFFF
    b = (b - c - a) ^ ((a << 16) & 0xFFFFFFFF); b &= 0xFFFFFFFF
    c = (c - a - b) ^ ((b >> 5) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    a = (a - b - c) ^ ((c >> 3) & 0xFFFFFFFF); a &= 0xFFFFFFFF
    b = (b - c - a) ^ ((a << 10) & 0xFFFFFFFF); b &= 0xFFFFFFFF
    c = (c - a - b) ^ ((b >> 15) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    return c



def pfx_str(pfx: int, plen: int = 24) -> str:
    return f"{(pfx >> 24) & 0xFF}.{(pfx >> 16) & 0xFF}.{(pfx >> 8) & 0xFF}.{pfx & 0xFF}/{plen}"


def pfx_mask(plen: int) -> int:
    return (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF



def eval_static(scores, attack_pfxs, tau):
    
    tp = sum(1 for p in attack_pfxs if scores.get(p, 0.0) > tau)
    fn = sum(1 for p in attack_pfxs if scores.get(p, 0.0) <= tau)
    fp = sum(1 for p, s in scores.items() if s > tau and p not in attack_pfxs)
    tn = sum(1 for p, s in scores.items() if s <= tau and p not in attack_pfxs)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tau": tau, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1}



def parallel_map(fn, tasks, jobs=None, desc="tasks", unit="file"):
    from multiprocessing import Pool, cpu_count
    from tqdm import tqdm
    nj = max(1, min(jobs or max(cpu_count() - 2, 1), len(tasks)))
    print(f"  [{nj} workers] {desc}")
    with Pool(nj) as p:
        return list(tqdm(p.imap_unordered(fn, tasks), total=len(tasks),
                         desc=desc, unit=unit))


def save_csv(path, rows, fieldnames):
    if not rows:
        print(f"  [skip] {path} (0 rows)")
        return path
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  [out] {path} ({len(rows)} rows)")



def _stub(name):
    def f(*a, **k):
        raise NotImplementedError(
            "baselines._support." + name + " is a stub in this release "
            "(not needed by the REAL-series experiments)")
    return f


read_pcap = _stub("read_pcap")
stitch_flows = _stub("stitch_flows")
attack_file_meta = _stub("attack_file_meta")
base_argparser = _stub("base_argparser")
