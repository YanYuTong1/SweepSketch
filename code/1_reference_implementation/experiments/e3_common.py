import json
import os
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OUT = os.path.join(REV, 'results', os.environ.get('SWEEPSKETCH_E3_DIR', 'e3'))

def ip_int(s):
    a, b, c, d = s.split('.')
    return int(a) << 24 | int(b) << 16 | int(c) << 8 | int(d)

def pfx_of(host):
    return host >> 8 << 8

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def cook_and_normalize(raw14):
    cnt, by, sq, mn, mx, tot_ipt, sq_ipt, mn_ipt, mx_ipt, alive, apkt, asize, urlc, urls = raw14
    avg = by / cnt
    var = sq / cnt - avg * avg
    if var < 0.0:
        var = 0.0
    aipt = tot_ipt / cnt
    vipt = sq_ipt / cnt - aipt * aipt
    if vipt < 0.0:
        vipt = 0.0
    apkt_avg = apkt / alive if alive else 0.0
    asize_avg = asize / alive if alive else 0.0
    cooked = [cnt, by, avg, var, mn, mx, aipt, vipt, mn_ipt, mx_ipt, alive, apkt_avg, asize_avg, urlc, urls]
    norm = [cooked[0] / 1000.0, cooked[1] / 1500000.0, cooked[2] / 1500.0, cooked[3] / 400000.0, cooked[4] / 1500.0, cooked[5] / 1500.0, cooked[10] / 50.0, cooked[11] / 100.0, cooked[12] / 400000.0, cooked[13] / 10.0, cooked[14] / 10000.0]
    return (cooked, norm)

def load_raw_file(path):
    win_t, win_hosts, win_X = ([], [], [])
    totals = {}
    with open(path) as f:
        for line in f:
            if line.startswith('{"name":"statistic_t2_1000"'):
                d = json.loads(line)
                feats = d['feature']
                if not feats:
                    continue
                times = d['time']
                hosts = []
                xs = []
                acc = 0.0
                for hs, raw in feats.items():
                    ti = times[hs]
                    acc += ti['sec'] + ti['usec'] / 1000000.0
                    _, norm = cook_and_normalize(raw)
                    hosts.append(ip_int(hs))
                    xs.append(norm)
                win_t.append(acc / len(hosts))
                win_hosts.append(hosts)
                win_X.append(np.asarray(xs, dtype=np.float32))
            elif line.startswith('{"name":"total_pkt_num"'):
                d = json.loads(line)
                for hs, c in d['feature'].items():
                    totals[ip_int(hs)] = c
    return (win_t, win_hosts, win_X, totals)

def build_cache(cache_path=None):
    inv = json.load(open(os.path.join(OUT, 'inventory.json')))
    files = []
    win_t = []
    win_off = [0]
    win_file = []
    row_host = []
    row_pfx = []
    row_lab = []
    row_X = []
    file_rows = []
    for fi, r in enumerate(inv['file_scan']):
        kind = r['kind']
        raw_path = os.path.join(OUT, 'raw', kind + '__' + r['file'] + '.txt')
        if not os.path.exists(raw_path):
            continue
        gt = {ip_int(p.split('/')[0]) for p in r['gt_prefixes']}
        tw, th, tx, totals = load_raw_file(raw_path)
        files.append({'kind': kind, 'file': r['file'], 'path': r['path'], 'packets': r['packets'], 'span_s': r['span_s'], 'gt_prefixes': r['gt_prefixes'], 'gt_n': r['gt_n'], 'n_windows': len(tw), 'n_rows': sum((len(h) for h in th)), 'extractor_packets': int(sum(totals.values()))})
        file_start = len(win_t)
        for t, hosts, x in zip(tw, th, tx):
            win_t.append(t)
            win_file.append(fi)
            hs = np.asarray(hosts, dtype=np.int64)
            pf = hs >> 8 << 8
            lab = np.zeros(len(hs), dtype=np.uint8)
            if not kind.startswith('benign'):
                for gt_pfx in gt:
                    lab[pf == gt_pfx] = 1
            row_host.append(hs)
            row_pfx.append(pf.astype(np.int32))
            row_lab.append(lab)
            row_X.append(x)
            win_off.append(win_off[-1] + len(hs))
        file_rows.append((file_start, len(win_t)))
        print('  %-60s windows=%d rows=%d' % (r['file'][:60], len(tw), sum((len(h) for h in th))), flush=True)
    cache = {'win_t': np.asarray(win_t, dtype=np.float32), 'win_off': np.asarray(win_off, dtype=np.int64), 'win_file': np.asarray(win_file, dtype=np.int16), 'row_host': np.concatenate(row_host) if row_host else np.zeros(0, np.int64), 'row_pfx': np.concatenate(row_pfx) if row_pfx else np.zeros(0, np.int32), 'row_lab': np.concatenate(row_lab) if row_lab else np.zeros(0, np.uint8), 'row_X': np.concatenate(row_X) if row_X else np.zeros((0, 11), np.float32), 'files': np.asarray(json.dumps(files)), 'file_rows': np.asarray(json.dumps(file_rows))}
    if cache_path is None:
        cache_path = os.path.join(OUT, 'feature_cache.npz')
    np.savez_compressed(cache_path, **cache)
    print('cache:', cache_path, 'windows', len(win_t), 'rows', win_off[-1], 'size_MB', round(os.path.getsize(cache_path) / 1000000.0, 1))
    return cache_path

class FeatureCache:

    def __init__(self, path=None):
        path = path or os.path.join(OUT, 'feature_cache.npz')
        z = np.load(path, allow_pickle=False)
        self.win_t = z['win_t']
        self.win_off = z['win_off']
        self.win_file = z['win_file']
        self.row_host = z['row_host']
        self.row_pfx = z['row_pfx']
        self.row_lab = z['row_lab']
        self.row_X = z['row_X']
        self.files = json.loads(str(z['files']))
        self.file_rows = json.loads(str(z['file_rows']))

    def n_windows(self):
        return len(self.win_t)

    def window_rows(self, w):
        return (self.win_off[w], self.win_off[w + 1])

    def file_windows(self, fi):
        a, b = self.file_rows[fi]
        return np.arange(a, b)

    def window_file(self, w):
        return int(self.win_file[w])

def main():
    os.makedirs(OUT, exist_ok=True)
    import sys
    build_cache(sys.argv[1] if len(sys.argv) > 1 else None)
if __name__ == '__main__':
    main()
