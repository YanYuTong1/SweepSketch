import gzip

def is_csv(path):
    p = path.lower()
    return p.endswith('.csv') or p.endswith('.csv.gz')

def _open(path):
    if path.lower().endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='ignore', newline='')
    return open(path, 'rt', encoding='utf-8', errors='ignore', newline='')

def _ip2int(s):
    a, b, c, d = s.split('.')
    return int(a) << 24 | int(b) << 16 | int(c) << 8 | int(d)

def iter_csv(path, max_pkts=500000, with_flow=False):
    with _open(path) as fh:
        header = fh.readline().strip().split(',')
        col = {name.strip(): i for i, name in enumerate(header)}
        its, isrc, idst = (col['ts'], col['src'], col['dst'])
        ipro, isp, idp = (col.get('proto', -1), col.get('sport', -1), col.get('dport', -1))
        n = 0
        for line in fh:
            if not line.strip():
                continue
            f = line.rstrip('\n').split(',')
            ts = float(f[its])
            s = _ip2int(f[isrc])
            d = _ip2int(f[idst])
            if with_flow:
                yield (s, d, int(f[ipro]) if ipro >= 0 else 0, int(f[isp]) if isp >= 0 else 0, int(f[idp]) if idp >= 0 else 0, ts)
            else:
                yield (s, d, ts)
            n += 1
            if n >= max_pkts:
                break

def read_csv(path, max_pkts=500000, with_flow=False):
    return list(iter_csv(path, max_pkts, with_flow))

def read_csv_sample(path, max_pkts=500000):
    return list(iter_csv(path, max_pkts, with_flow=False))
