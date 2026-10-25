import struct
import sys
import zlib
NB = 4096
CELLS = 7
LIGHT_N = 1 << 18
SALT_BUCKET = 37120
SALT_LIGHT = 37376

def _crc_candidates(key32, salt16):
    s_le, s_be = (struct.pack('<H', salt16), struct.pack('>H', salt16))
    k_le, k_be = (struct.pack('<I', key32), struct.pack('>I', key32))
    return {'le_le': zlib.crc32(s_le + k_le) & 4294967295, 'be_be': zlib.crc32(s_be + k_be) & 4294967295, 'le_be': zlib.crc32(s_le + k_be) & 4294967295, 'be_le': zlib.crc32(s_be + k_le) & 4294967295}

def _extract_value(resp):
    try:
        d = resp.data
    except AttributeError:
        d = resp if isinstance(resp, dict) else {}
    best = 0
    for k, v in d.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, int):
                    best = max(best, int(item) & 4294967295)
        elif isinstance(v, int):
            best = max(best, int(v) & 4294967295)
    return best

def _find_ingress():
    for name in ('elastic_rs', 'elastic'):
        try:
            return getattr(bfrt, name).pipe.Ingress
        except (NameError, AttributeError):
            continue
    return None

def _get_reg(tbl, idx):
    try:
        return _extract_value(tbl.get(REGISTER_INDEX=idx, from_hw=True, print_ents=False))
    except Exception:
        return 0

def parse_args(argv):
    d = {'bucket_range': (0, NB), 'guard_range': (0, 0), 'n_packets': 0, 'threshold': None, 'calibrate': False, 'light_crc': 'le_le', 'topk': 0}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--bucket-range':
            lo, hi = argv[i + 1].split(':')
            d['bucket_range'] = (int(lo), int(hi))
            i += 2
        elif a == '--guard-range':
            lo, hi = argv[i + 1].split(':')
            d['guard_range'] = (int(lo), int(hi))
            i += 2
        elif a == '--n-packets':
            d['n_packets'] = int(argv[i + 1])
            i += 2
        elif a == '--threshold':
            d['threshold'] = float(argv[i + 1])
            i += 2
        elif a == '--calibrate':
            d['calibrate'] = True
            i += 1
        elif a == '--light-crc':
            d['light_crc'] = argv[i + 1]
            i += 2
        elif a == '--topk':
            d['topk'] = int(argv[i + 1])
            i += 2
        else:
            i += 1
    if d['threshold'] is None:
        d['threshold'] = 0.005 * d['n_packets'] if d['n_packets'] else 0.0
    return d

def main():
    p4 = _find_ingress()
    if p4 is None:
        pass
        pass
        sys.exit(1)
    args = parse_args(sys.argv[1:])
    b_lo, b_hi = args['bucket_range']
    g_lo, g_hi = args['guard_range']
    crc_name = args['light_crc']
    cell_tbls = [getattr(p4, 'cellc_%d' % i) for i in range(CELLS)]
    print('=' * 72)
    pass
    print('=' * 72)
    found = {}
    calib = {k: 0 for k in ('le_le', 'be_be', 'le_be', 'be_le')}
    n_cells = 0
    for b in range(b_lo, b_hi):
        for i in range(CELLS):
            v = _get_reg(cell_tbls[i], b)
            if v == 0:
                continue
            n_cells += 1
            key32 = v >> 8 << 8
            if key32 not in found:
                found[key32] = {'val': v & 255, 'flag': v >> 7 & 1, 'bucket': b}
    pass
    crc_hits = dict(calib)
    for key32, info in found.items():
        for name, crc in _crc_candidates(key32, SALT_BUCKET).items():
            if crc % NB == info['bucket']:
                crc_hits[name] += 1
    pass
    for name in ('le_le', 'be_be', 'le_be', 'be_le'):
        pass
    best = max(crc_hits, key=crc_hits.get)
    if len(found) > 0 and crc_hits[best] == 0:
        pass
    if args['calibrate']:
        crc_name = best
        pass
    else:
        pass
    light_tbl = getattr(p4, 'light')
    scores = []
    for key32, info in found.items():
        cnt = info['val'] & 127
        score = cnt
        if info['flag']:
            pos = _crc_candidates(key32, SALT_LIGHT)[crc_name] % LIGHT_N
            score += _get_reg(light_tbl, pos)
        scores.append((key32, score, cnt, info['flag'], info['bucket']))
    theta = args['threshold']
    ip = lambda k: '%d.%d.%d.%d' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255, k & 255)
    heavy = [(k, s, c, f, b) for k, s, c, f, b in scores if s >= theta]
    heavy.sort(key=lambda x: -x[1])
    if args['topk']:
        heavy = heavy[:args['topk']]
    print('\n' + '=' * 72)
    pass
    print('=' * 72)
    print(f"{'key':>18} {'bucket':>6} {'heavy':>6} {'light+':>7} {'score':>6}")
    print('-' * 72)
    for k, s, c, f, b in heavy:
        print(f"{ip(k):>18} {b:>6} {c:>6} {('yes' if f else 'no '):>7} {s:>6}")
    if not heavy:
        pass
    if g_hi > g_lo:
        pass
        guard_tbl = getattr(p4, 'guard')
        nz = 0
        for b in range(g_lo, g_hi):
            g = _get_reg(guard_tbl, b)
            if g:
                print(f' bucket {b}: guard = {g}')
                nz += 1
        if not nz:
            pass
    pass
if __name__ == '__main__':
    main()
