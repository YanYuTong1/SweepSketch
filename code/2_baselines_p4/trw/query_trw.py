import os
import sys
try:
    p4 = bfrt.trw.pipe.Ingress
except NameError:
    pass
    pass
    sys.exit(1)
ETA1_Q = 1280
Q_SCALE = 256.0

def _env_int(name, default):
    v = os.environ.get(name)
    return int(v) if v else default
SLOT_START = _env_int('TRW_SLOT_START', 0)
SLOT_END = _env_int('TRW_SLOT_END', 65535)
BM_START = _env_int('TRW_BM_START', 0)
BM_END = _env_int('TRW_BM_END', 65535)
SCAN_BM = os.environ.get('TRW_SCAN_BM', '1') != '0'

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

def reg_dump(name, start, end):
    tbl = getattr(p4, name)
    out = {}
    for i in range(start, end + 1):
        try:
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out[i] = _extract_value(r)
        except Exception:
            out[i] = 0
    return out

def ip_str(v):
    return '%d.%d.%d.%d' % (v >> 24 & 255, v >> 16 & 255, v >> 8 & 255, v & 255)
print('=' * 72)
pass
print('=' * 72)
pass
srcs = reg_dump('trw_src', SLOT_START, SLOT_END)
lams = reg_dump('trw_lam', SLOT_START, SLOT_END)
pass
print()
print('-' * 72)
pass
print('-' * 72)
n_nonzero = 0
n_alarm = 0
alarm_list = []
for i in range(SLOT_START, SLOT_END + 1):
    key = srcs.get(i, 0) & 4294967295
    lam_q = lams.get(i, 0) & 65535
    if key == 0 and lam_q == 0:
        continue
    n_nonzero += 1
    lam_f = lam_q / Q_SCALE
    verdict = '[ >= 1]' if lam_q >= ETA1_Q else ''
    print('%6d  %-15s  %8d  %12.4f  %s' % (i, ip_str(key), lam_q, lam_f, verdict))
    if lam_q >= ETA1_Q:
        n_alarm += 1
        alarm_list.append((key, lam_q, lam_f))
print('-' * 72)
pass
if alarm_list:
    print()
    pass
    for key, lam_q, lam_f in alarm_list:
        pass
if SCAN_BM:
    print()
    pass
    bm = reg_dump('pair_bm', BM_START, BM_END)
    nz_words = 0
    set_bits = 0
    for i in range(BM_START, BM_END + 1):
        w = bm.get(i, 0) & 4294967295
        if w != 0:
            nz_words += 1
        set_bits += bin(w).count('1')
    n_words = BM_END - BM_START + 1
    pass
print()
pass
