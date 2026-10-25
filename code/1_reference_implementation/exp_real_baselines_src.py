import csv
import os
import sys
import time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from baselines.step02_baselines import SOURCE_METHODS, _build
from baselines._support import eval_static
from sweepsketch import pcapio
RES = os.path.join(HERE, '..', '..', 'results')
ATT = os.path.join(HERE, '..', '..', '..', 'database', 'attack')
MULTI_DIRS = [('natural', os.path.join(ATT, 'natural_multi24')), ('synthetic_byts', os.path.join(ATT, 'synthetic_multi24_by_timestamp')), ('synthetic_shuffled', os.path.join(ATT, 'synthetic_multi24_shuffled'))]
BENIGN_FILES = [('benign', os.path.join(HERE, '..', '..', '..', 'database', 'benign', 'CIC-IDS-2017-Benign.pcap')), ('benign', os.path.join(HERE, '..', '..', '..', 'database', 'benign', 'CIC-IoT-2023-Benign.pcap'))]
TAU = {'segsketch': 0.0, 'spreadsketch': 0.0, 'couper': 0.0, 'trw': 0.0}
BENIGN_MAX = 2000000

def _stats(path, max_pkts):
    srcs = set()
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=max_pkts, with_flow=False):
        srcs.add(s)
    return srcs

def _one_file(path, kind, method, tau):
    max_pkts = BENIGN_MAX if kind == 'benign' else 10000000
    srcs = _stats(path, max_pkts)
    if not srcs:
        return None
    sk, mem, structure = _build(method, 512, None)
    for pkt_i, (s, d, ts) in enumerate(pcapio.iter_pcap(path, max_pkts=max_pkts, with_flow=False)):
        sk.insert(s, d, pkt_i)
    scores = sk.query()
    r = eval_static(scores, srcs, tau)
    r['method'] = method
    r['file'] = os.path.basename(path)
    r['kind'] = kind
    r['gt'] = len(srcs)
    return r

def run_real_baselines_src():
    files = []
    for kind, d in MULTI_DIRS:
        files += [(kind, os.path.join(d, f)) for f in sorted(os.listdir(d)) if f.endswith('.pcap')]
    files += BENIGN_FILES
    rows = []
    pass
    t_all = time.time()
    for kind, path in files:
        for method in SOURCE_METHODS:
            t0 = time.time()
            r = _one_file(path, kind, method, TAU[method])
            if r is None:
                continue
            r['wall_s'] = round(time.time() - t0, 1)
            rows.append(r)
            print('  [%s] %-12s %-45s gt=%d tp=%d fn=%d (%.0fs)' % (kind, method, r['file'][:45], r['gt'], r['tp'], r['fn'], time.time() - t0))
    os.makedirs(RES, exist_ok=True)
    cols = ['method', 'kind', 'file', 'tau', 'gt', 'tp', 'fp', 'fn', 'tn', 'precision', 'recall', 'f1', 'wall_s']
    with open(os.path.join(RES, 'EXP_real_baselines_src.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    pass
if __name__ == '__main__':
    run_real_baselines_src()
