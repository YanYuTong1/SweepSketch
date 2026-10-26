import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DB = os.path.join(REV, 'database')
BIN = os.path.join(os.environ.get('NETRADAR_DIR', ''), 'cpp_datacooking', 'build', 'extract_raw_feature')
OUT = os.path.join(REV, 'results', os.environ.get('SWEEPSKETCH_E3_DIR', 'e3'))
RAW = os.path.join(OUT, 'raw')
WORKERS = int(os.environ.get('SWEEPSKETCH_WORKERS', '2'))
FEATURE = 'statistic_t2_1000'

def run_one(job):
    kind, relpath, outname, empty_map, empty_list = job
    src = os.path.join(DB, relpath)
    out = os.path.join(RAW, outname)
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return (kind, outname, 0.0, -1)
    mp = os.path.join(OUT, 'http_maps', outname[:-4] + '.json')
    if os.path.exists(mp) and os.path.getsize(mp) > 2:
        d = json.load(open(mp))
        if d.get('flow_size') or d.get('url_map'):
            base = os.path.join(OUT, 'http_maps', 'tmp', outname[:-4])
            os.makedirs(os.path.dirname(base), exist_ok=True)
            with open(base + '_url.json', 'w') as f:
                json.dump(d.get('url_map', {}), f)
            with open(base + '_size.json', 'w') as f:
                json.dump(d.get('flow_size', {}), f)
            with open(base + '_pkt.json', 'w') as f:
                json.dump(d.get('flow_pkt_size', {}), f)
            url_f, size_f, pkt_f = (base + '_url.json', base + '_size.json', base + '_pkt.json')
        else:
            url_f = size_f = pkt_f = empty_map
    else:
        url_f = size_f = pkt_f = empty_map
    t0 = time.time()
    cmd = [BIN, src, url_f, size_f, pkt_f, empty_list, out, '--features', FEATURE]
    with open(os.path.join(REV, 'logs', 'e3', 'extract_' + outname + '.stderr'), 'w') as errf:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=errf)
    wall = time.time() - t0
    print('  %-60s %8.1fs exit=%d size=%s' % (outname, wall, p.returncode, os.path.getsize(out) if os.path.exists(out) else '-'), flush=True)
    return (kind, outname, round(wall, 2), p.returncode)

def main():
    os.makedirs(RAW, exist_ok=True)
    os.makedirs(os.path.join(REV, 'logs', 'e3'), exist_ok=True)
    tmp_dir = os.path.join(OUT, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)
    tmp = os.path.join(tmp_dir, 'empty_map.json')
    tmp_list = os.path.join(tmp_dir, 'empty_list.json')
    with open(tmp, 'w') as f:
        f.write('{}')
    with open(tmp_list, 'w') as f:
        f.write('[]')
    inv = json.load(open(os.path.join(OUT, 'inventory.json')))
    jobs = []
    for r in inv['file_scan']:
        outname = r['kind'] + '__' + r['file'] + '.txt'
        jobs.append((r['kind'], r['path'], outname, tmp, tmp_list))
    t0 = time.time()
    rows = []
    with ProcessPoolExecutor(max_workers=WORKERS) as ex:
        for res in ex.map(run_one, jobs):
            rows.append(res)
    wall = time.time() - t0
    with open(os.path.join(OUT, 'feature_extract_timing.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['kind', 'raw_file', 'wall_s', 'exit_code'])
        w.writerows(rows)
    meta = {'script': os.path.abspath(__file__), 'binary': BIN, 'binary_note': 'official cpp_datacooking with 3 macOS/libc++ portability patches (see the NETRADAR_DIR checkout); feature logic unchanged', 'feature': FEATURE, 'url_maps': 'empty (no HTTP payload/URL parsing): max_hit_url_* columns are 0', 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(t0)), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'wall_s': round(wall, 1), 'workers': WORKERS, 'n_files': len(rows), 'files_nonzero_exit': [r for r in rows if r[3] not in (-1, 0)], 'host': os.uname().nodename, 'python': sys.version.split()[0]}
    with open(os.path.join(OUT, 'feature_extract.meta.json'), 'w') as f:
        json.dump(meta, f, indent=1)
    print('done %d files in %.1fs' % (len(rows), wall))
if __name__ == '__main__':
    main()
