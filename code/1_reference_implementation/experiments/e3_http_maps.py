import csv
import json
import mmap
import os
import struct
import sys
import time
from concurrent.futures import ProcessPoolExecutor
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DB = os.path.join(REV, 'database')
OUT = os.path.join(REV, 'results', 'e3')
MAPS = os.path.join(OUT, 'http_maps')
WORKERS = int(os.environ.get('SWEEPSKETCH_WORKERS', '2'))
HOST_MARK = b'Host: '
METHODS = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'PATCH ', b'CONNECT ')

def _u32(b, o, endian):
    return struct.unpack_from(endian + 'I', b, o)[0]

def _u16(b, o, endian):
    return struct.unpack_from(endian + 'H', b, o)[0]

def iter_packets(path):
    with open(path, 'rb') as f:
        size = os.fstat(f.fileno()).st_size
        if size < 4:
            return
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        magic = bytes(buf[:4])
        try:
            if magic in (b'\xd4\xc3\xb2\xa1', b'M<\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\xa1\xb2<M'):
                endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'M<\xb2\xa1') else '>'
                link = _u32(buf, 20, endian)
                off = 24
                while off + 16 <= size:
                    incl = _u32(buf, off + 8, endian)
                    orig = _u32(buf, off + 12, endian)
                    off += 16
                    if off + incl > size:
                        break
                    yield (link, orig, memoryview(buf)[off:off + incl])
                    off += incl
            elif magic == b'\n\r\r\n':
                off = 0
                link = 1
                while off + 12 <= size:
                    btype = _u32(buf, off, '<')
                    blen = _u32(buf, off + 4, '<')
                    if blen < 12 or off + blen > size:
                        break
                    if btype == 1:
                        link = _u16(buf, off + 8, '<')
                    elif btype == 6:
                        cap = _u32(buf, off + 20, '<')
                        orig = _u32(buf, off + 24, '<')
                        data_off = off + 28
                        yield (link, orig, memoryview(buf)[data_off:data_off + cap])
                    elif btype == 3:
                        orig = _u32(buf, off + 8, '<')
                        data_off = off + 12
                        yield (link, orig, memoryview(buf)[data_off:data_off + orig])
                    off += blen
        finally:
            del buf

def parse_one(job):
    kind, relpath, outname = job
    src = os.path.join(DB, relpath)
    out = os.path.join(MAPS, outname + '.json')
    if os.path.exists(out):
        return (outname, 0.0, 0, 0)
    t0 = time.time()
    url_map, fsize, fpkt = ({}, {}, {})
    http_keys = set()
    n_tcp = n_http = 0
    for link, wire, pkt in iter_packets(src):
        off = 0
        if link == 1:
            if len(pkt) < 34:
                continue
            et = pkt[12] << 8 | pkt[13]
            if et == 33024:
                off = 18
                if len(pkt) < 38:
                    continue
                et = pkt[16] << 8 | pkt[17]
            if et != 2048:
                continue
            off = off or 14
        elif link in (101, 12, 228):
            off = 0
        else:
            continue
        if len(pkt) < off + 20 or pkt[off] >> 4 != 4:
            continue
        ihl = (pkt[off] & 15) * 4
        if pkt[off + 9] != 6:
            continue
        tot = pkt[off + 2] << 8 | pkt[off + 3]
        t = off + ihl
        if len(pkt) < t + 20:
            continue
        n_tcp += 1
        sip = '%d.%d.%d.%d' % (pkt[off + 12], pkt[off + 13], pkt[off + 14], pkt[off + 15])
        dip = '%d.%d.%d.%d' % (pkt[off + 16], pkt[off + 17], pkt[off + 18], pkt[off + 19])
        sp = pkt[t] << 8 | pkt[t + 1]
        dp = pkt[t + 2] << 8 | pkt[t + 3]
        key = '%s_%s_%d_%d' % (sip, dip, sp, dp)
        fsize[key] = fsize.get(key, 0) + wire
        fpkt[key] = fpkt.get(key, 0) + 1
        doff = (pkt[t + 12] >> 4) * 4
        pstart = t + doff
        if len(pkt) > pstart + 8:
            pay = bytes(pkt[pstart:pstart + 512])
            if pay[:4] in METHODS:
                k = pay.find(HOST_MARK)
                if k >= 0:
                    e = pay.find(b'\r\n', k + 6)
                    if e > k + 6:
                        host = pay[k + 6:e].decode('latin-1', 'ignore')
                        url_map[key] = host
                        url_map['%s_%s_%d_%d' % (dip, sip, dp, sp)] = host
                        http_keys.add(key)
                        n_http += 1
    os.makedirs(MAPS, exist_ok=True)
    fsize_h = {k: v for k, v in fsize.items() if k in http_keys}
    fpkt_h = {k: v for k, v in fpkt.items() if k in http_keys}
    with open(out, 'w') as f:
        json.dump({'url_map': url_map, 'flow_size': fsize_h, 'flow_pkt_size': fpkt_h}, f)
    wall = time.time() - t0
    print('  %-58s tcp=%8d http=%7d maps=%7d %6.1fs' % (outname[:58], n_tcp, n_http, len(fsize), wall), flush=True)
    return (outname, round(wall, 2), n_tcp, n_http)

def main():
    inv = json.load(open(os.path.join(OUT, 'inventory.json')))
    os.makedirs(MAPS, exist_ok=True)
    jobs = []
    for r in inv['file_scan']:
        jobs.append((r['kind'], r['path'], r['kind'] + '__' + r['file']))
    t0 = time.time()
    rows = []
    with ProcessPoolExecutor(max_workers=WORKERS) as ex:
        for res in ex.map(parse_one, jobs):
            rows.append(res)
    with open(os.path.join(OUT, 'http_maps_timing.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['map_name', 'wall_s', 'tcp_pkts', 'http_requests'])
        w.writerows(rows)
    meta = {'script': os.path.abspath(__file__), 'official_reference': 'python_datacooking/extract_http_features_from_pcap.py + cpp_datacooking/src/extract_http_features_from_pcap.cpp', 'semantics': 'url = HTTP Host header value; flow_size = sum of pcap wire lengths per 5-tuple; flow_pkt_size = packet count per 5-tuple; only HTTP-request flows get a url entry (official default 0)', 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(t0)), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'wall_s': round(time.time() - t0, 1), 'workers': WORKERS, 'n_files': len(rows), 'files_with_http': sum((1 for r in rows if r[3] > 0)), 'host': os.uname().nodename}
    with open(os.path.join(OUT, 'http_maps.meta.json'), 'w') as f:
        json.dump(meta, f, indent=1)
    print('done', len(rows), 'files in', round(time.time() - t0, 1), 's')
if __name__ == '__main__':
    main()
