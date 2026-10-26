import json
import mmap
import os
import struct
import sys
import time
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DB = os.path.join(REV, 'database')
BEN = os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')
OUT = os.path.join(REV, 'results', 'e11')
PCAP = os.path.join(OUT, 'pcap')
SEG = (3000.0, 3600.0)
DURATIONS = [0.5, 1.0, 2.0]
SWEEPS = [16, 32]
RATES = [40, 400]
SEEDS = [0, 1, 2]
WINDOWS = 200
POOL_BASE = 198 << 24 | 18 << 16
POOL_N = 512
CAPLEN = 96
EPOCH = 4294967296 / 1000000000.0

def read_benign():
    t_first = None
    out = []
    lt = 1
    with open(BEN, 'rb') as f:
        size = os.fstat(f.fileno()).st_size
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        magic = bytes(buf[:4])
        try:
            if magic == b'\n\r\r\n':
                off = 0
                while off + 12 <= size:
                    btype, blen = struct.unpack_from('<II', buf, off)
                    if blen < 12 or off + blen > size:
                        break
                    if btype == 1:
                        lt = struct.unpack_from('<H', buf, off + 8)[0]
                    elif btype == 6:
                        cap = struct.unpack_from('<I', buf, off + 20)[0]
                        ts_hi, ts_lo = struct.unpack_from('<II', buf, off + 12)
                        ts_us = (ts_hi << 32 | ts_lo) / 1000000.0
                        if t_first is None:
                            t_first = ts_us
                        rel = ts_us - t_first - SEG[0]
                        if rel >= SEG[1] - SEG[0]:
                            break
                        if rel >= 0 and cap >= 34:
                            p = memoryview(buf)[off + 28:off + 28 + cap]
                            et = p[12] << 8 | p[13]
                            off2 = 14
                            if et == 33024:
                                et = p[16] << 8 | p[17]
                                off2 = 18
                            if et == 2048 and len(p) >= off2 + 20:
                                d = p[off2 + 16] << 24 | p[off2 + 17] << 16 | p[off2 + 18] << 8 | p[off2 + 19]
                                out.append((float(rel), int(d), bytes(p[:CAPLEN])))
                    off += blen
            elif magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'M<\xb2\xa1', b'\xa1\xb2<M'):
                endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'M<\xb2\xa1') else '>'
                lt = struct.unpack_from(endian + 'I', buf, 20)[0]
                off = 24
                while off + 16 <= size:
                    sec, usec, incl, orig = struct.unpack_from(endian + 'IIII', buf, off)
                    off += 16
                    if off + incl > size:
                        break
                    ts = sec + usec / 1000000.0
                    data = memoryview(buf)[off:off + incl]
                    if t_first is None:
                        t_first = ts
                    rel = ts - t_first - SEG[0]
                    if rel >= SEG[1] - SEG[0]:
                        break
                    if rel >= 0 and incl >= 34:
                        et = data[12] << 8 | data[13]
                        off2 = 14
                        if et == 33024:
                            et = data[16] << 8 | data[17]
                            off2 = 18
                        if et == 2048 and len(data) >= off2 + 20:
                            d = data[off2 + 16] << 24 | data[off2 + 17] << 16 | data[off2 + 18] << 8 | data[off2 + 19]
                            out.append((float(rel), int(d), bytes(data[:CAPLEN])))
                    off += incl
        finally:
            del buf
    return (lt, out)

def gen_windows(seed, dur, S, rate, benign_pfx=frozenset()):
    rng = np.random.default_rng(seed * 10007 + int(dur * 1000) * 31 + S * 7 + rate)
    per_ep = max(1, int(round(dur / 0.5)))
    episodes = WINDOWS // per_ep
    pool = [POOL_BASE + (i << 8) for i in range(POOL_N)]
    pool = [p for p in pool if p not in benign_pfx]
    rng.shuffle(pool)
    starts = []
    tries = 0
    while len(starts) < episodes and tries < episodes * 400:
        tries += 1
        s = 5.0 + rng.random() * (590.0 - dur)
        if all((abs(s - x) >= dur + 0.6 for x in starts)):
            starts.append(s)
    starts = sorted(starts)[:episodes]
    windows = []
    prev = None
    for i, t0 in enumerate(starts):
        for w in range(per_ep):
            cand = int(pool[(i * per_ep + w) % len(pool)])
            if prev is not None and cand == prev:
                cand = int(pool[(i * per_ep + w + 1) % len(pool)])
            prev = cand
            ws = t0 + w * 0.5
            npk = max(1, int(round(rate * 0.5)))
            S_eff = int(min(S, npk, 256))
            hosts = cand & ~255 | rng.choice(256, S_eff, replace=False)
            windows.append({'target': cand, 'target_str': '%d.%d.%d.0/24' % (cand >> 24 & 255, cand >> 16 & 255, cand >> 8 & 255), 'start': round(ws, 4), 'end': round(ws + 0.5, 4), 'S': int(S), 'S_eff': S_eff, 'rate': rate, 'dur': dur, 'packets': npk, 'hosts': [int(h) for h in hosts]})
    return windows

def attack_packets(windows, rng):
    out = []
    for w in windows:
        hosts = w['hosts']
        n = w['packets']
        for k in range(n):
            ts = w['start'] + (k + rng.random()) / n * 0.5
            out.append((float(ts), int(hosts[k % len(hosts)])))
    return out
ETH = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + b'\x08\x00'

def ip_udp_frame(dst, src, sport, dport, payload_len=36):
    ip_len = 20 + 8 + payload_len
    ip = bytearray(20)
    ip[0] = 69
    struct.pack_into('>H', ip, 2, ip_len)
    struct.pack_into('>H', ip, 6, 16384)
    ip[8] = 64
    ip[9] = 17
    struct.pack_into('>I', ip, 12, src)
    struct.pack_into('>I', ip, 16, dst)
    udp = struct.pack('>HHHH', sport, dport, 8 + payload_len, 0)
    return ETH + bytes(ip) + udp + b'\x00' * payload_len

def _orig_len(data):
    if len(data) >= 34:
        et = data[12] << 8 | data[13]
        o = 14
        if et == 33024 and len(data) >= 38:
            et = data[16] << 8 | data[17]
            o = 18
        if et == 2048 and len(data) >= o + 20:
            ip_len = data[o + 2] << 8 | data[o + 3]
            return o + ip_len
    return len(data)

def write_pcap(path, benign, att_pkts):
    frames = [(ts, b) for ts, d, b in benign]
    for i, (ts, d) in enumerate(att_pkts):
        src = 10 << 24 | 65536 + i & 16777215
        frames.append((ts, ip_udp_frame(d, src, 1000 + (i & 16383), 2000 + (i & 16383))))
    frames.sort(key=lambda x: x[0])
    n = 0
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 2712847316, 2, 4, 0, 0, CAPLEN, 1))
        for ts, data in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000.0))
            if usec >= 1000000:
                sec += 1
                usec -= 1000000
            f.write(struct.pack('<IIII', sec, usec, len(data), _orig_len(data)))
            f.write(data)
            n += 1
    return n

def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(PCAP, exist_ok=True)
    t0 = time.time()
    print('reading CIC benign segment %.0f-%.0f s ...' % SEG, flush=True)
    lt, benign = read_benign()
    benign_pfx = {d >> 8 << 8 for _, d, _ in benign}
    print('benign packets', len(benign), 'linktype', lt, 'prefixes', len(benign_pfx), '%.1fs' % (time.time() - t0), flush=True)
    np.savez(os.path.join(OUT, 'e11_benign_stream.npz'), dst=np.asarray([d for _, d, _ in benign], dtype=np.int64), ts=np.asarray([t for t, _, _ in benign], dtype=np.float32), lt=np.asarray([lt]))
    rows = []
    for dur in DURATIONS:
        for S in SWEEPS:
            for rate in RATES:
                for seed in SEEDS:
                    cfg = 'dur%g_S%d_r%d_s%d' % (dur, S, rate, seed)
                    windows = gen_windows(seed, dur, S, rate, benign_pfx)
                    rng = np.random.default_rng(seed * 1000003 + int(dur * 100) * 7919 + S * 104729 + rate)
                    att = attack_packets(windows, rng)
                    with open(os.path.join(OUT, 'attack_' + cfg + '.json'), 'w') as f:
                        json.dump({'cfg': cfg, 'dur': dur, 'S': S, 'rate': rate, 'seed': seed, 'windows': windows}, f)
                    n = 0
                    if seed == 0:
                        n = write_pcap(os.path.join(PCAP, cfg + '.pcap'), benign, att)
                    rows.append({'cfg': cfg, 'windows': len(windows), 'attack_packets': len(att), 'pcap_frames': n})
                    print('  %-22s windows=%d pkts=%d frames=%d' % (cfg, len(windows), len(att), n), flush=True)
    meta = {'script': os.path.abspath(__file__), 'segment_s': list(SEG), 'benign_packets': len(benign), 'benign_prefixes': len(benign_pfx), 'configs': rows, 'attrs': {'durations': DURATIONS, 'sweeps': SWEEPS, 'rates': RATES, 'seeds': SEEDS, 'windows_per_config': WINDOWS, 'target_pool': '198.18.0.0/15 (RFC2544), 512 /24, excluding benign prefixes', 'pcap_snaplen': CAPLEN, 'pcap_seed': 0, 'note': 'benign frames truncated to 96 B caplen; IP total-length fields preserved so official T2 features see identical ip_len values'}, 'wall_s': round(time.time() - t0, 1), 'host': os.uname().nodename, 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'gen_meta.json'), 'w') as f:
        json.dump(meta, f, indent=1)
    print('done in', round(time.time() - t0, 1), 's')
if __name__ == '__main__':
    main()
