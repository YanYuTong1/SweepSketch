import argparse
import struct
EPOCH_NS = 1 << 32
BASE = 174325760

def ipv4(src, dst, payload=0):
    total = 20 + payload
    hdr = struct.pack('>BBHHHBBHII', 69, 0, total, 0, 0, 64, 17, 0, src, dst)
    return hdr + b'\x00' * payload

def eth(src, dst):
    return b'\x00\x11"3DU' + b'fw\x88\x99\xaa\xbb' + b'\x08\x00'

def gen(out_pcap, out_bin, seed=1):
    pkts = []
    s = seed

    def rnd():
        nonlocal s
        s = s * 6364136223846793005 + 1442695040888963407 & (1 << 64) - 1
        return s
    for w in range(8):
        t0 = (w + 1) * EPOCH_NS + 10000000
        for b in range(30):
            pfx = 184549376 | b << 8
            for i in range(20):
                ts = t0 + i * 2000 * 1000
                pkts.append((ts, pfx | 1 + i % 254, 16909060))
        pfx = BASE | 256
        for i in range(16):
            for _ in range(2):
                ts = t0 + (1000 + i * 37) * 1000
                pkts.append((ts, pfx | 1 + i, 16909060))
        pfx = BASE | 512
        for i in range(300):
            ts = t0 + (2000 + i * 3) * 1000
            pkts.append((ts, pfx | 1 + i % 8, 16909060))
        p16 = 207880192 + (w << 16)
        for i in range(32):
            ts = t0 + (3000 + i * 41) * 1000
            pkts.append((ts, p16 | 256 | 1 + i, 16909060))
    pkts.sort(key=lambda x: x[0])
    with open(out_pcap, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 2712847316, 2, 4, 0, 0, 65535, 1))
        for ts, dst, src in pkts:
            sec = ts // 1000000000
            usec = ts % 1000000000 // 1000
            frame = eth(0, 0) + ipv4(src, dst, 8)
            f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)))
            f.write(frame)
    if out_bin:
        with open(out_bin, 'wb') as f:
            for ts, dst, src in pkts:
                f.write(struct.pack('<QII', ts, dst, src))
    print('[gen] %s: %d packets (%s)' % (out_pcap, len(pkts), out_bin or '-'))
if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcap', required=True)
    ap.add_argument('--bin', default='')
    ap.add_argument('--seed', type=int, default=1)
    a = ap.parse_args()
    gen(a.pcap, a.bin, a.seed)
