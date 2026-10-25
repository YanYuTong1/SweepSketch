import os
import struct
from . import csvio

def _parse_ipv4(pkt: bytes, raw: bool=False):
    if raw:
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            return None
        off = 0
    else:
        if len(pkt) < 34:
            return None
        etype = pkt[12] << 8 | pkt[13]
        off = 14
        if etype == 33024:
            if len(pkt) < 22:
                return None
            etype = pkt[16] << 8 | pkt[17]
            off = 18
        elif etype == 34984:
            if len(pkt) < 26:
                return None
            etype = pkt[20] << 8 | pkt[21]
            off = 22
        if etype != 2048 or len(pkt) < off + 20:
            return None
    src = pkt[off + 12] << 24 | pkt[off + 13] << 16 | pkt[off + 14] << 8 | pkt[off + 15]
    dst = pkt[off + 16] << 24 | pkt[off + 17] << 16 | pkt[off + 18] << 8 | pkt[off + 19]
    proto = pkt[off + 9]
    sport = dport = 0
    t = off + (pkt[off] & 15) * 4
    if proto in (6, 17) and len(pkt) >= t + 4:
        sport = pkt[t] << 8 | pkt[t + 1]
        dport = pkt[t + 2] << 8 | pkt[t + 3]
    return (src, dst, proto, sport, dport)

def iter_pcap_legacy(path: str, max_pkts: int=500000, with_flow: bool=False):
    with open(path, 'rb') as f:
        magic = f.read(4)
        if len(magic) < 4:
            return
        little = magic in (b'\xd4\xc3\xb2\xa1', b'M<\xb2\xa1')
        big = magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2<M')
        if not (little or big):
            return
        endian = '<' if little else '>'
        gh = f.read(20)
        if len(gh) < 20:
            return
        linktype = struct.unpack_from(endian + 'I', gh, 16)[0]
        raw = linktype == 101
        min_len = 20 if raw else 34
        for _ in range(max_pkts):
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, cap_len = struct.unpack_from(endian + 'III', hdr, 0)
            pkt = f.read(cap_len)
            if len(pkt) < min_len:
                continue
            r = _parse_ipv4(pkt, raw)
            if r:
                if with_flow:
                    yield (r[0], r[1], r[2], r[3], r[4], ts_sec + ts_usec / 1000000.0)
                else:
                    yield (r[0], r[1], ts_sec + ts_usec / 1000000.0)

def read_pcap_legacy(path: str, max_pkts: int=500000, with_flow: bool=False):
    return list(iter_pcap_legacy(path, max_pkts, with_flow))

def iter_pcapng(path: str, max_pkts: int=500000, with_flow: bool=False):
    with open(path, 'rb') as f:
        magic = f.read(4)
        if len(magic) < 4 or struct.unpack_from('<I', magic, 0)[0] not in (168627466, 218762506):
            return
        f.seek(0)
        n = 0
        while n < max_pkts:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            bt, tlen = struct.unpack_from('<II', hdr, 0)
            if tlen < 12 or tlen > 2 ** 24:
                break
            if bt in (168627466, 1):
                skip = tlen - 8
                if skip > 0:
                    f.seek(skip, 1)
                continue
            if bt == 6:
                body = f.read(tlen - 12)
                if len(body) < 24:
                    break
                ts_high, ts_low = struct.unpack_from('<II', body, 4)
                ts = (ts_high << 32 | ts_low) / 1000000.0
                cap_len = struct.unpack_from('<I', body, 12)[0]
                if cap_len < 34 or cap_len > 10000:
                    f.read(4)
                    continue
                pkt = body[20:20 + cap_len]
                r = _parse_ipv4(pkt)
                if r:
                    n += 1
                    if with_flow:
                        yield (r[0], r[1], r[2], r[3], r[4], ts)
                    else:
                        yield (r[0], r[1], ts)
                f.read(4)
            else:
                break

def read_pcapng(path: str, max_pkts: int=500000, with_flow: bool=False):
    return list(iter_pcapng(path, max_pkts, with_flow))

def read_pcap(path: str, max_pkts: int=500000, with_flow: bool=False):
    if csvio.is_csv(path):
        flows = csvio.read_csv(path, max_pkts, with_flow)
        flows.sort(key=lambda x: x[-1])
        return flows
    flows = read_pcap_legacy(path, max_pkts, with_flow)
    if not flows:
        flows = read_pcapng(path, max_pkts, with_flow)
    flows.sort(key=lambda x: x[-1])
    return flows

def iter_pcap(path: str, max_pkts: int=500000, with_flow: bool=True):
    if csvio.is_csv(path):
        yield from csvio.iter_csv(path, max_pkts, with_flow)
        return
    it = iter_pcap_legacy(path, max_pkts, with_flow)
    first = next(it, None)
    if first is not None:
        yield first
        yield from it
        return
    yield from iter_pcapng(path, max_pkts, with_flow)

def read_pcap_sample(path: str, max_pkts: int=500000):
    if csvio.is_csv(path):
        return csvio.read_csv_sample(path, max_pkts)
    flows = []
    with open(path, 'rb') as f:
        magic = f.read(4)
        if len(magic) < 4:
            return flows
        m = struct.unpack_from('<I', magic, 0)[0]
        if m in (168627466, 218762506):
            return read_pcapng(path, max_pkts)
        endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'M<\xb2\xa1') else '>'
        gh = f.read(20)
        if len(gh) < 20:
            return flows
        linktype = struct.unpack_from(endian + 'I', gh, 16)[0]
        raw = linktype == 101
        min_len = 20 if raw else 34
        for _ in range(max_pkts):
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, cap_len = struct.unpack_from(endian + 'III', hdr, 0)
            pkt = f.read(cap_len)
            if len(pkt) < min_len:
                continue
            r = _parse_ipv4(pkt, raw)
            if r:
                flows.append((r[0], r[1], ts_sec + ts_usec / 1000000.0))
    flows.sort(key=lambda x: x[2])
    return flows
if __name__ == '__main__':
    db = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'database')
    legacy = os.path.join(db, 'attack', 'normal_single24', '103.135.248.0_ACK-Carpet-Bombing_20240530.pcap')
    pcapng = os.path.join(db, 'benign', 'CIC-IDS-2017-Benign.pcap')
    for p, n in ((legacy, 50000), (pcapng, 50000)):
        if not os.path.exists(p):
            continue
        fl = read_pcap(p, n)
        assert fl, p
        print(f'{os.path.basename(p)}: {len(fl)} flows, first={fl[0]}, last={fl[-1]}')
    import tempfile
    ip4 = bytes([69, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])
    gh = struct.pack('<IHHIIII', 2712847316, 2, 4, 0, 0, 65535, 101)
    rec = struct.pack('<IIII', 100, 0, len(ip4), len(ip4)) + ip4
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
        tf.write(gh + rec)
        tmp = tf.name
    fl = read_pcap(tmp, 10)
    os.unlink(tmp)
    assert fl == [(16909060, 84281096, 100.0)], fl
    print('RAW(101) self-check ok', fl[0])
