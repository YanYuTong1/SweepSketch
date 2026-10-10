

import struct

GOLDEN = 0x9E3779B9


def bob_hash(key: bytes, seed: int) -> int:
    a = b = GOLDEN
    c = seed & 0xFFFFFFFF
    n = len(key)
    i = 0
    while i + 12 <= n:
        a += key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24)
        b += key[i + 4] | (key[i + 5] << 8) | (key[i + 6] << 16) | (key[i + 7] << 24)
        c += key[i + 8] | (key[i + 9] << 8) | (key[i + 10] << 16) | (key[i + 11] << 24)
        a = (a - b - c) ^ ((c >> 13) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 8) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 13) & 0xFFFFFFFF); c &= 0xFFFFFFFF
        a = (a - b - c) ^ ((c >> 12) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 16) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 5) & 0xFFFFFFFF); c &= 0xFFFFFFFF
        a = (a - b - c) ^ ((c >> 3) & 0xFFFFFFFF); a &= 0xFFFFFFFF
        b = (b - c - a) ^ ((a << 10) & 0xFFFFFFFF); b &= 0xFFFFFFFF
        c = (c - a - b) ^ ((b >> 15) & 0xFFFFFFFF); c &= 0xFFFFFFFF
        i += 12
    c = (c + n) & 0xFFFFFFFF
    t = key[i:]
    tl = len(t)
    if tl >= 11: c = (c + (t[10] << 24)) & 0xFFFFFFFF
    if tl >= 10: c = (c + (t[9] << 16)) & 0xFFFFFFFF
    if tl >= 9: c = (c + (t[8] << 8)) & 0xFFFFFFFF
    if tl >= 8: b = (b + (t[7] << 24)) & 0xFFFFFFFF
    if tl >= 7: b = (b + (t[6] << 16)) & 0xFFFFFFFF
    if tl >= 6: b = (b + (t[5] << 8)) & 0xFFFFFFFF
    if tl >= 5: b = (b + t[4]) & 0xFFFFFFFF
    if tl >= 4: a = (a + (t[3] << 24)) & 0xFFFFFFFF
    if tl >= 3: a = (a + (t[2] << 16)) & 0xFFFFFFFF
    if tl >= 2: a = (a + (t[1] << 8)) & 0xFFFFFFFF
    if tl >= 1: a = (a + t[0]) & 0xFFFFFFFF
    
    
    a = (a - b - c) ^ ((c >> 13) & 0xFFFFFFFF); a &= 0xFFFFFFFF
    b = (b - c - a) ^ ((a << 8) & 0xFFFFFFFF); b &= 0xFFFFFFFF
    c = (c - a - b) ^ ((b >> 13) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    a = (a - b - c) ^ ((c >> 12) & 0xFFFFFFFF); a &= 0xFFFFFFFF
    b = (b - c - a) ^ ((a << 16) & 0xFFFFFFFF); b &= 0xFFFFFFFF
    c = (c - a - b) ^ ((b >> 5) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    a = (a - b - c) ^ ((c >> 3) & 0xFFFFFFFF); a &= 0xFFFFFFFF
    b = (b - c - a) ^ ((a << 10) & 0xFFFFFFFF); b &= 0xFFFFFFFF
    c = (c - a - b) ^ ((b >> 15) & 0xFFFFFFFF); c &= 0xFFFFFFFF
    return c & 0xFFFFFFFF


def flow_hash64(src_ip: int, dst_ip: int) -> int:
    
    key = struct.pack("<II", src_ip & 0xFFFFFFFF, dst_ip & 0xFFFFFFFF)
    lo = bob_hash(key, 0xAB)
    hi = bob_hash(key, 0xCD)
    return (hi << 32) | lo


def flow_hash(src_ip: int, dst_ip: int, seed: int) -> int:
    
    return bob_hash(struct.pack("<II", src_ip & 0xFFFFFFFF, dst_ip & 0xFFFFFFFF), seed)


def pfx_hash(pfx: int, seed: int) -> int:
    
    return bob_hash(struct.pack("<I", pfx & 0xFFFFFFFF), seed)


if __name__ == "__main__":
    
    assert bob_hash(struct.pack("<I", 0x67F88200), 0x11) != 0  
    assert flow_hash(0x01020304, 0x0A000001, 0xAB) == flow_hash(0x01020304, 0x0A000001, 0xAB)
    assert flow_hash(1, 2, 3) != flow_hash(2, 1, 3)
    print("hash self-check ok")
