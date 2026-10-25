import struct
GOLDEN = 2654435769

def bob_hash(key: bytes, seed: int) -> int:
    a = b = GOLDEN
    c = seed & 4294967295
    n = len(key)
    i = 0
    while i + 12 <= n:
        a += key[i] | key[i + 1] << 8 | key[i + 2] << 16 | key[i + 3] << 24
        b += key[i + 4] | key[i + 5] << 8 | key[i + 6] << 16 | key[i + 7] << 24
        c += key[i + 8] | key[i + 9] << 8 | key[i + 10] << 16 | key[i + 11] << 24
        a = a - b - c ^ c >> 13 & 4294967295
        a &= 4294967295
        b = b - c - a ^ a << 8 & 4294967295
        b &= 4294967295
        c = c - a - b ^ b >> 13 & 4294967295
        c &= 4294967295
        a = a - b - c ^ c >> 12 & 4294967295
        a &= 4294967295
        b = b - c - a ^ a << 16 & 4294967295
        b &= 4294967295
        c = c - a - b ^ b >> 5 & 4294967295
        c &= 4294967295
        a = a - b - c ^ c >> 3 & 4294967295
        a &= 4294967295
        b = b - c - a ^ a << 10 & 4294967295
        b &= 4294967295
        c = c - a - b ^ b >> 15 & 4294967295
        c &= 4294967295
        i += 12
    c = c + n & 4294967295
    t = key[i:]
    tl = len(t)
    if tl >= 11:
        c = c + (t[10] << 24) & 4294967295
    if tl >= 10:
        c = c + (t[9] << 16) & 4294967295
    if tl >= 9:
        c = c + (t[8] << 8) & 4294967295
    if tl >= 8:
        b = b + (t[7] << 24) & 4294967295
    if tl >= 7:
        b = b + (t[6] << 16) & 4294967295
    if tl >= 6:
        b = b + (t[5] << 8) & 4294967295
    if tl >= 5:
        b = b + t[4] & 4294967295
    if tl >= 4:
        a = a + (t[3] << 24) & 4294967295
    if tl >= 3:
        a = a + (t[2] << 16) & 4294967295
    if tl >= 2:
        a = a + (t[1] << 8) & 4294967295
    if tl >= 1:
        a = a + t[0] & 4294967295
    a = a - b - c ^ c >> 13 & 4294967295
    a &= 4294967295
    b = b - c - a ^ a << 8 & 4294967295
    b &= 4294967295
    c = c - a - b ^ b >> 13 & 4294967295
    c &= 4294967295
    a = a - b - c ^ c >> 12 & 4294967295
    a &= 4294967295
    b = b - c - a ^ a << 16 & 4294967295
    b &= 4294967295
    c = c - a - b ^ b >> 5 & 4294967295
    c &= 4294967295
    a = a - b - c ^ c >> 3 & 4294967295
    a &= 4294967295
    b = b - c - a ^ a << 10 & 4294967295
    b &= 4294967295
    c = c - a - b ^ b >> 15 & 4294967295
    c &= 4294967295
    return c & 4294967295

def flow_hash64(src_ip: int, dst_ip: int) -> int:
    key = struct.pack('<II', src_ip & 4294967295, dst_ip & 4294967295)
    lo = bob_hash(key, 171)
    hi = bob_hash(key, 205)
    return hi << 32 | lo

def flow_hash(src_ip: int, dst_ip: int, seed: int) -> int:
    return bob_hash(struct.pack('<II', src_ip & 4294967295, dst_ip & 4294967295), seed)

def pfx_hash(pfx: int, seed: int) -> int:
    return bob_hash(struct.pack('<I', pfx & 4294967295), seed)
if __name__ == '__main__':
    assert bob_hash(struct.pack('<I', 1744339456), 17) != 0
    assert flow_hash(16909060, 167772161, 171) == flow_hash(16909060, 167772161, 171)
    assert flow_hash(1, 2, 3) != flow_hash(2, 1, 3)
    print('hash self-check ok')
