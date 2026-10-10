

import sys

try:
    p4 = bfrt.SegSketch.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    sys.exit(1)

print("=" * 72)
print(" SegSketch deployment diagnosis")
print("=" * 72)




print("\n[1/4] forward_ipv4 table contents:")
try:
    p4.forward_ipv4.dump(from_hw=False)
except Exception as e:
    print(f"  ⚠ dump failed: {e}")


for ip in (392, 400):
    found = False
    for kn in ("ig_intr_md.ingress_port", "ingress_port", "$MATCH_PRIORITY"):
        try:
            r = p4.forward_ipv4.get(**{kn: ip}, from_hw=False, print_ents=False)
            print(f"  ✓ ingress {ip} hits (key name = {kn})")
            try:
                d = r.data
                for k, v in d.items():
                    print(f"      {k} = {v}")
            except Exception:
                pass
            found = True
            break
        except Exception:
            continue
    if not found:
        print(f"  ✗ ingress {ip} entry not found")




print("\n[2/4] mask table entry count:")
for tname, expect in [("tbl_mask1", 2), ("tbl_mask2", 4),
                      ("tbl_mask3", 8), ("tbl_hmask", 32)]:
    try:
        
        cnt = 0
        try:
            cnt = p4.__getattr__(tname).usage_get()["usage"]
        except Exception:
            try:
                cnt = p4.__getattr__(tname).get_usage()
            except Exception:
                cnt = -1
        marker = "✓" if cnt == expect else "✗"
        print(f"  {marker} {tname:12s}  usage = {cnt} (expected {expect})")
    except Exception as e:
        print(f"  ⚠ {tname:12s}  not found ({e})")




print("\n[3/4] register non-zero slot count (reads only the first 64 slots per row; slow):")

REGS_64 = ["bucket_key0", "bucket_cnt0", "subnet_bm0",
           "bucket_key1", "bucket_cnt1", "subnet_bm1",
           "bucket_key2", "bucket_cnt2", "subnet_bm2"]
REGS_512 = ["host_bm0", "host_bm1", "host_bm2"]

def _extract(resp):
    
    try:
        d = resp.data
    except AttributeError:
        d = resp if isinstance(resp, dict) else {}
    best = 0
    for k, v in d.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, int):
                    best = max(best, int(item) & 0xFFFFFFFF)
        elif isinstance(v, int):
            best = max(best, int(v) & 0xFFFFFFFF)
    return best

def count_nonzero(name, n):
    tbl = getattr(p4, name)
    nz = 0
    for i in range(n):
        try:
            v = _extract(tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False))
            if v != 0:
                nz += 1
        except Exception:
            pass
    return nz

for r in REGS_64:
    nz = count_nonzero(r, 64)
    print(f"  {r:14s}  non-zero = {nz:>3} / 64")


for r in REGS_512:
    nz = count_nonzero(r, 64)
    print(f"  {r:14s}  non-zero = {nz:>3} / 64 (first 64 slots)")




print("\n[4/4] diagnosis:")
print("  - if neither forward_ipv4 ingress entry is found → setup_tables.py did not populate the tables")
print("  - if forward_ipv4 is OK but all registers are zero → packets never reach the SegSketch logic")
print("    → is the tester really sending IPv4 packets? (ipv4.isValid()=false when parse_ethernet takes the default branch)")
print("  - if cnt is non-zero but host_bm is all zeros → bug in the HBM RegisterAction / hidx")
print()
print("diagnosis done.")
