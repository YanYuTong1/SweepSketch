

import sys

try:
    p4 = bfrt.SegSketch.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    print("Usage: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)

DEV_PORT_MAP = {
    392: 400,
    400: 392,
}


print("[1/5] clearing all existing entries...")

TABLES_TO_CLEAR = [
    "tbl_mask1", "tbl_mask2", "tbl_mask3", "tbl_hmask",
    "forward_ipv4",
]

for tname in TABLES_TO_CLEAR:
    try:
        getattr(p4, tname).clear()
        print(f"  ✓ {tname} cleared")
    except Exception as e:
        print(f"  ⚠ {tname} clear failed: {e}")




print("[2/5] tbl_mask1 (2entries)...")
p4.tbl_mask1.add_with_act_m1(hash_s1=0, m=0xF0)
p4.tbl_mask1.add_with_act_m1(hash_s1=1, m=0x0F)
print("  ✓ wrote 2 entries")

print("[3/5] tbl_mask2 (4entries)...")
p4.tbl_mask2.add_with_act_m2(hash_s1=0, hash_s2=0, m=0xC0)
p4.tbl_mask2.add_with_act_m2(hash_s1=0, hash_s2=1, m=0x30)
p4.tbl_mask2.add_with_act_m2(hash_s1=1, hash_s2=0, m=0x0C)
p4.tbl_mask2.add_with_act_m2(hash_s1=1, hash_s2=1, m=0x03)
print("  ✓ wrote 4 entries")

print("[3/5] tbl_mask3 (8entries)...")
MASK3 = [
    (0,0,0,0x80),(0,0,1,0x40),(0,1,0,0x20),(0,1,1,0x10),
    (1,0,0,0x08),(1,0,1,0x04),(1,1,0,0x02),(1,1,1,0x01),
]
for s1,s2,s3,m in MASK3:
    p4.tbl_mask3.add_with_act_m3(hash_s1=s1, hash_s2=s2, hash_s3=s3, m=m)
print("  ✓ wrote 8 entries")



print("[4/5] tbl_hmask (32entries)...")
for b in range(32):
    p4.tbl_hmask.add_with_act_hmask(host_bm_bit=b, m=(1 << b))
print("  ✓ wrote 32 entries")


print("[5/5] forward_ipv4 (port forwarding)...")
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    
    for key_name in ("ingress_port", "ig_intr_md.ingress_port", "ig_intr_md_ingress_port"):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(
                **{key_name: ingress_port}, egr_port=egress_port
            )
            print(f"  ✓ ingress {ingress_port} → egress {egress_port}  (key={key_name})")
            added = True
        except Exception as e:
            if "exists" in str(e).lower():
                
                print(f"  ✓ ingress {ingress_port} → egress {egress_port}  (already exists)")
                added = True
                break
            
    if not added:
        print(f"  ✗ ingress {ingress_port} → egress {egress_port}  all key names failed")


print("\n[verify] forward_ipv4 read back:")
for ingress_port in DEV_PORT_MAP.keys():
    found = False
    for key_name in ("ingress_port", "ig_intr_md.ingress_port", "ig_intr_md_ingress_port"):
        try:
            resp = p4.forward_ipv4.get(**{key_name: ingress_port}, print_ents=False)
            found = True
            print(f"  ✓ ingress {ingress_port} confirmed present (use {key_name})")
            break
        except Exception:
            continue
    if not found:
        print(f"  ✗ ingress {ingress_port} not readable! (add may have failed)")

print("\n[done] SegSketch control plane initialized.")
