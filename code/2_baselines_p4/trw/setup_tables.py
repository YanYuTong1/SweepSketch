

import sys

try:
    p4 = bfrt.trw.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    print("Usage: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)


DEV_PORT_MAP = {
    392: 400,
    400: 392,
}


print("[1/3] clearing all existing entries...")

TABLES_TO_CLEAR = [
    "tbl_mask",
    "forward_ipv4",
]

for tname in TABLES_TO_CLEAR:
    try:
        getattr(p4, tname).clear()
        print(f"  ✓ {tname} cleared")
    except Exception as e:
        print(f"  ⚠ {tname} clear failed: {e}")



print("[2/3] tbl_mask (32 entries)...")
for b in range(32):
    p4.tbl_mask.add_with_act_mask(pair_bit=b, m=(1 << b))
print("  ✓ wrote 32 entries")


print("[3/3] forward_ipv4 (port forwarding)...")
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

print("\n[done] TRW control plane initialized.")
