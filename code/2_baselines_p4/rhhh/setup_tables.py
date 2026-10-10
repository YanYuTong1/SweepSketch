

import sys

import bfrt_grpc.client as gc

try:
    p4 = bfrt.rhhh.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    print("Usage: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)



DEV_PORT_MAP = {
    392: 400,
    400: 392,
}


print("[1/3] clearing existing entries...")
for tname in ("tbl_mask", "forward_ipv4"):
    try:
        getattr(p4, tname).clear()
        print(f"  ✓ {tname} cleared")
    except Exception as e:
        print(f"  ⚠ {tname} clear failed: {e}")




print("[2/3] tbl_mask (4 ternary entries)...")
for lv, mask in ((0, 0xFFFFFFFF), (1, 0xFFFFFF00), (2, 0xFFFF0000), (3, 0xFF000000)):
    p4.tbl_mask.entry_add(
        p4.tbl_mask.make_key([
            gc.KeyTuple('$MATCH_PRIORITY', 0),
            gc.KeyTuple('lv', lv, 0x3),
        ]),
        p4.tbl_mask.make_data([gc.DataTuple('m', mask)], 'act_mask'))
print("  ✓ wrote 4 entries")


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


print("\n[verify] tbl_mask read back:")
try:
    resp = p4.tbl_mask.dump()
    print("  ✓ tbl_mask dump done (4 entries expected)")
except Exception as e:
    print(f"  ✗ tbl_mask dump failed: {e}")

print("\n[done] RHHH control plane initialized.")
print("  next: inject traffic → run_bfshell.sh -b query_rhhh.py to read registers + hierarchy report")
