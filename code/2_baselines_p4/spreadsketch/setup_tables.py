
import sys

import bfrt_grpc.client as gc

try:
    p4 = bfrt.spreadsketch.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    print("Usage: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)

DEV_PORT_MAP = {
    392: 400,   
    400: 392,   
}



print("[1/4] clearing all existing entries...")
for tname in ("tz_tcam", "tbl_mask", "forward_ipv4"):
    try:
        getattr(p4, tname).clear()
        print(f"  ✓ {tname} cleared")
    except Exception as e:
        print(f"  ⚠ {tname} clear failed: {e}")




print("[2/4] tz_tcam (32 ternary entries)...")
tbl = p4.tz_tcam
for i in range(32):
    def _seg(i, lo, hi):
        
        if i < lo:
            return (0, 0)
        if i >= hi - 1:
            full = (1 << (hi - lo)) - 1
            return (full, full)
        pat = (1 << (i - lo + 1)) - 1
        return (pat, pat)
    v0, m0 = _seg(i, 0, 8)     
    v1, m1 = _seg(i, 8, 16)    
    v2, m2 = _seg(i, 16, 24)   
    v3, m3 = _seg(i, 24, 32)   
    tbl.entry_add(
        tbl.make_key([
            gc.KeyTuple('$MATCH_PRIORITY', i),
            gc.KeyTuple('b0', v0, m0),
            gc.KeyTuple('b1', v1, m1),
            gc.KeyTuple('b2', v2, m2),
            gc.KeyTuple('b3', v3, m3),
        ]),
        tbl.make_data([gc.DataTuple('lvl_v', i + 2)], 'act_lvl_tc'))
print("  ✓ wrote 32 entries (priority 0..31)")


print("[3/4] tbl_mask (32entries)...")
for b in range(32):
    p4.tbl_mask.add_with_act_mask(bit_idx=b, m=(1 << b))
print("  ✓ wrote 32 entries")


print("[4/4] forward_ipv4 (port forwarding)...")
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

print("\n[done] SpreadSketch control plane initialized: tz_tcam 32 + mask 32 + forward 2 entries.")
print("suggested check: p4.forward_ipv4.dump(); p4.tz_tcam.dump() to spot-check entries.")
