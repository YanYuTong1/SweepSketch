
import sys

try:
    p4 = bfrt.sweepsketch.pipe.Ingress
except NameError:
    print("must run inside bfshell: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)


DEV_PORT_MAP = {
    392: 400,   
    400: 392,   
}

print("[1/2] forward_ipv4 (port forwarding)...")
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    
    for key_name in ("ingress_port", "ig_intr_md.ingress_port", "ig_intr_md_ingress_port"):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(
                **{key_name: ingress_port}, port=egress_port
            )
            print("  ✓ ingress {} → egress {}  (key={})".format(ingress_port, egress_port, key_name))
            added = True
        except Exception as e:
            if "exists" in str(e).lower():
                print("  ✓ ingress {} → egress {}  (already exists)".format(ingress_port, egress_port))
                added = True
                break
            






print("[2/2] setup_tables done: remaining tables are default-only and need no entries")
