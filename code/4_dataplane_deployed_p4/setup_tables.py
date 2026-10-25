import sys
try:
    p4 = bfrt.sweepsketch.pipe.Ingress
except NameError:
    pass
    sys.exit(1)
DEV_PORT_MAP = {392: 400, 400: 392}
pass
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    for key_name in ('ingress_port', 'ig_intr_md.ingress_port', 'ig_intr_md_ingress_port'):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(**{key_name: ingress_port}, port=egress_port)
            pass
            added = True
        except Exception as e:
            if 'exists' in str(e).lower():
                pass
                added = True
                break
pass
