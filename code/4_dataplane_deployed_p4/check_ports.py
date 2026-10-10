
import sys

try:
    bfrt.port
except NameError:
    print("must run inside bfshell")
    sys.exit(1)


for dp in (392, 400):
    print("=" * 60)
    print("dev_port {} counters (from_hw):".format(dp))
    try:
        pst = bfrt.port.port_stat
        pst.get(DEV_PORT=dp, from_hw=True, print_ents=True)
    except Exception as e1:
        print("  port_stat read failed: {}".format(e1))
        
        try:
            info = bfrt.port.info()
            print("  bfrt.port node tree (to find stat-related table names):")
            print(info)
        except Exception as e2:
            print("  info() also failed: {}".format(e2))
print("=" * 60)
