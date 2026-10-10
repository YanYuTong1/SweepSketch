

import sys

PORTS = [
    
    (392, "BF_SPEED_100G", "BF_FEC_TYP_REED_SOLOMON"),  
    (400, "BF_SPEED_100G", "BF_FEC_TYP_REED_SOLOMON"),  
]

try:
    pt = bfrt.port.port
except (NameError, AttributeError) as e:
    print("Error: bfrt.port.port unavailable ({})".format(e))
    sys.exit(1)

print("[port] adding ports via the bfrt.port.port table ...")

for dp, speed, fec in PORTS:
    try:
        
        pt.add(
            DEV_PORT=dp,
            SPEED=speed,
            FEC=fec,
            PORT_ENABLE=True,
            AUTO_NEGOTIATION="PM_AN_DEFAULT",
        )
        print("  ✓ dev_port {:>4}  ({}, {})  ENABLED".format(dp, speed, fec))
    except Exception as e:
        
        try:
            pt.mod(DEV_PORT=dp, PORT_ENABLE=True)
            print("  ✓ dev_port {:>4}  already exists → re-enable".format(dp))
        except Exception as e2:
            print("  ⚠ dev_port {:>4}  failed: add={}  mod={}".format(dp, e, e2))

print("[port] done. Wait ~5s, then check `pm show` for OPR = UP")
