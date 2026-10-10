

import sys

PORTS = [
    
    (392, "BF_SPEED_100G", "BF_FEC_TYP_REED_SOLOMON"),  
    (400, "BF_SPEED_100G", "BF_FEC_TYP_REED_SOLOMON"),  
]

try:
    pt = bfrt.port.port
except (NameError, AttributeError) as e:
    print(f"Error: bfrt.port.port unavailable ({e})")
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
        print(f"  ✓ dev_port {dp:>4}  ({speed}, {fec})  ENABLED")
    except Exception as e:
        
        try:
            pt.mod(DEV_PORT=dp, PORT_ENABLE=True)
            print(f"  ✓ dev_port {dp:>4}  already exists → re-enable")
        except Exception as e2:
            print(f"  ⚠ dev_port {dp:>4}  failed: add={e}  mod={e2}")

print("[port] done. Run `pm show` in another terminal; wait for OPR to become UP (~5s)")
