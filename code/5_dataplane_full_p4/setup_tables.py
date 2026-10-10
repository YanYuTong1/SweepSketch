
import math
import sys

try:
    p4 = bfrt.sweepsketch.pipe.Ingress
except NameError:
    print("must run inside bfshell: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)



for c in range(1, 256):
    rho = 0 + (8 - 1 - int(math.floor(math.log2(c))))
    p4.clz0.add_with_act_clz(r_hi=c, rho_v=rho, done_v=1)
for c in range(1, 256):
    rho = 8 + (8 - 1 - int(math.floor(math.log2(c))))
    p4.clz1.add_with_act_clz(r_mid=c, rho_v=rho, done_v=1)
for c in range(1, 256):
    rho = 16 + (8 - 1 - int(math.floor(math.log2(c))))
    p4.clz2.add_with_act_clz(r_lo=c, rho_v=rho, done_v=1)
for c in range(1, 8):
    rho = 24 + (3 - 1 - int(math.floor(math.log2(c))))
    p4.clz3.add_with_act_clz(r_tail=c, rho_v=rho, done_v=1)



p4.t1_delta.add_with_act_delta(event=1, claim=0, rollover=0, d=38)      
p4.t1_delta.add_with_act_dD(event=1, claim=0, rollover=1, dc=38)        
p4.t1_delta.add_with_act_dD(event=1, claim=1, rollover=0, dc=38)        
p4.t1_delta.add_with_act_dD(event=1, claim=1, rollover=1, dc=38)        
p4.t1_delta.add_with_act_delta(event=0, claim=0, rollover=0, d=0xFFDA)  
p4.t1_delta.add_with_act_dnegC(event=0, claim=0, rollover=1)            
p4.t1_delta.add_with_act_dnegC(event=0, claim=1, rollover=0)            
p4.t1_delta.add_with_act_dnegC(event=0, claim=1, rollover=1)            

p4.t2_delta.add_with_act_delta2(event2=1, claim2=0, rollover2=0, d=38)
p4.t2_delta.add_with_act_dD2(event2=1, claim2=0, rollover2=1, dc=38)
p4.t2_delta.add_with_act_dD2(event2=1, claim2=1, rollover2=0, dc=38)
p4.t2_delta.add_with_act_dD2(event2=1, claim2=1, rollover2=1, dc=38)
p4.t2_delta.add_with_act_delta2(event2=0, claim2=0, rollover2=0, d=0xFFDA)
p4.t2_delta.add_with_act_dnegC2(event2=0, claim2=0, rollover2=1)
p4.t2_delta.add_with_act_dnegC2(event2=0, claim2=1, rollover2=0)
p4.t2_delta.add_with_act_dnegC2(event2=0, claim2=1, rollover2=1)


_n_e1 = 0
for k in range(32):
    v = (k << 3) & 0xFF
    p4.tb1_e1.add_with_act_e1(global_epoch=k, v=v)
    p4.tb2_e1.add_with_act_e12(global_epoch=k, v=v)
    _n_e1 += 2
assert _n_e1 == 64, _n_e1
_n_wn = 0
for k in range(256):
    w = k & 7
    p4.tb1_wn0.add_with_act_wn(ep_old=k, v=w)
    p4.tb1_wn1.add_with_act_wn(ep_old=k, v=(w + 1) & 7)
    p4.tb2_wn0.add_with_act_wn2(ep2_old=k, v=w)
    p4.tb2_wn1.add_with_act_wn2(ep2_old=k, v=(w + 1) & 7)
    _n_wn += 4
assert _n_wn == 1024, _n_wn
_n_w5 = 0
for k in range(256):
    v = (k & 7) << 5
    p4.tb1_w5.add_with_act_w5(win_new=k, v=v)
    p4.tb2_w5.add_with_act_w52(win2_new=k, v=v)
    _n_w5 += 2
assert _n_w5 == 512, _n_w5


p4.forward_ipv4.add_with_set_egr(ingress_port=392, port=400)
p4.forward_ipv4.add_with_set_egr(ingress_port=400, port=392)


print("setup_tables done: CLZ 774 + t1/t2_delta 16 + decision-14 lookup tables 1600 + forward_ipv4 2")
