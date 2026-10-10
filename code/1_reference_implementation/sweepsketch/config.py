


HLL_M = 32          
                    
RHO_BITS = 5        
WIN_MASK = 7        
USE_L2 = True       
USE_D1 = True       
USE_D2 = True       
USE_GATE = True     
N_L1 = 7943         
                    
                    
                    
N_L2 = 3972         
SCALE = 8           
C_MAX = 0xFFFF      
PKT_MAX = 0xFFFF    


THETA0 = 0.0345      
                     
                     
                     
THETA1 = 0.9        
H_BITS = 9.2        
                     
                     
                     
H_FP = 74           
K_ALARM = 8         
K_ALARM_QUIET = 12  
                    
                    
                    
N_EWMA_QUIET = 4    
K_FLOOD = 6         
                    
                    
EWMA_SHIFT = 3      
P_MIN = 200         
D2_MULT = 3         
                    


EPOCH_NS = 1 << 32  


BENIGN_MAX = 12000000
ATTACK_MAX = 500000


if __name__ == "__main__":
    assert N_L1 + N_L2 == 11915, (N_L1, N_L2)
    assert (N_L1 + N_L2) * 44 <= 512 * 1024  
    assert H_FP == round(H_BITS * SCALE)
    assert 0 < THETA0 < THETA1 < 1 and K_ALARM >= 1 and P_MIN >= 1
    assert HLL_M == 32 and RHO_BITS == 5 and WIN_MASK == 7
    print("config self-check ok")
