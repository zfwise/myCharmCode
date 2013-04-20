from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.crypto.cryptobase import *

import time
import string
import random

def randomStringGen(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

##group = PairingGroup('SS512')
##print("SS512, ZR, G1, G2, GT: \n")
##print(group.random())
##print(group.random(G1))
##print(group.random(G2))
##print(group.random(GT))
##
##group = PairingGroup('MNT159')
##print("MNT159, ZR, G1, G2, GT: \n")
##print(group.random(ZR))
##print(group.random(G1))
##print(group.random(G2))
##print(group.random(GT))
##
##group = PairingGroup('MNT224')
##print("MNT224, ZR, G1, G2, GT: \n")
##print(group.random())
##print(group.random(G1))
##print(group.random(G2))
##print(group.random(GT))

group = PairingGroup('/home/zfwise/Downloads/pbc-0.5.12/param/f.param', param_file=True)
print("BN, ZR, G1, G2, GT: \n")
print(group.random())
print(group.random(G1))
print(group.random(G2))
print(group.random(GT))


##v1 = group.random()
##print(v1)
##v2 =  group.random()
##print(v2)
##print(v1+v2)
##print(v1*(1/v2))
##print(v1/v2)
