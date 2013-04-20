from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.crypto.cryptobase import *
from charm.toolbox.hash_module import Waters
from charm.schemes.ibenc.ibenc_waters09 import DSE09

import time
import string
import random

def randomStringGen(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

b = 1000
group = PairingGroup('SS512')
#group = PairingGroup('/home/zfwise/Downloads/pbc-0.5.12/param/f.param', param_file=True)
global waters_hash
waters_hash = Waters(group)

za = group.random()
zb = group.random()
g = group.random(G1)
h = group.random(G1)
i = group.random(G1)
j = group.random(G2)
k = group.random(G2)
m = group.random(G2)
n = group.random(ZR)
o = group.random(GT)
x = group.random(GT)
y = group.random(GT)
G1add = 0.0
G1sub = 0.0
G1mul = 0.0
G1exp = 0.0
G1div = 0.0

G2add = 0.0
G2sub = 0.0
G2mul = 0.0
G2exp = 0.0
G2div = 0.0

GTmul = 0.0
GTexp = 0.0

pairTime = 0.0
ZREXP = 0.0

RandomG1 = 0.0
RandomG2 = 0.0

bitG1 = 0.0
bitG2 = 0.0

##G1mul = 0.0
##for a in range(0, b):
##    g = group.random(G1)
##    h = group.random(G1)
##    startTime = time.time()
##    g = g + h
##    G1mul += time.time() - startTime
##print(" %d times ,average = %f ms" %(b, G1mul/b*1000))
##G1exp = 0.0
##for a in range(0, b):
##    n1 = group.random()
##    n = group.random()
##    startTime = time.time()
##    n = n1 + n
##    G1exp += time.time() - startTime
##print(" %d times, average = %f ms" %(b, G1exp/b*1000))
##G1exp = 0.0
##for a in range(0, b):
##    n1 = group.random()
##    n = group.random()
##    startTime = time.time()
##    n = n1 - n
##    G1exp += time.time() - startTime
##print(" %d times, average = %f ms" %(b, G1exp/b*1000))
##G1exp = 0.0
##for a in range(0, b):
##    n1 = group.random()
##    n = group.random()
##    startTime = time.time()
##    n = n1 * n
##    G1exp += time.time() - startTime
##print(" %d times, average = %f ms" %(b, G1exp/b*1000))
##G1exp = 0.0
##for a in range(0, b):
##    n1 = group.random()
##    n = group.random()
##    startTime = time.time()
##    n = n1/n
##    G1exp += time.time() - startTime
##print(" %d times, average = %f ms" %(b, G1exp/b*1000))

for a in range(0, b):
    g = group.random(G1)
    h = group.random(G1)
    startTime = time.time()
    i = g * h
    G1mul += time.time() - startTime
print(" %d times of G1 mul, average = %f ms" %(b, G1mul/b*1000))

for a in range(0, b):
    g = group.random(G1)
    n = group.random(ZR)
    startTime = time.time()
    i = g ** n
    G1exp += time.time() - startTime
print(" %d times of G1 exp, average = %f ms" %(b, G1exp/b*1000))

for a in range(0, b):
    j = group.random(G2)
    k = group.random(G2)
    startTime = time.time()
    m = j * k
    G2mul += time.time() - startTime
print(" %d times of G2 mul, average = %f ms" %(b, G2mul/b*1000))

for a in range(0, b):
    j = group.random(G2)
    n = group.random(ZR)
    startTime = time.time()
    m = j ** n
    G2exp += time.time() - startTime
print(" %d times of G2 exp, average = %f ms" %(b, G2exp/b*1000))

for a in range(0, b):
    x = group.random(GT)
    y = group.random(GT)
    startTime = time.time()
    o = x * y
    GTmul += time.time() - startTime
print(" %d times of GT mul, average = %f ms" %(b, GTmul/b*1000))

for a in range(0, b):
    x = group.random(GT)
    n = group.random(ZR)
    startTime = time.time()
    o = x ** n
    GTexp += time.time() - startTime
print(" %d times of GT exp, average = %f ms" %(b, GTexp/b*1000))

for a in range(0, b):
    g = group.random(G1)
    k = group.random(G2)
    startTime = time.time()
    o = pair(g, k)
    pairTime += time.time() - startTime
print(" %d times of pairing, average = %f ms" %(b, pairTime/b*1000))

for a in range(0, b):
    za = group.random()
    zb = group.random()
    startTime = time.time()
    i = za ** zb
    ZREXP += time.time() - startTime
print(" %d times of ZR Exp, average = %f ms" %(b, ZREXP/b*1000))

for a in range(0, b):
    startTime = time.time()
    g = group.random(G1)
    RandomG1 += time.time() - startTime
print(" %d times of Random(G1), average = %f ms" %(b, RandomG1/b*1000))

for a in range(0, b):
    startTime = time.time()
    j = group.random(G2)
    RandomG2 += time.time() - startTime
print(" %d times of Random(G2), average = %f ms" %(b, RandomG2/b*1000))

for a in range(0, b):
    ID = randomStringGen()
    v = waters_hash.hash(ID)
    g = group.random(G1)
    startTime = time.time()
    h = g ** v[0]
    bitG1 += time.time() - startTime
print(" %d times of 32 bit G1 Exp, average = %f ms" %(b, bitG1/b*1000))

for a in range(0, b):
    ID = randomStringGen()
    v = waters_hash.hash(ID)
    k = group.random(G2)
    startTime = time.time()
    j = k ** v[0]
    bitG2 += time.time() - startTime
print(" %d times of 32 bit G2 Exp, average = %f ms" %(b, bitG2/b*1000))

print("&%.4f &%.4f &%.4f &%.4f &%.4f &%.4f &%.4f &%.4f &%.4f &%.4f &%.4f &%.4f "
      %(G1mul/b*1000, G1exp/b*1000, G2mul/b*1000, G2exp/b*1000,
      GTmul/b*1000, GTexp/b*1000, pairTime/b*1000, ZREXP/b*1000,
      RandomG1/b*1000, RandomG2/b*1000, bitG1/b*1000, bitG2/b*1000))
