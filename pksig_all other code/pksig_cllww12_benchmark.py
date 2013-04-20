from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.crypto.cryptobase import *
from charm.toolbox.IBEnc import IBEnc
from charm.schemes.pksig.pksig_cllww12 import Sign_Chen12
from charm.schemes.pksig.pksig_cllww12_swap import Sign_Chen12_swap
from charm.schemes.pksig.pksig_cllww12_swap_improved import Sign_Chen12_swap_improved
from charm.schemes.pksig.pksig_bls04 import IBSig
from charm.schemes.pksig.pksig_waters05 import IBE_N04_Sig
from charm.schemes.pksig.pksig_waters05_improved import IBE_N04_Sig_improved
from charm.schemes.pksig.pksig_waters09_improved import IBEWaters09_improved
from charm.toolbox.hash_module import Waters

import time
import string
import random

def randomStringGen(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

n = 200
#groupObj = PairingGroup('MNT224')
groupObj = PairingGroup('/home/zfwise/Downloads/pbc-0.5.12/param/f.param', param_file=True)
if(1):
    m = "plese sign this message!!!!"
    #cllww = Sign_Chen12(groupObj)
    cllww = Sign_Chen12(groupObj)
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (pk, sk) = cllww.keygen()
        cllwwKeyGenTime += time.time() - startTime

        m = randomStringGen()
        startTime = time.time()
        signature = cllww.sign(pk, sk, m)
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert cllww.verify(pk, signature, m), "Invalid Verification!!!!"
        cllwwVerifyTime += time.time() - startTime
    print("CLLWW12_sign: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("CLLWW12_sign: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("CLLWW12_sign: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
if(1):
    m = "plese sign this message!!!!"
    #cllww = Sign_Chen12(groupObj)
    cllww = Sign_Chen12_swap(groupObj)
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (pk, sk) = cllww.keygen()
        cllwwKeyGenTime += time.time() - startTime

        m = randomStringGen()
        startTime = time.time()
        signature = cllww.sign(pk, sk, m)
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert cllww.verify(pk, signature, m), "Invalid Verification!!!!"
        cllwwVerifyTime += time.time() - startTime
    print("CLLWW12_sign_swap: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("CLLWW12_sign_swap: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("CLLWW12_sign_swap: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
if(1):
    m = "plese sign this message!!!!"
    #cllww = Sign_Chen12(groupObj)
    cllww = Sign_Chen12_swap_improved(groupObj)
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (pk, sk) = cllww.keygen()
        cllwwKeyGenTime += time.time() - startTime

        m = randomStringGen()
        startTime = time.time()
        signature = cllww.sign(pk, sk, m)
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert cllww.verify(pk, signature, m), "Invalid Verification!!!!"
        cllwwVerifyTime += time.time() - startTime
    print("CLLWW12_sign_swap_improved: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("CLLWW12_sign_swap_improved: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("CLLWW12_sign_swap_improved: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
#groupObj = PairingGroup('MNT224')
#groupObj = PairingGroup('SS512')
if(1):
    m = { 'a':"hello world!!!" , 'b':"test message" }
    bls = IBSig(groupObj)
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (pk, sk) = bls.keygen()
        cllwwKeyGenTime += time.time() - startTime

        m = {'a':randomStringGen() , 'b':randomStringGen()}
        startTime = time.time()
        sig = bls.sign(sk['x'], m) 
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert bls.verify(pk, sig, m), "Failure!!!"
        cllwwVerifyTime += time.time() - startTime
    print("Bls04: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("Bls04: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("Bls04: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
#groupObj = PairingGroup('MNT159')
#groupObj = PairingGroup('SS512')
if(1):
    ibe = IBE_N04_Sig(groupObj)
    waters = Waters(groupObj)
    msg = waters.hash("This is a test.")  
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (pk, sk) = ibe.keygen()
        cllwwKeyGenTime += time.time() - startTime

        msg = waters.hash(randomStringGen()) 
        startTime = time.time()
        sig = ibe.sign(pk, sk, msg) 
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert ibe.verify(pk, msg, sig), "Failed verification!"
        cllwwVerifyTime += time.time() - startTime
    print("Waters05: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("Waters05: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("Waters05: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
if(1):
    ibe = IBE_N04_Sig_improved(groupObj)
    waters = Waters(groupObj)
    msg = waters.hash("This is a test.")  
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (pk, sk) = ibe.keygen()
        cllwwKeyGenTime += time.time() - startTime

        msg = waters.hash(randomStringGen()) 
        startTime = time.time()
        sig = ibe.sign(pk, sk, msg) 
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert ibe.verify(pk, msg, sig), "Failed verification!"
        cllwwVerifyTime += time.time() - startTime
    print("Waters05_improved: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("Waters05_improved: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("Waters05_improved: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
#grp = PairingGroup('MNT224')
#grp = PairingGroup('SS512')
if(1):
    ibe = IBEWaters09_improved(groupObj)
    m = "plese sign this message!!!!"  
    bls = IBSig(groupObj)
    cllwwKeyGenTime = 0.0
    cllwwSignTime = 0.0
    cllwwVerifyTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (mpk, msk) = ibe.keygen()
        cllwwKeyGenTime += time.time() - startTime

        m = randomStringGen()
        startTime = time.time()
        sigma = ibe.sign(mpk, msk, m)
        cllwwSignTime += time.time() - startTime

        startTime = time.time()
        assert ibe.verify(mpk, sigma, m), "Invalid Verification!!!!"
        cllwwVerifyTime += time.time() - startTime
    print("Waters09: Keygen %d times, average time %f ms" %(n, cllwwKeyGenTime/n*1000))
    print("Waters09: Sign random message %d times, average time %f ms" %(n, cllwwSignTime/n*1000))
    print("Waters09: Verify %d times, average time %f ms" %(n, cllwwVerifyTime/n*1000))
    print("&%.2f () &%.2f () &%.2f ()" %(cllwwKeyGenTime/n*1000,
                                         cllwwSignTime/n*1000,
                                         cllwwVerifyTime/n*1000))
