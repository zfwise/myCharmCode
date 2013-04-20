'''David Naccache based Identity-Based Encryption
 
| From: "David Naccache Secure and Practical Identity-Based Encryption Section 4"
| Available from: http://eprint.iacr.org/2005/369.pdf

* type:			encryption (identity-based)
* setting:		bilinear groups (asymmetric)

:Authors:	Gary Belvin
:Date:			06/2011

:Improved by: Fan Zhang, 3/2013
:Note:
1. e(g1,g2) is pre-calculated as part of public parameters.
2. Previous implemenaton was trying to multiply an element in G1 with an element
in ZR, which sometimes cause the compiler throw an error. I fixed that problem
by having U_z in ZR and calculate g^U_z. Now, elements are in the right group.
3. I stored U_z and u as part of msk. This will speed up the extract() a lot.
The trick is that, instead of doing exponential operation and then multiply
all together, I compute the exponent first and then do one exponential operation
4. sk are in G2 and ct are in G1 now. Before that, we have 1 element in G1 and
the other in G2 in both sk and ct.

''' 
from __future__ import print_function
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.bitstring import Bytes
from charm.toolbox.hash_module import Waters
import hashlib, math
import time
import string
import random

def randomStringGen(size=30, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

debug = False
class IBE_N04_z(IBEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,GT
    >>> from charm.toolbox.hash_module import Waters
    >>> group = PairingGroup('SS512')
    >>> waters_hash = Waters(group)
    >>> ibe = IBE_N04_z(group)
    >>> (master_public_key, master_key) = ibe.setup()
    >>> ID = "bob@mail.com"
    >>> kID = waters_hash.hash(ID)
    >>> secret_key = ibe.extract(master_public_key, master_key, kID)
    >>> msg = group.random(GT)
    >>> cipher_text = ibe.encrypt(master_public_key, kID, msg)
    >>> decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
    >>> decrypted_msg == msg
    True
    """
    
    """Implementation of David Naccahe Identity Based Encryption"""
    def __init__(self, groupObj):
        IBEnc.__init__(self)
        IBEnc.setProperty(self, secdef='IND_ID_CPA', assumption='DBDH', secmodel='Standard')
        #, other={'id':ZR}
        #message_space=[GT, 'KEM']
        global group
        group = groupObj
        global waters_hash
        waters_hash = Waters(group)

    def setup(self, l=32):
        '''l is the security parameter
        with l = 32, and the hash function at 160 bits = n * l with n = 5'''
        global waters
        sha1_func, sha1_len = 'sha1', 20
        g = group.random(G1)      # generator for group G of prime order p
        
        hLen = sha1_len * 8
        n = int(math.floor(hLen / l))
        waters = Waters(group, n, l, sha1_func)
                
        alpha = group.random(ZR)  #from Zp
        g1    = g ** alpha      # G1
        g2    = group.random(G2)    #G2
        u = group.random(ZR)
        uprime = g ** u
        U_z = [group.random(ZR) for x in range(n)]
        U = [g ** x  for x in U_z]
        
        pk = {'g':g, 'g1':g1, 'g2': g2, 'uPrime':uprime, 'U': U, 
            'n':n, 'l':l, 'eg1g2':pair(g1, g2)}

        mk = {'g2^alpha': g2 ** alpha, 'U_z':U_z, 'u':u} #master secret
        if debug: 
            print(mk)
        
        return (pk, mk)
        
    def extract(self, pk, mk, v):
        '''v = (v1, .., vn) is an identity'''
        r = group.random(ZR)
        
        u = mk['u']

        for i in range(pk['n']):
            u += mk['U_z'][i] * v[i]    
        d1 = mk['g2^alpha'] * (pk['g2'] ** (u * r) )
        d2 = pk['g2'] ** r
        
        if debug:
            print("D1    =>", d1)
            print("D2    =>", d2)
        return {'d1': d1, 'd2':d2}

    def encrypt(self, pk, ID, M): # M:GT
        t = group.random(ZR)
        c1 = (pk['eg1g2'] ** t) * M
        c2 = pk['g'] ** t
        c3 = pk['uPrime']

        for i in range(pk['n']):
            c3 *= pk['U'][i] ** ID[i]
        c3 = c3 ** t
        
        if debug:
            print("Encrypting")
            print("C1    =>", c1)
            print("C2    =>", c2)
            print("C3    =>", c3)
        return {'c1':c1, 'c2': c2, 'c3':c3}

    def decrypt(self, pk, sID, ct):
        num = pair(ct['c3'], sID['d2'])
        dem = pair(ct['c2'], sID['d1'])
        if debug:
            print("Decrypting")    
            print("arg1    =>", sID['d2'].type)
            print("arg2    =>", ct['c3'].type)
            print("Num:    =>", num)
            print("Dem:    =>", dem)
            
        return ct['c1'] *  num / dem

def main():
    group = PairingGroup('MNT224')
    waters_hash = Waters(group)
    ibe = IBE_N04_z(group)
    (master_public_key, master_key) = ibe.setup()

    ID = "bob@mail.com"
    kID = waters_hash.hash(ID)
    secret_key = ibe.extract(master_public_key, master_key, kID)
    msg = group.random(GT)
    cipher_text = ibe.encrypt(master_public_key, kID, msg)
    decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
    assert msg == decrypted_msg, "invalid decryption"
    if debug: print("Successful Decryption!")

if __name__ == "__main__":
    debug = True
    main()

