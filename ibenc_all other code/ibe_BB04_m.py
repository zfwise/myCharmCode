'''
Boneh-Boyen Identity Based Encryption
 
| From: "D. Boneh, X. Boyen.  Efficient Selective Identity-Based Encryption Without Random Oracles", Section 5.1.
| Published in: Eurocrypt 2004
| Available from: http://crypto.stanford.edu/~dabo/pubs/papers/bbibe.pdf
| Notes: This is the IBE (1-level HIBE) implementation of the HIBE scheme BB_2.

* type:			encryption (identity-based)
* setting:		bilinear groups (asymmetric)

:Authors:	J Ayo Akinyele
:Date:			11/2010
:Fixed by Hoeteck Wee 04/2013
extract is 2 G2-exp (not one)
dec is 2 PP (not 1 PP + 1 G1-exp)
'''

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.crypto.cryptobase import *
from charm.toolbox.IBEnc import IBEnc
from charm.core.math.pairing import hashPair as sha1

debug = False
class IBE_BB04_m(IBEnc):
    """
    >>> group = PairingGroup('MNT224')
    >>> ibe = IBE_BB04(group)
    >>> (master_public_key, master_key) = ibe.setup()
    >>> master_public_key_ID = group.random(ZR)
    >>> key = ibe.extract(master_key, master_public_key_ID)
    >>> msg = group.random(GT)
    >>> cipher_text = ibe.encrypt(master_public_key, master_public_key_ID, msg)
    >>> decrypted_msg = ibe.decrypt(master_public_key, key, cipher_text)
    >>> decrypted_msg == msg
    True
    """
    def __init__(self, groupObj):
        IBEnc.__init__(self)
        IBEnc.setProperty(self, secdef='IND_sID_CPA', assumption='DBDH', 
                          message_space=[GT, 'KEM'], secmodel='ROM', other={'id':ZR})
        global group
        group = groupObj
        
    def setup(self, secparam=None):
        #StartBenchmark(bID1, [CpuTime, NativeTime])
        g, g2 = group.random(G1), group.random(G2)
        x, y = group.random(ZR), group.random(ZR)
        alpha = group.random(ZR)  #from Zp
        g2a = g2 ** alpha
        v = pair(g, g2a)

        X = g ** x
        Y = g ** y 
        pk = { 'g':g, 'X':X, 'Y':Y, 'v':v } # public params
        mk = { 'x':x, 'y':y, 'g2a':g2a, 'g2':g2 }         # master secret
        return (pk, mk)
    
    # Note: ID is a string and is the public key ID for the user
    def extract(self, mk, ID):

        _ID = group.hash(ID,ZR)
        r = group.random()
        g2 = mk['g2']
        g2r = g2**r
        # compute K
        K = mk['g2a'] * (g2 ** ((_ID * mk['x'] + mk['y']) * r))
        return { 'g2r': g2r, 'K':K }

    # assume that M is in GT
    def encrypt(self, params, ID, M):
        s = group.random(ZR)

        _ID = group.hash(ID,ZR)
        A = (params['v'] ** s) * M 
        B = params['g'] ** s
        C = (params['Y'] ** s) * (params['X'] ** (s * _ID))
        return { 'A':A, 'B':B, 'C':C }

    def decrypt(self, pk, dID, CT):
        A, B, C = CT['A'], CT['B'], CT['C']
        v_s = pair(B, dID['K']) / pair(C, dID['g2r'])
        return A / v_s
    
def main():

    #group = PairingGroup('MNT159', secparam=1024)    
    G = PairingGroup('SS512')

    ibe = IBE_BB04_m(G)
    (master_public_key, master_secret_key) = ibe.setup()
    ID = 'user@email.com'
    private_key = ibe.extract(master_secret_key, ID)
    msg = G.random(GT)
    cipher_text = ibe.encrypt(master_public_key, ID, msg)
    decryptedMSG = ibe.decrypt(master_public_key, private_key, cipher_text)
    print (decryptedMSG==msg)

if __name__ == '__main__':
    main()   
