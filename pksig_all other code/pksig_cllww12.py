'''
Shorter IBE and Signatures via Asymmetric Pairings
  
| From: "J. Chen, H. Lim, S. Ling, H. Wang, H. Wee Shorter IBE and Signatures via Asymmetric Pairings", Section 4.
| Published in: Pairing 2012
| Available from: http://eprint.iacr.org/2012/224
| Notes: This is a shorter IBE construction based on SXDH construction.

* type:           signature (identity-based)
* setting:        bilinear groups (asymmetric)

:Authors:    Fan Zhang
:Date:       3/2013
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.crypto.cryptobase import *
from charm.toolbox.PKSig import PKSig

debug = False
class Sign_Chen12(PKSig):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup
    >>> groupObj = PairingGroup('MNT224')
    >>> m = "plese sign this message!!!!"
    >>> cllww = Sign_Chen12(groupObj)
    >>> (pk, sk) = cllww.keygen()
    >>> signature = cllww.sign(pk, sk, m)
    >>> cllww.verify(pk, signature, m) 
    True
    """
    def __init__(self, groupObj):
        PKSig.__init__(self)
        #IBEnc.setProperty(self, message_space=[GT, 'KEM'], secdef='IND_sID_CPA', assumption='DBDH', secmodel='ROM', other={'id':ZR})
        global group
        group = groupObj
        
    def keygen(self):
        g1 = group.random(G1)
        g2 = group.random(G2)
        alpha = group.random(ZR)

        #generate the 4*4 dual pairing vector spaces.
        d11, d12, d13, d14 = group.random(ZR),group.random(ZR),group.random(ZR),group.random(ZR)
        d21, d22, d23, d24 = group.random(ZR),group.random(ZR),group.random(ZR),group.random(ZR)
        d31, d32, d33, d34 = group.random(ZR),group.random(ZR),group.random(ZR),group.random(ZR)
        d41, d42, d43, d44 = group.random(ZR),group.random(ZR),group.random(ZR),group.random(ZR)
        D11, D12, D13, D14 = group.init(ZR),group.init(ZR),group.init(ZR),group.init(ZR)
        D21, D22, D23, D24 = group.init(ZR),group.init(ZR),group.init(ZR),group.init(ZR)
        D31, D32, D33, D34 = group.init(ZR),group.init(ZR),group.init(ZR),group.init(ZR)
        D41, D42, D43, D44 = group.init(ZR),group.init(ZR),group.init(ZR),group.init(ZR)

        one = group.random(ZR)
        
        [D11, D12, D13, D14] = self.GaussEleminationinGroups([[d11, d12, d13, d14, one],
                                        [d21, d22, d23, d24, group.init(ZR, long(0))],
                                        [d31, d32, d33, d34, group.init(ZR, long(0))],
                                        [d41, d42, d43, d44, group.init(ZR, long(0))]])
        [D21, D22, D23, D24] = self.GaussEleminationinGroups([[d11, d12, d13, d14, group.init(ZR, long(0))],
                                        [d21, d22, d23, d24, one],
                                        [d31, d32, d33, d34, group.init(ZR, long(0))],
                                        [d41, d42, d43, d44, group.init(ZR, long(0))]])
        [D31, D32, D33, D34] = self.GaussEleminationinGroups([[d11, d12, d13, d14, group.init(ZR, long(0))],
                                        [d21, d22, d23, d24, group.init(ZR, long(0))],
                                        [d31, d32, d33, d34, one],
                                        [d41, d42, d43, d44, group.init(ZR, long(0))]])
        [D41, D42, D43, D44] = self.GaussEleminationinGroups([[d11, d12, d13, d14, group.init(ZR, long(0))],
                                        [d21, d22, d23, d24, group.init(ZR, long(0))],
                                        [d31, d32, d33, d34, group.init(ZR, long(0))],
                                        [d41, d42, d43, d44, one]])
        

        #generate public parameters.
        PP2 = (pair(g1, g2))**(alpha*one)
        gd11 = g1**d11
        gd12 = g1**d12
        gd13 = g1**d13
        gd14 = g1**d14
        gd21 = g1**d21
        gd22 = g1**d22
        gd23 = g1**d23
        gd24 = g1**d24
        pk = { 'PP2':PP2, 'gd11':gd11, 'gd12':gd12, 'gd13':gd13, 'gd14':gd14,
               'gd21':gd21, 'gd22':gd22, 'gd23':gd23, 'gd24':gd24 }
        #generate private parameters
        gD11 = g2**D11
        gD12 = g2**D12
        gD13 = g2**D13
        gD14 = g2**D14
        gD21 = g2**D21
        gD22 = g2**D22
        gD23 = g2**D23
        gD24 = g2**D24
        sk = { 'alpha':alpha, 'gD11':gD11, 'gD12':gD12, 'gD13':gD13, 'gD14':gD14,
               'gD21':gD21, 'gD22':gD22, 'gD23':gD23, 'gD24':gD24 }
        if(debug):
            print("Public parameters...")
            group.debug(pk)
            print("Secret parameters...")
            group.debug(sk)
        return (pk, sk)

    def sign(self, pk, sk, m):
        r = group.random(ZR)
        M = group.hash(m)
        s1 = (sk['gD11']**(sk['alpha']+r*M))/(sk['gD21']**r)
        s2 = (sk['gD12']**(sk['alpha']+r*M))/(sk['gD22']**r)
        s3 = (sk['gD13']**(sk['alpha']+r*M))/(sk['gD23']**r)
        s4 = (sk['gD14']**(sk['alpha']+r*M))/(sk['gD24']**r)
        
        signature = { 's1':s1, 's2':s2, 's3':s3, 's4':s4 }
        return signature
        
    def verify(self, pk, sig, m):
        M = group.hash(m)
        if pk['PP2'] == (pair(pk['gd11']*(pk['gd21']**M), sig['s1']) *
                         pair(pk['gd12']*(pk['gd22']**M), sig['s2']) *
                         pair(pk['gd13']*(pk['gd23']**M), sig['s3']) *
                         pair(pk['gd14']*(pk['gd24']**M), sig['s4']) ):
            return True
        return False
    
    def GaussEleminationinGroups(self, m):
        #eliminate columns
        for col in range(len(m[0])):
            for row in range(col+1, len(m)):
                r = [(rowValue * (-(m[row][col] / m[col][col]))) for rowValue in m[col]]
                m[row] = [ (pair[0]+pair[1]) for pair in zip(m[row], r)]
        #now backsolve by substitution
        ans = []
        m.reverse() #makes it easier to backsolve
        for sol in range(len(m)):
                if sol == 0:
                    ans.append(m[sol][-1] / m[sol][-2])
                else:
                    inner = 0
                    #substitute in all known coefficients
                    for x in range(sol):
                        inner += (ans[x]*m[sol][-2-x])
                    #the equation is now reduced to ax + b = c form
                    #solve with (c - b) / a
                    ans.append((m[sol][-1]-inner)/m[sol][-sol-2])
        ans.reverse()
        return ans

def main():
    groupObj = PairingGroup('MNT224')
    m = "plese sign this message!!!!"
    cllww = Sign_Chen12(groupObj)
    (pk, sk) = cllww.keygen()
    signature = cllww.sign(pk, sk, m)
    
    if debug: print("Signature :=", signature)

    assert cllww.verify(pk, signature, m), "Invalid Verification!!!!"
    if debug: print("Successful Individual Verification!")
    
if __name__ == "__main__":
    debug = True
    main()
