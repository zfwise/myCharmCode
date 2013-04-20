from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.crypto.cryptobase import *
from charm.toolbox.IBEnc import IBEnc
from charm.schemes.ibenc.ibenc_cllww12 import IBE_Chen12
from charm.schemes.ibenc.ibenc_cllww12_improved import IBE_Chen12_improved
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
from charm.schemes.ibenc.ibenc_ckrs09 import IBE_CKRS
from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke
from charm.schemes.ibenc.ibenc_waters05 import IBE_N04
from charm.schemes.ibenc.ibenc_waters05_improved import IBE_N04_improved
from charm.toolbox.hash_module import Waters
from charm.schemes.ibenc.ibenc_waters09_improved import DSE09_improved

import time
import string
import random

def randomStringGen(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

n = 200
#group = PairingGroup('MNT224')
group = PairingGroup('/home/zfwise/Downloads/pbc-0.5.12/param/f.param', param_file=True)

if(1):
    #ibe = IBE_Chen12(group)
    ibe = IBE_Chen12(group)
    #ID = 'user@email.com'
    cllwwSetupTime = 0.0
    cllwwExtTime = 0.0
    cllwwEncTime = 0.0
    cllwwDecTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (master_public_key, master_secret_key) = ibe.setup()
        cllwwSetupTime += time.time() - startTime
        
        ID = randomStringGen()
        startTime = time.time()
        private_key = ibe.extract(master_secret_key, ID)
        cllwwExtTime += time.time() - startTime

        msg = group.random(GT)
        startTime = time.time()
        cipher_text = ibe.encrypt(master_public_key, ID, msg)
        cllwwEncTime += time.time() - startTime

        startTime = time.time()
        decryptedMSG = ibe.decrypt(master_public_key, private_key, cipher_text)
        cllwwDecTime += time.time() - startTime
    print("\nJ. Chen, H. Lim, S. Ling, H. Wang, H. Wee Shorter IBE and Signatures via Asymmetric Pairings\", Section 4")
    #print("Group: MNT224")
    print("CLLWW12_ibe: Setup %d times, average time %f ms" %(n, cllwwSetupTime/n*1000))
    print("CLLWW12_ibe: Extract %d times, average time %f ms" %(n, cllwwExtTime/n*1000))
    print("CLLWW12_ibe: Enc random message %d times, average time %f ms" %(n, cllwwEncTime/n*1000))
    print("CLLWW12_ibe: Dec %d times, average time %f ms" %(n, cllwwDecTime/n*1000))
    print("&%.2f () &%.2f () &%.2f () &%.2f ()" %(cllwwSetupTime/n*1000,
                                                  cllwwExtTime/n*1000,
                                                  cllwwEncTime/n*1000,
                                                  cllwwDecTime/n*1000))
if(1):
    #ibe = IBE_Chen12(group)
    ibe = IBE_Chen12_improved(group)
    #ID = 'user@email.com'
    cllwwSetupTime = 0.0
    cllwwExtTime = 0.0
    cllwwEncTime = 0.0
    cllwwDecTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (master_public_key, master_secret_key) = ibe.setup()
        cllwwSetupTime += time.time() - startTime
        
        ID = randomStringGen()
        startTime = time.time()
        private_key = ibe.extract(master_secret_key, ID)
        cllwwExtTime += time.time() - startTime

        msg = group.random(GT)
        startTime = time.time()
        cipher_text = ibe.encrypt(master_public_key, ID, msg)
        cllwwEncTime += time.time() - startTime

        startTime = time.time()
        decryptedMSG = ibe.decrypt(master_public_key, private_key, cipher_text)
        cllwwDecTime += time.time() - startTime
    print("\nJ. Chen, H. Lim, S. Ling, H. Wang, H. Wee Shorter IBE and Signatures via Asymmetric Pairings\", Section 4")
    #print("Group: MNT224")
    print("CLLWW12_ibe_improved: Setup %d times, average time %f ms" %(n, cllwwSetupTime/n*1000))
    print("CLLWW12_ibe_improved: Extract %d times, average time %f ms" %(n, cllwwExtTime/n*1000))
    print("CLLWW12_ibe_improved: Enc random message %d times, average time %f ms" %(n, cllwwEncTime/n*1000))
    print("CLLWW12_ibe_improved: Dec %d times, average time %f ms" %(n, cllwwDecTime/n*1000))
    print("&%.2f () &%.2f () &%.2f () &%.2f ()" %(cllwwSetupTime/n*1000,
                                                  cllwwExtTime/n*1000,
                                                  cllwwEncTime/n*1000,
                                                  cllwwDecTime/n*1000))
##group=PairingGroup('MNT224', secparam=1024)
###group=PairingGroup('SS512', secparam=1024)
##ibe = IBE_BonehFranklin(group)
##BBibeSetupTime = 0.0
##BBibeExtTime = 0.0
##BBibeEncTime = 0.0
##BBibeDecTime = 0.0
###ID = 'user@email.com'
###msg = "hello world!!!!!"
##for i in range(0, n):
##    startTime = time.time()
##    (master_public_key, master_secret_key) = ibe.setup()
##    BBibeSetupTime += time.time() - startTime
##    
##    ID = randomStringGen()
##    startTime = time.time()
##    private_key = ibe.extract(master_secret_key, ID)
##    BBibeExtTime += time.time() - startTime
##
##    msg = randomStringGen()
##    startTime = time.time()
##    cipher_text = ibe.encrypt(master_public_key, ID, msg)
##    BBibeEncTime += time.time() - startTime
##    
##    startTime = time.time()
##    ibe.decrypt(master_public_key, private_key, cipher_text)
##    BBibeDecTime += time.time() - startTime
##print("\nD. Boneh, M. Franklin Identity-Based Encryption from the Weil Pairing\", Section 4.2")
###print("Group: MNT224")
##print("bb_ibe: Setup %d times, average time %f ms" %(n, BBibeSetupTime/n*1000))
##print("bb_ibe: Extract %d times, average time %f ms" %(n, BBibeExtTime/n*1000))
##print("bb_ibe: Enc random message %d times, average time %f ms" %(n, BBibeEncTime/n*1000))
##print("bb_ibe: Dec %d times, average time %f ms" %(n, BBibeDecTime/n*1000))

#group = PairingGroup('MNT224')
#group=PairingGroup('SS512')
if(1):
    ibe = IBE_BB04(group)
    BB04ibeSetupTime = 0.0
    BB04ibeExtTime = 0.0
    BB04ibeEncTime = 0.0
    BB04ibeDecTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (master_public_key, master_key) = ibe.setup()
        BB04ibeSetupTime += time.time() - startTime
        
        master_public_key_ID = group.random(ZR)    
        startTime = time.time()
        key = ibe.extract(master_key, master_public_key_ID)
        BB04ibeExtTime += time.time() - startTime

        msg = group.random(GT)
        startTime = time.time()
        cipher_text = ibe.encrypt(master_public_key, master_public_key_ID, msg)
        BB04ibeEncTime += time.time() - startTime
        
        startTime = time.time()
        decrypted_msg = ibe.decrypt(master_public_key, key, cipher_text)
        BB04ibeDecTime += time.time() - startTime
    print("\nD. Boneh, X. Boyen.  Efficient Selective Identity-Based Encryption Without Random Oracles\", Section 5.1")
    #print("Group: MNT224")
    print("bb04_ibe: Setup %d times, average time %f ms" %(n, BB04ibeSetupTime/n*1000))
    print("bb04_ibe: Extract %d times, average time %f ms" %(n, BB04ibeExtTime/n*1000))
    print("bb04_ibe: Enc random message %d times, average time %f ms" %(n, BB04ibeEncTime/n*1000))
    print("bb04_ibe: Dec %d times, average time %f ms" %(n, BB04ibeDecTime/n*1000))
    print("&%.2f () &%.2f () &%.2f () &%.2f ()" %(BB04ibeSetupTime/n*1000,
                                                  BB04ibeExtTime/n*1000,
                                                  BB04ibeEncTime/n*1000,
                                                  BB04ibeDecTime/n*1000))

###group = PairingGroup('SS512')
##group = PairingGroup('MNT224')
##ibe = IBE_CKRS(group)
##(master_public_key, master_secret_key) = ibe.setup()
##IBE_CKRSExtTime = 0.0
##IBE_CKRSEncTime = 0.0
##IBE_CKRSDecTime = 0.0
##for i in range(0, n):
##    ID = randomStringGen()   
##    startTime = time.time()
##    secret_key = ibe.extract(master_public_key, master_secret_key, ID)
##    IBE_CKRSExtTime += time.time() - startTime
##
##    msg = group.random(GT)
##    startTime = time.time()
##    cipher_text = ibe.encrypt(master_public_key, ID, msg)
##    IBE_CKRSEncTime += time.time() - startTime
##    
##    startTime = time.time()
##    decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
##    IBE_CKRSDecTime += time.time() - startTime
##print("\nJan Camenisch, Markulf Kohlweiss, Alfredo Rial, and Caroline Sheedy, Blind and Anonymous Identity-Based Encryption and Authorised Private Searches on Public Key Encrypted Data")
###print("Group: SS512")
##print("IBE_CKRS: Extract %d times, average time %f ms" %(n, IBE_CKRSExtTime/n*1000))
##print("IBE_CKRS: Enc random message %d times, average time %f ms" %(n, IBE_CKRSEncTime/n*1000))
##print("IBE_CKRS: Dec %d times, average time %f ms" %(n, IBE_CKRSDecTime/n*1000))

##group = PairingGroup('SS512')
###group = PairingGroup('MNT159')
##num_users = 5 # total # of users
##ibe = IBE_Revoke(group)
##(master_public_key, master_secret_key) = ibe.setup(num_users)
##ID = "user2@email.com"
##S = ["user1@email.com", "user3@email.com", "user4@email.com"]
##IBE_RevokeExtTime = 0.0
##IBE_RevokeEncTime = 0.0
##IBE_RevokeDecTime = 0.0
##for i in range(0, n):   
##    startTime = time.time()
##    secret_key = ibe.keygen(master_public_key, master_secret_key, ID)
##    IBE_RevokeExtTime += time.time() - startTime
##
##    msg = group.random(GT)
##    startTime = time.time()
##    cipher_text = ibe.encrypt(master_public_key, msg, S)
##    IBE_RevokeEncTime += time.time() - startTime
##    
##    startTime = time.time()
##    decrypted_msg = ibe.decrypt(S, cipher_text, secret_key)
##    IBE_RevokeDecTime += time.time() - startTime
##print("\nAllison Lewko, Amit Sahai and Brent Waters, Revocation Systems with Very Small Private Keys")
###print("Group: SS512")
##print("IBE_Revoke: Extract %d times, average time %f ms" %(n, IBE_RevokeExtTime/n*1000))
##print("IBE_Revoke: Enc random message %d times, average time %f ms" %(n, IBE_RevokeEncTime/n*1000))
##print("IBE_Revoke: Dec %d times, average time %f ms" %(n, IBE_RevokeDecTime/n*1000))


#group = PairingGroup('SS512')
#group = PairingGroup('MNT224')
if(1):
    waters_hash = Waters(group)
    ibe = IBE_N04(group)
    IBE_N04SetupTime = 0.0
    IBE_N04ExtTime = 0.0
    IBE_N04EncTime = 0.0
    IBE_N04DecTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (master_public_key, master_key) = ibe.setup()
        IBE_N04SetupTime += time.time() - startTime
        
        ID = randomStringGen() 
        kID = waters_hash.hash(ID)
        startTime = time.time()
        secret_key = ibe.extract(master_key, kID)
        IBE_N04ExtTime += time.time() - startTime

        msg = group.random(GT)
        startTime = time.time()
        cipher_text = ibe.encrypt(master_public_key, kID, msg)
        IBE_N04EncTime += time.time() - startTime
        
        startTime = time.time()
        decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
        IBE_N04DecTime += time.time() - startTime
    print("\nDavid Naccache Secure and Practical Identity-Based Encryption, Section 4")
    #print("Group: SS512")
    print("IBE_N04: Setup %d times, average time %f ms" %(n, IBE_N04SetupTime/n*1000))
    print("IBE_N04: Extract %d times, average time %f ms" %(n, IBE_N04ExtTime/n*1000))
    print("IBE_N04: Enc random message %d times, average time %f ms" %(n, IBE_N04EncTime/n*1000))
    print("IBE_N04: Dec %d times, average time %f ms" %(n, IBE_N04DecTime/n*1000))
    print("&%.2f () &%.2f () &%.2f () &%.2f ()" %(IBE_N04SetupTime/n*1000,
                                                  IBE_N04ExtTime/n*1000,
                                                  IBE_N04EncTime/n*1000,
                                                  IBE_N04DecTime/n*1000))
if(1):
    waters_hash = Waters(group)
    ibe = IBE_N04_improved(group)
    IBE_N04SetupTime = 0.0
    IBE_N04ExtTime = 0.0
    IBE_N04EncTime = 0.0
    IBE_N04DecTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (master_public_key, master_key) = ibe.setup()
        IBE_N04SetupTime += time.time() - startTime
        
        ID = randomStringGen() 
        kID = waters_hash.hash(ID)
        startTime = time.time()
        secret_key = ibe.extract(master_public_key, master_key, kID)
        IBE_N04ExtTime += time.time() - startTime

        msg = group.random(GT)
        startTime = time.time()
        cipher_text = ibe.encrypt(master_public_key, kID, msg)
        IBE_N04EncTime += time.time() - startTime
        
        startTime = time.time()
        decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
        IBE_N04DecTime += time.time() - startTime
    print("\nDavid Naccache Secure and Practical Identity-Based Encryption, Section 4")
    #print("Group: SS512")
    print("IBE_N04_improved: Setup %d times, average time %f ms" %(n, IBE_N04SetupTime/n*1000))
    print("IBE_N04_improved: Extract %d times, average time %f ms" %(n, IBE_N04ExtTime/n*1000))
    print("IBE_N04_improved: Enc random message %d times, average time %f ms" %(n, IBE_N04EncTime/n*1000))
    print("IBE_N04_improved: Dec %d times, average time %f ms" %(n, IBE_N04DecTime/n*1000))
    print("&%.2f () &%.2f () &%.2f () &%.2f ()" %(IBE_N04SetupTime/n*1000,
                                                  IBE_N04ExtTime/n*1000,
                                                  IBE_N04EncTime/n*1000,
                                                  IBE_N04DecTime/n*1000))
#group = PairingGroup('SS512')
#group = PairingGroup('SS512')
if(1):
    ibe = DSE09_improved(group)
    #ID = "user2@email.com"
    DSE09SetupTime = 0.0
    DSE09ExtTime = 0.0
    DSE09EncTime = 0.0
    DSE09DecTime = 0.0
    for i in range(0, n):
        startTime = time.time()
        (master_public_key, master_secret_key) = ibe.setup()
        DSE09SetupTime += time.time() - startTime
        
        ID = randomStringGen()
        startTime = time.time()
        secret_key = ibe.keygen(master_public_key, master_secret_key, ID)
        DSE09ExtTime += time.time() - startTime

        msg = group.random(GT)
        startTime = time.time()
        cipher_text = ibe.encrypt(master_public_key, msg, ID)
        DSE09EncTime += time.time() - startTime
        
        startTime = time.time()
        decrypted_msg = ibe.decrypt(cipher_text, secret_key)
        DSE09DecTime += time.time() - startTime
    print("\nDual System Encryption: Realizing Fully Secure IBE and HIBE under Simple Assumptions")
    #print("Group: SS512")
    print("DSE09: Setup %d times, average time %f ms" %(n, DSE09SetupTime/n*1000))
    print("DSE09: Extract %d times, average time %f ms" %(n, DSE09ExtTime/n*1000))
    print("DSE09: Enc random message %d times, average time %f ms" %(n, DSE09EncTime/n*1000))
    print("DSE09: Dec %d times, average time %f ms" %(n, DSE09DecTime/n*1000))
    print("&%.2f () &%.2f () &%.2f () &%.2f ()" %(DSE09SetupTime/n*1000,
                                                  DSE09ExtTime/n*1000,
                                                  DSE09EncTime/n*1000,
                                                  DSE09DecTime/n*1000))
