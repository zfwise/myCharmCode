from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.math.pairing import hashPair as sha1
from charm.toolbox.IBEnc import IBEnc
from charm.core.crypto.cryptobase import *
from charm.adapters.ibenc_adapt_hybrid import HybridIBEnc
from charm.schemes.ibenc.ibenc_clw12 import IBE_Chen12
from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04

group = PairingGroup('MNT224')
ibe = IBE_Chen12(group)
hyb_ibe = HybridIBEnc(ibe, group)
(master_public_key, master_key) = hyb_ibe.setup()
ID = 'waldoayo@gmail.com'
secret_key = hyb_ibe.extract(master_key, ID)
msg = b"Hello World My name is blah blah!!!! Word!"
cipher_text = hyb_ibe.encrypt(master_public_key, ID, msg)
decrypted_msg = hyb_ibe.decrypt(master_public_key, secret_key, cipher_text)
print(decrypted_msg == msg)
