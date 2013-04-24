\ibenc_z contains fully annotated code.
\pksig_z contains fully annotated code.
\ibenc_all other code and \pksig_all other code contains all my code. Details can be found at:http://student.seas.gwu.edu/~zfwise/crypto/, which is a webpage that list all the code and its functionalities.
\toolbox has the matrix operations over finite group

***********************************************
CLLWW12 is based on the paper: J. Chen, H. Lim, S. Ling, H. Wang, H. Wee Shorter IBE and Signatures via Asymmetric Pairings", Section 4. Published in: Pairing 2012

I made improvements to Waters 05 and Waters 09 schemes, both encryption and signature scheme. What I did can be found at the annotation, also, I have a benchmark report, which can be found at: http://student.seas.gwu.edu/~zfwise/crypto/

If you found my report, you can see that after the changes, waters 05 ibe and signature schemes are much more faster in asymmetric groups, which are MNT159 and MNT224. For Waters 09, only some minor changes have been made. Generally, Waters 09 ibe scheme didn't work under asymmetric group. I fixed it. 

And the CLLWW12 schemes have different versions. Generally speaking, if the annotation in the file talks about swap, it means I swapped G1 group and G2 group. In curves like MNT and BN, operations in G2 are expensive. I swapped the groups for better efficiency. 

***************************************************
Here are some other issues I want to share:
1. Here is a bug I found when I was using the ABE schemes (The following paragraphs are copied directly from my developing notes.): if there are multiple involvement of an attr, which means an attr been used more than once, Charm will add an extension to the attrs name. For example, (ONE or TWO) and (TWO or THREE), the Charm will have ONE, TWO_0, TWO_1, THREE. One has to notice that the TWO_0 and TWO_1 are different(have different shares). In decryption, if the receiver has TWO, the receiver can decrypt both. But which one to DEC eventually? It depends on the tree. If only one of the 'TWO' is required, the DEC will only take one of the 'TWO' that satisfies the access structure. For example, the receiver has [ONE, TWO], the the decryptor will use ONE, TWO_1

Here is a bug. I think Charm use some string concatenation to do the extension. If my system has an attr called FanZhang_1, this will not work. Charm will think FanZhang_1 in an AS as FanZhang. If we use string concatenation here, we should banned the use of attribute that has a name ended with "_numbers", for example, "FanZhang_1" should not be an attribute! Maybe we need a filter in the code that processing the access tree and user's attributes.

2. I talked to Joseph before that the Exp in G2 are expensive. In MNT curves, Exp in G2 takes longer than Pairing. There is an optimization in PBC library, which is called pre-processing. I looked into the pre-processing and the result is disappointing. There is a section called "Exponential, Multiplication and Pairing in pre-processing, PBC library", which talks about this problem in detail. The short conclusion here is that in PBC, pre-processing saves time. However, the pre-processing itself takes longer. 
