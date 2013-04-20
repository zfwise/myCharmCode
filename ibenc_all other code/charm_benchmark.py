##from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
##from charm.core.math.pairing import InitBenchmark,StartBenchmark,EndBenchmark,GetBenchmark,GetGeneralBenchmarks,GetGranularBenchmarks,ClearBenchmark,RealTime,Mul,Div,Exp,Pair,Granular
##
##trials = 100
##group = PairingGroup("SS512")
##g = group.random(G1)
##h = group.random(G1)
##i = group.random(G2)
##
##ID = InitBenchmark()
##StartBenchmark(ID, [Mul, Exp, Pair, Granular])
##for a in range(trials):
##    j = g * h
##    k = i ** group.random(ZR)
##    t = (j ** group.random(ZR)) / h
##    n = pair(h, i)
##EndBenchmark(ID)
##
##msmtDict = GetGeneralBenchmarks(ID)
##granDict = GetGranularBenchmarks(ID)
##print granDict
##print granDict[Mul]
##print granDict[Exp]
###print granDict[Pair]
###print granDict[Granular]
##print msmtDict
##print("<=== General Benchmarks ===>")
##print("Results  := ", msmtDict)
##print("<=== Granular Benchmarks ===>")
##print("G1 mul   := ", granDict[Mul][G1])
##print("G2 exp   := ", granDict[Exp][G2])
##ClearBenchmark(ID)

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.math.pairing import InitBenchmark,StartBenchmark,EndBenchmark,GetBenchmark,GetGeneralBenchmarks,GetGranularBenchmarks,ClearBenchmark,RealTime,Mul,Div,Exp,Pair,Granular

trials = 100
group = PairingGroup("SS512")
g = group.random(G1)
h = group.random(G1)
i = group.random(G2)

ID = InitBenchmark()
StartBenchmark(ID, [Mul, Exp, Pair, Granular])
for a in range(trials):
    j = g * h
    k = i ** group.random(ZR)
    t = (j ** group.random(ZR)) / h
    n = pair(h, i)
EndBenchmark(ID)

msmtDict = GetGeneralBenchmarks(ID)
granDict = GetGranularBenchmarks(ID)
print("<=== General Benchmarks ===>")
print("Results  := ", msmtDict)
print("<=== Granular Benchmarks ===>")
print("G1 mul   := ", granDict[Mul][G1])
print("G2 exp   := ", granDict[Exp][G2])
ClearBenchmark(ID)
