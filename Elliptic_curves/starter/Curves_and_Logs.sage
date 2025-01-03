a = 497
b = 1768
p = 9739
F = GF(p)
E = EllipticCurve(F, [a, b])
print(factor(E.order()))
# 3 * 5 * 11 * 59
from hashlib import sha1
QA = E(815, 3190)
nb = 1829
print(sha1(str((nb*QA)[0]).encode()).hexdigest()) 
# crypto{80e5212754a824d3a4aed185ace4f9cac0f908bf}