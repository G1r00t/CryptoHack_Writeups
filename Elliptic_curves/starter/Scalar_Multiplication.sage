a = 497
b = 1768
p = 9739
F = GF(p)
E = EllipticCurve(F, [a, b])
x = 2339
y = 2213
R = E(x,y)
print(7863*R)
#crypto{9467,2742}