a = 497
b = 1768
p = 9739
F = GF(p)
E = EllipticCurve(F, [a, b])
p_x = 8045
p_y = 6936
P = E(p_x,p_y)
print(P)
#(8045 : 6936 : 1)
print(-1*P)
(#8045 : 2803 : 1)
#crypto{8045,2803}