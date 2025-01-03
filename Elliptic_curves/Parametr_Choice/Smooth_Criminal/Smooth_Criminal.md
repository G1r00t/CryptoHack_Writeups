## Challenge files 
Source Code : [Source](a.py)
Output File : [Output](1.txt)

So first we check that if the order of the curve is smooth or not

```sage
p = 310717010502520989590157367261876774703
a = 2
b = 3
Point = namedtuple("Point", "x y")
F = GF(p)
E = EllipticCurve(F,[a,b])
print(E.order())
print(factor(E.order()))
```
And Voila!
It prints `2^2 * 3^7 * 139 * 165229 * 31850531 * 270778799 * 179317983307`

So Finding dlog for all the factors using pohlig hellman attack we can solve this

Solve sage code
```

from Cryptodome.Cipher import AES
from Cryptodome.Util.number import inverse
from Cryptodome.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os
def check_point(P: tuple):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P: tuple, Q: tuple):
    # based of algo. in ICM
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P: tuple, n: int):
    # based of algo. in ICM
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


def gen_shared_secret(Q: tuple, n: int):
    # Bob's Public key, my secret int
    S = double_and_add(Q, n)
    return S.x

p = 310717010502520989590157367261876774703
a = 2
b = 3
Point = namedtuple("Point", "x y")
F = GF(p)
E = EllipticCurve(F,[a,b])
print(E.order())
print(factor(E.order()))


# Generator
g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = E.point((g_x, g_y))
n = randint(1, p)

p_x = 280810182131414898730378982766101210916
p_y = 291506490768054478159835604632710368904
P = E.point((p_x, p_y))
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317


factors, exps = zip(*factor(E.order()))
primes = [factors[i]^exps[i] for i in range(len(factors))]
print(primes)
dlogs = [] 
for fac in primes:
    t = int(G.order() / fac)
    dlog = discrete_log(t*P, t*G, operation="+")
    dlogs += [dlog]
    print("factor:", fac, "dlog:", dlog)

print(dlogs)
n = crt(dlogs, primes)
print(n * G == P)
print(n)

def decrypt(shared_secret: int, iv: str, encrypted: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    iv = bytes.fromhex(iv)
    encrypted = bytes.fromhex(encrypted)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted)
    return plaintext
iv = '07e2628b590095a5e332d397b8a59aa7'
encrypted_flag = '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'

b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = Point(b_x, b_y)

s = gen_shared_secret(B, n)
print(s)
print(decrypt(s, iv, encrypted_flag))
```

`crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}`