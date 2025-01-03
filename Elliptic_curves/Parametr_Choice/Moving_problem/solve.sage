import logging
import hashlib
from math import gcd
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from sage.all import GF, EllipticCurve

def get_suitable_random_point(Ek, n):
    Q = Ek.random_point()
    m = Q.order()
    d = gcd(m, n)
    Q = (m // d) * Q
    return Q if Q.order() == n else None


def mov_attack(G, P, max_k: int = 20, max_tries: int = 15):
    E = G.curve()
    q = E.base_ring().order()
    n = G.order()
    for k in range(1, max_k + 1):
        if (q**k - 1) % n == 0:
            break
    Ek = E.base_extend(GF(q ** k))
    Gk = Ek(G)
    Pk = Ek(P)
    for _ in range(max_tries):
        Q = get_suitable_random_point(Ek, n)
        if Q is None:
            continue    
        alpha = Gk.weil_pairing(Q, n)
        if alpha == 1:
            continue   
        beta = Pk.weil_pairing(Q, n)
        discrete_log = beta.log(alpha)
        if G * int(discrete_log) == P:
            return int(discrete_log)            
    return None

def gen_shared_secret(P, n):
    S = P * n
    return S.xy()[0]

def decrypt_flag(shared_secret: int, encrypted_data: dict):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    iv = bytes.fromhex(encrypted_data['iv'])
    ciphertext = bytes.fromhex(encrypted_data['encrypted_flag'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)
    return decrypted
p = 1331169830894825846283645180581
a = -35
b = 98
E = EllipticCurve(GF(p), [a,b])
G = E(479691812266187139164535778017, 568535594075310466177352868412)
P1 = E(1110072782478160369250829345256, 800079550745409318906383650948)  # Alice's public key
P2 = E(1290982289093010194550717223760, 762857612860564354370535420319)  # Bob's public key

encrypted_flag = {
    'iv': 'eac58c26203c04f68d63dc2c58d79aca',
    'encrypted_flag': 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'
}

n_b = mov_attack(G, P2)
secret = gen_shared_secret(P1, n_b)
print(secret)
flag = decrypt_flag(secret, encrypted_flag)
print(flag)
