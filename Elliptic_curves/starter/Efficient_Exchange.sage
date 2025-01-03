a = 497
b = 1768
p = 9739
F = GF(p)
E = EllipticCurve(F, [a, b])
print(factor(E.order()))
# 3 * 5 * 11 * 59
x = 4726
print((x^3 + a*x + b)%p)
#5507
# Since p = 3mod4
exp = (p+1)//4
y = pow(5507,exp,p)
print(y)
print(-y%p)
# 6287 
# 3452
Q = E(4726,6287)
nb = 6534
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16)
    else:
        return plaintext

secret = (nb*(Q))[0]
iv = "cd9da9f1c60925922377ea952afc212c"
ct = "febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8"

print(decrypt_flag(secret, iv, ct))
# crypto{3ff1c1ent_k3y_3xch4ng3}