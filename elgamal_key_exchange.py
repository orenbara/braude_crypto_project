import random

# Elliptic curve parameters (using NIST P-256 curve)
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def mod_inverse(a, m):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - a * x - b) % p == 0

def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] == P2[0] and P1[1] != P2[1]:
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] + a) * mod_inverse(2 * P1[1], p)
    else:
        lam = (P2[1] - P1[1]) * mod_inverse(P2[0] - P1[0], p)
    x3 = (lam * lam - P1[0] - P2[0]) % p
    y3 = (lam * (P1[0] - x3) - P1[1]) % p
    return (x3, y3)

def scalar_mult(k, P):
    Q = None
    for i in range(256):
        if k & (1 << i):
            Q = point_add(Q, P)
        P = point_add(P, P)
    return Q

def generate_keypair():
    private_key = random.randint(1, n - 1)
    public_key = scalar_mult(private_key, (Gx, Gy))
    return private_key, public_key

def encrypt_key(public_key, plaintext):
    k = random.randint(1, n - 1)
    C1 = scalar_mult(k, (Gx, Gy))
    S = scalar_mult(k, public_key)
    C2 = (plaintext * S[0]) % p
    return (C1, C2)

def decrypt_key(private_key, ciphertext):
    C1, C2 = ciphertext
    S = scalar_mult(private_key, C1)
    plaintext = (C2 * mod_inverse(S[0], p)) % p
    return plaintext