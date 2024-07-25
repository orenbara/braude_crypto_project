import hashlib
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

def point_sub(P1, P2):
    neg_P2 = (P2[0], -P2[1] % p)
    return point_add(P1, neg_P2)

"""
This uses the double-and-add algorithm, an efficient method for scalar multiplication
Scalar multiplication involves computing the product of a scalar (integer) k and a point P on an elliptic curve 
to obtain another point Q on the curve, denoted as Q=kP This operation is analogous to repeated addition in the 
context of elliptic curves.
"""
def scalar_mult(k, P):
    Q = None
    for i in range(256):
        if k & (1 << i):
            Q = point_add(Q, P)
        P = point_add(P, P)
    return Q


"""
Generate an ECC key pair
"""
def generate_keypair():
    # Chooses a random integer as the private key
    private_key = random.randint(1, n - 1)

    # Computes the public key by multiplying the generator point (Gx, Gy) by the private key.
    public_key = scalar_mult(private_key, (Gx, Gy))
    return private_key, public_key

"""
Encrypt a message (in this case, the SALSA20 key) using ECC El-Gamal encryption
"""

def encode_plaintext_as_point(plaintext):
    # Ensure plaintext is 32 bytes long
    assert len(plaintext) == 32, "Plaintext must be exactly 32 bytes"
    x = int.from_bytes(plaintext, byteorder='big') % p
    while True:
        y_square = (x * x * x + a * x + b) % p
        y = pow(y_square, (p + 1) // 4, p)  # This is (p + 1) / 4 for P-256 curve
        if (y * y) % p == y_square:
            return (x, y)
        x = (x + 1) % p


def decode_point_as_plaintext(point):
    x, y = point
    return x.to_bytes(32, byteorder='big')


def encrypt_key(public_key, plaintext):
    # Ensure plaintext is exactly 32 bytes long
    assert len(plaintext) == 32, "Plaintext must be exactly 32 bytes"

    # Convert plaintext to elliptic curve point
    plaintext_point = encode_plaintext_as_point(plaintext)

    # Chooses a random k for this encryption.
    k = random.randint(1, n - 1)
    C1 = scalar_mult(k, (Gx, Gy))
    S = scalar_mult(k, public_key)

    # Add the plaintext point to S to form C2
    C2 = point_add(plaintext_point, S)
    return (C1, C2)
"""
def decrypt_key(private_key, ciphertext):
    C1, C2 = ciphertext
    S = scalar_mult(private_key, C1)
    plaintext_converted_to_point = point_sub(C2, S)

    decrypted_decoded_point = decode_point_as_plaintext(plaintext_converted_to_point)

    # Convert the point back to bytes
    x = plaintext_converted_to_point[0].to_bytes(32, byteorder='big')
    y = plaintext_converted_to_point[1].to_bytes(32, byteorder='big')
    hashed_value = x + y

    plaintext = hashed_value[:32]  # Since only the first 32 bytes were originally used as plaintext
    return plaintext
"""


def decrypt_key(private_key, ciphertext):
    C1, C2 = ciphertext
    S = scalar_mult(private_key, C1)

    # Subtract S from C2 to get the original plaintext point
    plaintext_point = point_sub(C2, S)

    # Convert the elliptic curve point back to plaintext
    plaintext = decode_point_as_plaintext(plaintext_point)
    return plaintext