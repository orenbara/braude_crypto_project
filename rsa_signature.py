"""
RSA is a public-key crypto system used for secure data transmission and digital signatures.
It's based on the practical difficulty of factoring the product of two large prime numbers.
"""
import secrets

from elgamal_key_exchange import mod_inverse


def is_prime(n, k=5):
    """
    Determine if a number is prime using the Miller-Rabin primality test.
    
    Args:
        n (int): The number to test.
        k (int): The number of iterations for accuracy.
    
    Returns:
        bool: True if n is probably prime, False otherwise.
    """
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(k):
        a = secrets.randbelow(n - 1) + 1
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """
    Generate a random prime number of specified bit length.
    
    Args:
        bits (int): The bit length of the prime number.
    
    Returns:
        int: A prime number of the specified bit length.
    """
    while True:
        p = secrets.randbits(bits)
        if is_prime(p):
            return p

def generate_rsa_keypair(bits=2048):
    """
    Generate an RSA key pair.
    
    Args:
        bits (int): The bit length of the RSA modulus n.
    
    Returns:
        tuple: The public key (n, e) and the private key (n, d).
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    if d is None:
        raise ValueError("Modular inverse of e and phi is not found.")
    return (n, e), (n, d)

def rsa_sign(private_key, message):
    """
    Sign a message using the RSA private key.
    
    Args:
        private_key (tuple): The private key (n, d).
        message (bytes): The message to be signed.
    
    Returns:
        bytes: The signature.
    """
    n, d = private_key
    message_int = int.from_bytes(message, 'big')
    signature = pow(message_int, d, n)
    return signature.to_bytes((signature.bit_length() + 7) // 8, 'big')

def rsa_verify(public_key, message, signature):
    """
    Verify a message signature using the RSA public key.
    
    Args:
        public_key (tuple): The public key (n, e).
        message (bytes): The original message.
        signature (bytes): The signature to verify.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    n, e = public_key
    message_int = int.from_bytes(message, 'big')
    signature_int = int.from_bytes(signature, 'big')
    decrypted = pow(signature_int, e, n)
    return decrypted == message_int