import struct
import os

# Constants for SALSA20
ROUNDS = 20

# Rotate left operation for 32-bit integers
def rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

# Perform a quarter round of the Salsa20 algorithm
def quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff
    d ^= rotl32(a, 16)
    c = (c + d) & 0xffffffff
    b ^= rotl32(c, 12)
    a = (a + b) & 0xffffffff
    d ^= rotl32(a, 8)
    c = (c + d) & 0xffffffff
    b ^= rotl32(c, 7)
    return a, b, c, d


# Generate a Salsa20 block
def salsa20_block(input_block):
    # Pad the input to 64 bytes if necessary
    input_block = input_block.ljust(64, b'\x00')
    # Unpack the input block into 16 32-bit integers
    x = list(struct.unpack('<16I', input_block))
    orig_x = x[:]

    for _ in range(ROUNDS):
        # Column rounds
        x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12])
        x[5], x[9], x[13], x[1] = quarter_round(x[5], x[9], x[13], x[1])
        x[10], x[14], x[2], x[6] = quarter_round(x[10], x[14], x[2], x[6])
        x[15], x[3], x[7], x[11] = quarter_round(x[15], x[3], x[7], x[11])

        # Diagonal rounds
        x[0], x[1], x[2], x[3] = quarter_round(x[0], x[1], x[2], x[3])
        x[5], x[6], x[7], x[4] = quarter_round(x[5], x[6], x[7], x[4])
        x[10], x[11], x[8], x[9] = quarter_round(x[10], x[11], x[8], x[9])
        x[15], x[12], x[13], x[14] = quarter_round(x[15], x[12], x[13], x[14])

    # Add the original state to the new state
    for i in range(16):
        x[i] = (x[i] + orig_x[i]) & 0xffffffff

    # Pack the state back into a 64-byte block
    return struct.pack('<16I', *x)

# Salsa20 encryption function
def salsa20_encrypt(key, nonce, plaintext):
    # Check key and nonce lengths
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("Key must be 32 bytes and nonce must be 8 bytes")

    keystream = b''
    counter = 0
    while len(keystream) < len(plaintext):
        # Generate a counter block
        counter_bytes = struct.pack('<Q', counter)
        block = key[:16] + nonce + counter_bytes + key[16:]
        # Append the generated block to the keystream
        keystream += salsa20_block(block)
        counter += 1

    # XOR the plaintext with the keystream to produce the ciphertext
    return bytes(a ^ b for a, b in zip(plaintext, keystream))

# Salsa20 decryption function (identical to encryption in OFB mode)
def salsa20_decrypt(key, nonce, ciphertext):
    return salsa20_encrypt(key, nonce, ciphertext)

# OFB mode encryption function
def ofb_mode_encrypt(key, iv, plaintext):
    block_size = 64  # Salsa20 block size
    # Split the plaintext into blocks of block_size
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    ciphertext = b''
    previous_block = iv

    for block in blocks:
        # Generate a keystream block
        keystream = salsa20_encrypt(key, previous_block[:8], b'\x00' * block_size)[:len(block)]
        # XOR the block with the keystream to produce the ciphertext block
        cipher_block = bytes(a ^ b for a, b in zip(block, keystream))
        ciphertext += cipher_block
        # Use the first 8 bytes of the keystream as the next IV
        previous_block = keystream[:8]

    return ciphertext

# OFB mode decryption function (identical to encryption in OFB mode)
def ofb_mode_decrypt(key, iv, ciphertext):
    return ofb_mode_encrypt(key, iv, ciphertext)

# File encryption function
def encrypt_file(input_file, output_file, key):
    # Generate a random IV
    iv = os.urandom(8)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        plaintext = f_in.read()
        # Encrypt the file contents
        ciphertext = ofb_mode_encrypt(key, iv, plaintext)
        # Write the IV and the ciphertext to the output file
        f_out.write(iv + ciphertext)

# File decryption function
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        # Read the IV from the input file
        iv = f_in.read(8)
        ciphertext = f_in.read()
        # Decrypt the file contents
        plaintext = ofb_mode_decrypt(key, iv, ciphertext)
        # Write the plaintext to the output file
        f_out.write(plaintext)
