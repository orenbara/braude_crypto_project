import os
import hashlib

from elgamal_key_exchange import *
from rsa_signature import *
from salsa20_in_ofb_mode import *

import os


def main():
    try:
        print("Generating RSA keypair...")
        rsa_public_key, rsa_private_key = generate_rsa_keypair()
        print("RSA keypair generated successfully.")

        print("Generating EC keypair...")
        ec_private_key, ec_public_key = generate_keypair()
        print(f"EC private key: {ec_private_key}")
        print(f"EC public key: {ec_public_key}")
        print("EC keypair generated successfully.")

        print("Generating SALSA20 key...")
        salsa_key = os.urandom(32)
        print(f"SALSA20 key: {salsa_key.hex()}")
        print("SALSA20 key generated successfully.")

        print("Encrypting SALSA20 key with EC El-Gamal...")
        encrypted_key = encrypt_key(ec_public_key, salsa_key)
        print(f"Encrypted key: {encrypted_key}")
        print("SALSA20 key encrypted successfully.")

        print("Signing the encrypted key with RSA...")
        signature = rsa_sign(rsa_private_key, str(encrypted_key).encode())
        print(f"Signature: {signature.hex()}")
        print("Signature created successfully.")

        print("Encrypting file...")
        input_file = 'input.txt'
        if not os.path.exists(input_file):
            print(f"'{input_file}' not found. Creating a test file.")
            with open(input_file, 'w') as f:
                f.write("This is a test file for encryption and decryption.")

        encrypt_file(input_file, 'encrypted.bin', salsa_key)
        print("File encrypted successfully.")

        print("\nSimulating receiver's side:")
        print("Verifying signature...")
        if rsa_verify(rsa_public_key, str(encrypted_key).encode(), signature):
            print("Signature verified successfully")

            print("Decrypting SALSA20 key...")
            decrypted_key = decrypt_key(ec_private_key, encrypted_key)
            #recovered_salsa_key = decrypted_key.to_bytes(32, 'big')
            print(f"Recovered SALSA20 key: {decrypted_key.hex()}")
            print("SALSA20 key decrypted successfully.")

            print("Decrypting file...")
            decrypt_file('encrypted.bin', 'decrypted.txt', decrypted_key)
            print("File decrypted successfully")

            # Verify the decrypted content
            with open(input_file, 'r') as f_in, open('decrypted.txt', 'r') as f_out:
                original = f_in.read()
                decrypted = f_out.read()
                if original == decrypted:
                    print("Decryption successful: original and decrypted files match.")
                else:
                    print("Decryption failed: original and decrypted files do not match.")
        else:
            print("Signature verification failed")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()