from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.urandom(32)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.OFB(iv))

encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

encrypted_message = encryptor.update(
    b'this is a sample test message used to check out if this thing will work as expected') + encryptor.finalize()

decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

print('Encrypted data: {0}\nDecrypted data: {1}'.format(
    encrypted_message, decrypted_message))
