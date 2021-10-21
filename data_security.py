import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import secrets

"""
There are some ways this module can encrypt/hash the data.
WARNING: all the functions here operate on BYTES, not STRINGS.
Be sure to encode the strings into byte arrays before putting them here.
1) SHA-512 hash with salt (secure_data_hash)
    * Function can generate secure salt if it's not supplied by user
    * Function returns the hash and used salt as tuple pair
2) encrypted HMAC (secure_data_hmac)
  * returns SHA-512 based HMAC
  * uses provided secret key
3) AES-OFB encrypted data (encrypt_data_aes/decrypt_data_aes)
  * The provided datas MD5 hash is used as AES key
  * AES IV is stored as first 16 bytes, prepended to the encrypted data
4) AES-OFB encrypted SHA-512 hash with salt (secure_data_encrypted_hash/compare_data_encrypted_hash)
    * First, SHA-512 hash with salt is calculated, then it's encrypted
    * uses secure_data_hash and encrypt_data_aes functions
    * to compare raw data with encrypted hash, use compare_data_encrypted_hash
"""


def secure_data_hash(data: bytes, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Hashes the provided data with salt

    Args:
        data (bytes): data to be secured
        salt (bytes): optional, salt for the algorithm

    Returns:
        Tuple[bytes, bytes]: Pair of data hash and the salt
    """
    if salt is None or len(salt) != 16:
        salt = secrets.token_bytes(16)

    hashed_data = hashlib.sha512(salt + data).digest()
    return hashed_data, salt


def secure_data_hmac(data: bytes, key: bytes) -> bytes:
    """Hashes and encrypts the data using HMAC

    Args:
        data (bytes): data to be secured
        key (bytes): crypto key used for hashing

    Returns:
        bytes: data HMAC
    """
    return hmac.digest(key, data, 'sha512')


def encrypt_data_aes(data: bytes, key: bytes) -> bytes:
    """Encrypts the data using AES OFB. Generated random IV which is prepended to the beginning of encrypted data

    Args:
        data (bytes): data to be secured
        key (bytes): crypto key used for encryption

    Returns:
        bytes: encrypted data with first 16 bytes being init vector for AES
    """
    init_vector = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.OFB(init_vector))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(data) + encryptor.finalize()
    return init_vector + encrypted_message


def decrypt_data_aes(encrypted_data_with_iv: bytes, key: bytes) -> bytes:
    """Decrypts the passowrd using AES OFB. First 16 bytes of encrypted datas are used as IV for AES.

    Args:
        encrypted_data (bytes): encrypted data with IV
        key (bytes): crypto key used for decryption

    Returns:
        bytes: decrypted data
    """
    init_vector, encrypted_data = encrypted_data_with_iv[:16], encrypted_data_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.OFB(init_vector))
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_message


def secure_data_encrypted_hash(data: bytes, key: bytes, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Hashes and encrypts the data using provided key and optional salt. Uses secure_data_hash and encrypt_data_aes functions.

    Args:
        data (bytes): Data to be hashed and encrypted
        salt (bytes, optional): Hashing salt. Defaults to None.

    Returns:
        Tuple[bytes, bytes]: A pair of hashed and encrypted data, and a salt
    """
    hashed_data, salt = secure_data_hash(data, salt)
    encrypted_data = encrypt_data_aes(hashed_data, key)
    return encrypted_data, salt


def compare_data_encrypted_hash(compared_data: bytes, encrypted_data: bytes, salt: bytes, key: bytes) -> bool:
    """Compares the raw bytes with encrypted data hash and returns if they're the same

    Args:
        compared_data (bytes): Raw data to be compared
        encrypted_data (bytes): Encrypted hash with IV
        salt (bytes): salt used for hashing
        key (bytes): crypto key used for decryption

    Returns:
        bool: True if data is the same, otherwise false
    """
    decrypted_data = decrypt_data_aes(encrypted_data, key)
    compared_data_hash = secure_data_hash(compared_data, salt)[0]
    return decrypted_data == compared_data_hash


def run_tests():
    test_string = 'hello there'
    test_string_different = 'the second message'
    encryption_key = secrets.token_bytes(32)

    hashed_test_string_1, hashed_test_string_salt = secure_data_hash(
        test_string.encode('ASCII'))
    hashed_test_string_2, _ = secure_data_hash(
        test_string.encode('ASCII'), hashed_test_string_salt)

    print('First hash:\t{0}\nSecond hash:\t{1}'.format(
        hashed_test_string_1, hashed_test_string_2))
    print('Are the hashes of the same data with the same salt equal? {0}'.format(
        hashed_test_string_1 == hashed_test_string_2))

    encrypted_data = encrypt_data_aes(
        test_string_different.encode('ASCII'), encryption_key)
    decrypted_data = decrypt_data_aes(encrypted_data, encryption_key)

    print('Encrypted data: {0}\nDecrypted data: {1}'.format(
        encrypted_data, decrypted_data))

    encrypted_hash, encrypted_hash_salt = secure_data_encrypted_hash(
        test_string_different.encode('ASCII'), encryption_key)
    print('Is encrypted hash checking working? {0} and {1}'.format(compare_data_encrypted_hash(
        test_string_different.encode('ASCII'), encrypted_hash, encrypted_hash_salt, encryption_key),
        not compare_data_encrypted_hash(test_string.encode('ASCII'), encrypted_hash, encrypted_hash_salt, encryption_key)))


if __name__ == '__main__':
    run_tests()
