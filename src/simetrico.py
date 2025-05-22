from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def generar_clave(bits=256):
    return os.urandom(bits // 8)

def cifrar_archivo(input_path, output_path, key, modo='CBC'):
    with open(input_path, 'rb') as f:
        datos = f.read()

    iv = os.urandom(16)
    if modo == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(128).padder()
        datos = padder.update(datos) + padder.finalize()
    else:
        raise ValueError("Modo no soportado")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(datos) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)

def descifrar_archivo(input_path, output_path, key, modo='CBC'):
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    if modo == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError("Modo no soportado")

    decryptor = cipher.decryptor()
    datos = decryptor.update(ciphertext) + decryptor.finalize()

    if modo == 'CBC':
        unpadder = padding.PKCS7(128).unpadder()
        datos = unpadder.update(datos) + unpadder.finalize()

    with open(output_path, 'wb') as f:
        f.write(datos)