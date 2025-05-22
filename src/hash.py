from cryptography.hazmat.primitives import hashes
import os

def calcular_hash_archivo(ruta_archivo):
    """Calcula el hash SHA-256 de un archivo."""
    digest = hashes.Hash(hashes.SHA256())
    with open(ruta_archivo, 'rb') as f:
        while chunk := f.read(8192):
            digest.update(chunk)
    return digest.finalize()

def verificar_integridad(ruta_archivo, hash_original):
    """Verifica si el hash actual del archivo coincide con el hash original."""
    hash_actual = calcular_hash_archivo(ruta_archivo)
    return hash_actual == hash_original

def guardar_hash(ruta_archivo, ruta_hash):
    """Calcula y guarda el hash de un archivo."""
    hash_valor = calcular_hash_archivo(ruta_archivo)
    with open(ruta_hash, 'wb') as f:
        f.write(hash_valor)
    return hash_valor

def verificar_hash_guardado(ruta_archivo, ruta_hash):
    """Verifica la integridad usando un hash guardado previamente."""
    with open(ruta_hash, 'rb') as f:
        hash_original = f.read()
    return verificar_integridad(ruta_archivo, hash_original)
