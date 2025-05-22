from src.simetrico import generar_clave, cifrar_archivo, descifrar_archivo
import os

def test_cifrado_y_descifrado_temporal(tmp_path):
    clave = generar_clave()
    original = b"Texto de prueba para cifrado"
    input_file = tmp_path / "original.txt"
    encrypted_file = tmp_path / "cifrado.bin"
    decrypted_file = tmp_path / "descifrado.txt"

    input_file.write_bytes(original)
    cifrar_archivo(str(input_file), str(encrypted_file), clave)
    descifrar_archivo(str(encrypted_file), str(decrypted_file), clave)
