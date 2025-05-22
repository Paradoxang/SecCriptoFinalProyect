import argparse
from simetrico import generar_clave, cifrar_archivo, descifrar_archivo
from asimetrico import generar_claves_rsa, cifrar_con_rsa, descifrar_con_rsa
from firma import firmar_datos, verificar_firma
from hash import calcular_hash_archivo, guardar_hash, verificar_hash_guardado
from cryptography.hazmat.primitives import serialization

def guardar_clave_privada(private_key, ruta):
    with open(ruta, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def guardar_clave_publica(public_key, ruta):
    with open(ruta, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def cargar_clave_privada(ruta):
    with open(ruta, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def cargar_clave_publica(ruta):
    with open(ruta, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

parser = argparse.ArgumentParser(description="Herramienta criptográfica")
subparsers = parser.add_subparsers(dest="comando")

# Comandos para cifrado simétrico (AES)
parser_aes_gen = subparsers.add_parser("aes-generate-key")
parser_aes_gen.add_argument("--keyfile", required=True)
parser_aes_gen.add_argument("--bits", type=int, default=256, choices=[128, 192, 256])

parser_aes_enc = subparsers.add_parser("aes-encrypt")
parser_aes_enc.add_argument("--input", required=True)
parser_aes_enc.add_argument("--output", required=True)
parser_aes_enc.add_argument("--keyfile", required=True)

parser_aes_dec = subparsers.add_parser("aes-decrypt")
parser_aes_dec.add_argument("--input", required=True)
parser_aes_dec.add_argument("--output", required=True)
parser_aes_dec.add_argument("--keyfile", required=True)

# Comandos para cifrado asimétrico (RSA)
parser_rsa_gen = subparsers.add_parser("rsa-generate-keys")
parser_rsa_gen.add_argument("--private-key", required=True)
parser_rsa_gen.add_argument("--public-key", required=True)

parser_rsa_enc = subparsers.add_parser("rsa-encrypt")
parser_rsa_enc.add_argument("--input", required=True)
parser_rsa_enc.add_argument("--output", required=True)
parser_rsa_enc.add_argument("--public-key", required=True)

parser_rsa_dec = subparsers.add_parser("rsa-decrypt")
parser_rsa_dec.add_argument("--input", required=True)
parser_rsa_dec.add_argument("--output", required=True)
parser_rsa_dec.add_argument("--private-key", required=True)

# Comandos para firma digital
parser_sign = subparsers.add_parser("sign")
parser_sign.add_argument("--input", required=True)
parser_sign.add_argument("--signature-file", required=True)
parser_sign.add_argument("--private-key", required=True)

parser_verify = subparsers.add_parser("verify")
parser_verify.add_argument("--input", required=True)
parser_verify.add_argument("--signature-file", required=True)
parser_verify.add_argument("--public-key", required=True)

# Comandos para hash
parser_hash = subparsers.add_parser("hash")
parser_hash.add_argument("--input", required=True)
parser_hash.add_argument("--output", required=True)

parser_verify_hash = subparsers.add_parser("verify-hash")
parser_verify_hash.add_argument("--input", required=True)
parser_verify_hash.add_argument("--hash-file", required=True)

args = parser.parse_args()

if args.comando == "aes-generate-key":
    key = generar_clave(bits=args.bits)
    with open(args.keyfile, 'wb') as f:
        f.write(key)
    print(f"Clave AES de {args.bits} bits generada y guardada en {args.keyfile}")

elif args.comando == "aes-encrypt":
    with open(args.keyfile, 'rb') as f:
        key = f.read()
    cifrar_archivo(args.input, args.output, key)
    print(f"Archivo cifrado guardado en {args.output}")

elif args.comando == "aes-decrypt":
    with open(args.keyfile, 'rb') as f:
        key = f.read()
    descifrar_archivo(args.input, args.output, key)
    print(f"Archivo descifrado guardado en {args.output}")

elif args.comando == "rsa-generate-keys":
    private_key, public_key = generar_claves_rsa()
    guardar_clave_privada(private_key, args.private_key)
    guardar_clave_publica(public_key, args.public_key)
    print(f"Par de claves RSA generadas:\nPrivada: {args.private_key}\nPública: {args.public_key}")

elif args.comando == "rsa-encrypt":
    public_key = cargar_clave_publica(args.public_key)
    with open(args.input, 'rb') as f:
        mensaje = f.read()
    cifrado = cifrar_con_rsa(mensaje, public_key)
    with open(args.output, 'wb') as f:
        f.write(cifrado)
    print(f"Mensaje cifrado con RSA guardado en {args.output}")

elif args.comando == "rsa-decrypt":
    private_key = cargar_clave_privada(args.private_key)
    with open(args.input, 'rb') as f:
        cifrado = f.read()
    mensaje = descifrar_con_rsa(cifrado, private_key)
    with open(args.output, 'wb') as f:
        f.write(mensaje)
    print(f"Mensaje descifrado con RSA guardado en {args.output}")

elif args.comando == "sign":
    private_key = cargar_clave_privada(args.private_key)
    with open(args.input, 'rb') as f:
        data = f.read()
    firma = firmar_datos(data, private_key)
    with open(args.signature_file, 'wb') as f:
        f.write(firma)
    print(f"Firma digital guardada en {args.signature_file}")

elif args.comando == "verify":
    public_key = cargar_clave_publica(args.public_key)
    with open(args.input, 'rb') as f:
        data = f.read()
    with open(args.signature_file, 'rb') as f:
        firma = f.read()
    if verificar_firma(data, firma, public_key):
        print("La firma es válida")
    else:
        print("La firma NO es válida")
        exit(1)

elif args.comando == "hash":
    hash_valor = guardar_hash(args.input, args.output)
    print(f"Hash SHA-256 guardado en {args.output}")

elif args.comando == "verify-hash":
    if verificar_hash_guardado(args.input, args.hash_file):
        print("La integridad del archivo es correcta")
    else:
        print("¡ADVERTENCIA! El archivo ha sido modificado")
        exit(1)
