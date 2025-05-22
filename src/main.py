import argparse
from simetrico import generar_clave, cifrar_archivo, descifrar_archivo

parser = argparse.ArgumentParser(description="Herramienta criptográfica")
subparsers = parser.add_subparsers(dest="comando")

parser_aes_enc = subparsers.add_parser("aes-encrypt")
parser_aes_enc.add_argument("--input", required=True)
parser_aes_enc.add_argument("--output", required=True)
parser_aes_enc.add_argument("--keyfile", required=True)


parser_genkey = subparsers.add_parser("generate-key")
parser_genkey.add_argument("--keyfile", required=True)
parser_genkey.add_argument("--bits", type=int, default=256)


parser_aes_dec = subparsers.add_parser("aes-decrypt")
parser_aes_dec.add_argument("--input", required=True)
parser_aes_dec.add_argument("--output", required=True)
parser_aes_dec.add_argument("--keyfile", required=True)

args = parser.parse_args()

if args.comando == "aes-encrypt":
    with open(args.keyfile, 'rb') as f:
        key = f.read()
    cifrar_archivo(args.input, args.output, key)

elif args.comando == "aes-decrypt":
    with open(args.keyfile, 'rb') as f:
        key = f.read()
    descifrar_archivo(args.input, args.output, key)

elif args.comando == "generate-key":
    key = generar_clave(bits=args.bits)
    with open(args.keyfile, 'wb') as f:
        f.write(key)
    print(f"Clave generada y guardada en {args.keyfile}")



