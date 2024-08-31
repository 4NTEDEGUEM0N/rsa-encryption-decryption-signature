import hashlib
import base64
import random
import math
import argparse

def is_prime(n, k=10):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def lcm(a, b):
    return abs(a * b) // gcd(a, b)



def generate_keys():
    bits = 1024
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    lambda_n = lcm(p-1, q-1)

    e = 65537
    #d = pow(e, -1, phi_n)
    d = pow(e, -1, lambda_n)
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    def generate_private_key_pem(p, q, e, d, n, output_file='private_key.pem'):
        # Reconstruir o objeto RSA private key
        private_key = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=(d % (p - 1)),
            dmq1=(d % (q - 1)),
            iqmp=(pow(q, -1, p)),
            public_numbers=rsa.RSAPublicNumbers(e, n)
        ).private_key()
        
        # Serializar a chave privada em formato PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Escrever a chave no arquivo
        with open(output_file, 'wb') as f:
            f.write(pem)


    def generate_public_key_pem(e, n, output_file='public_key.pem'):
        # Criar o objeto RSA public key
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
        
        # Serializar a chave pública em formato PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Escrever a chave no arquivo
        with open(output_file, 'wb') as f:
            f.write(pem)

    print("Chaves salvas em private_key.pem e public_key.pem")

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

def decode_private_key_pem(private_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Lê a chave privada do arquivo PEM
    with open(private_key, "rb") as f:
        chave_privada_pem = f.read()

    # Carrega a chave privada
    chave_privada = serialization.load_pem_private_key(
        chave_privada_pem,
        password=None
    )

    if not isinstance(chave_privada, rsa.RSAPrivateKey):
        raise ValueError("A chave privada não é do tipo RSA")

    # Obtém os parâmetros da chave privada
    private_numbers = chave_privada.private_numbers()
    d = private_numbers.d
    n = private_numbers.public_numbers.n

    return (d, n)


def decode_public_key_pem(public_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Lê a chave pública do arquivo PEM
    with open(public_key, "rb") as f:
        chave_publica_pem = f.read()

    # Carrega a chave pública
    chave_publica = serialization.load_pem_public_key(chave_publica_pem)

    if not isinstance(chave_publica, rsa.RSAPublicKey):
        raise ValueError("A chave pública não é do tipo RSA")

    # Obtém os parâmetros da chave pública
    public_numbers = chave_publica.public_numbers()
    e = public_numbers.e
    n = public_numbers.n

    return (e, n)


def encode_base64(data):
    return base64.b64encode(data).decode('utf-8')


def decode_base64(data):
    return base64.b64decode(data.encode('utf-8'))


def pkcs1_v1_5_pad(plaintext, key_size):
    padding_length = key_size - len(plaintext) - 1
    if padding_length < 8:
        raise ValueError("Plaintext too long to pad")
    padding = b'\x00\x02'
    while len(padding) < padding_length:
        byte = random.randbytes(1)
        if byte != b'\x00':
            padding += byte

    padding = padding + b'\x00'
    return padding + plaintext


def pkcs1_v1_5_unpad(plaintext):
    return plaintext[plaintext.index(b'\x00') + 1:]


def rsa_encrypt_file_base64(input_file_path, output_file_path, public_key):
    with open(input_file_path, 'rb') as file:
        file_data = file.read()
    key_size = 256
    file_data = pkcs1_v1_5_pad(file_data, key_size)

    message_int = int.from_bytes(file_data, 'big')
    cipher_int = pow(message_int, public_key[0], public_key[1])

    cipher_bytes = cipher_int.to_bytes(
        (math.ceil(cipher_int.bit_length() / 8)), 'big')
    cipher_b64 = encode_base64(cipher_bytes)

    with open(output_file_path, 'w') as file:
        file.write(cipher_b64)


def rsa_decrypt_file_base64(input_file_path, output_file_path, private_key):
    with open(input_file_path, 'r') as file:
        cipher_b64 = file.read()

    cipher_bytes = decode_base64(cipher_b64)
    cipher_int = int.from_bytes(cipher_bytes, 'big')

    message_int = pow(cipher_int, private_key[0], private_key[1])

    message = message_int.to_bytes(
        math.ceil(message_int.bit_length() / 8), 'big')

    message = pkcs1_v1_5_unpad(message)

    with open(output_file_path, 'wb') as file:
        file.write(message)


def sha3_hash_file(file_path):
    hash_object = hashlib.sha3_256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_object.update(chunk)
    return hash_object.digest()


def sign_file(file_path, private_key):
    file_hash = sha3_hash_file(file_path)
    hash_int = int.from_bytes(file_hash, 'big')
    signature = pow(hash_int, private_key[0], private_key[1])
    return signature


def save_signature(signature, output_path):
    signature_b64 = encode_base64(signature.to_bytes(
        (signature.bit_length() + 7) // 8, 'big'))
    with open(output_path, 'w') as sig_file:
        sig_file.write(signature_b64)


def verify_file_signature(file_path, signature_path, public_key):
    with open(signature_path, 'r') as sig_file:
        signature_b64 = sig_file.read()

    signature = int.from_bytes(decode_base64(signature_b64), 'big')
    hash_from_signature = pow(signature, public_key[0], public_key[1])
    original_hash = int.from_bytes(sha3_hash_file(file_path), 'big')

    return hash_from_signature == original_hash

# =-=-=-=-=-==--==-=-=-

def main():
    
    parser = argparse.ArgumentParser(description="Encrypt, decrypt and sing a file using RSA")
    
    parser.add_argument("operation", type=str, help='\"gen\" for key generation,\"enc\" for encryption, \"dec\" for decryption, \"sign\" for sign or \"verify\" for verify the signature')
    parser.add_argument("-in_file", type=str, required=False, help="Input file to be processed")
    parser.add_argument("-sign_file", type=str, required=False, help="Input file to be processed")
    parser.add_argument("-key", type=str, required=False, help="Key file to be used")
    
    args = parser.parse_args()
    
    operation = args.operation
    if operation == "gen":
        generate_keys()
    elif operation == "enc":
        file_path = args.in_file
        encrypted_file = file_path + ".encrypted"
        public_key = args.key
        public_key = decode_public_key_pem(public_key)
        rsa_encrypt_file_base64(file_path, encrypted_file, public_key)
        print(f"Arquivo {file_path} cifrado e salvo em {encrypted_file}")
    elif operation == "dec":
        encrypted_file = args.in_file
        decrypted_file = encrypted_file + ".decrypted"
        private_key = args.key
        private_key = decode_private_key_pem(private_key)
        rsa_decrypt_file_base64(encrypted_file, decrypted_file, private_key)
        print(f"Arquivo {encrypted_file} decifrado e salvo em {decrypted_file}")
    elif operation == "sign":
        file_path = args.in_file
        signature_file = file_path + ".signature"
        private_key = args.key
        private_key = decode_private_key_pem(private_key)
        signature = sign_file(file_path, private_key)
        save_signature(signature, signature_file)
        print("Assinatura salva em ", signature_file)
    elif operation == "verify":
        file_path = args.in_file
        signature_file = args.sign_file
        public_key = args.key
        public_key = decode_public_key_pem(public_key)
        is_valid = verify_file_signature(file_path, signature_file, public_key)
        print("Assinatura válida:", is_valid)
    else:
        print("Operação inválida")
        

if __name__ == '__main__':
    main()

