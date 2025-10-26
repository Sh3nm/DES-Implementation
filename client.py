import socket
import argparse
from des import des_encrypt_ecb, des_decrypt_ecb, des_encrypt_cbc, des_decrypt_cbc

def start_client(host, port, key, iv, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Connected to server {host}:{port} (mode: {mode.upper()})")

        while True:
            plaintext = input("Type message (or 'exit' for exit): ")
            if plaintext.lower() == 'exit':
                break

            # Enkripsi sesuai mode
            if mode == "cbc":
                cipher = des_encrypt_cbc(plaintext, key, iv)
            else:
                cipher = des_encrypt_ecb(plaintext, key)

            print(f" Message encrypted: {cipher}")
            s.sendall(cipher.encode('utf-8'))

            # Terima balasan
            data = s.recv(4096)
            if not data:
                break

            cipher_reply = data.decode('utf-8')
            if mode == "cbc":
                reply = des_decrypt_cbc(cipher_reply, key, iv)
            else:
                reply = des_decrypt_ecb(cipher_reply, key)

            print(f" Reply encrypted: {cipher_reply}")
            print(f" Reply decrypted: {reply}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client untuk komunikasi DES")
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="cbc", help="Mode enkripsi (ecb atau cbc)")
    parser.add_argument("--host", default="127.0.0.1", help="Alamat host server")
    parser.add_argument("--port", type=int, default=65432, help="Port server")
    parser.add_argument("--key", default="rahasiah", help="Kunci enkripsi (8 karakter)")
    parser.add_argument("--iv", default="12345678", help="Initialization Vector (8 karakter, untuk CBC)")

    args = parser.parse_args()
    start_client(args.host, args.port, args.key, args.iv, args.mode)
