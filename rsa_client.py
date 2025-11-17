import socket
import argparse
from rsa import rsa_encrypt, import_public_key
from des import (
    des_encrypt_ecb, des_decrypt_ecb,
    des_encrypt_cbc, des_decrypt_cbc
)
import os
import random
import string


def start_client(host, port, key, iv, mode):

    # kalo key ma iv gadikasi, generate random
    if key is None:
        key = input("Masukkan DES KEY (8 chars) atau tekan Enter untuk random: ")
        if key == "":
            # Generate random 8-byte key using printable ASCII
            key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        elif len(key) != 8:
            print(f"Warning: Key harus 8 karakter, padding/truncating dari {len(key)} ke 8")
            key = (key + '0' * 8)[:8]
        print("DES KEY =", key)

    if iv is None:
        iv = input("Masukkan DES IV (8 chars) atau tekan Enter untuk random: ")
        if iv == "":
            # Generate random 8-byte IV using printable ASCII
            iv = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        elif len(iv) != 8:
            print(f"Warning: IV harus 8 karakter, padding/truncating dari {len(iv)} ke 8")
            iv = (iv + '0' * 8)[:8]
        print("DES IV =", iv)

    # Connect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(f"Connected to server {host}:{port} (mode: {mode.upper()})")

    # Terima Public Key
    pub_bytes = s.recv(1024)
    public_key = import_public_key(pub_bytes)
    e, n = public_key

    print("\nReceived RSA Public Key:")
    print("e =", e)
    print("n =", n)

    # Create Session
    key_bytes = key.encode()
    iv_bytes = iv.encode()

    # Ensure exactly 8 bytes each
    key_bytes = (key_bytes + b'\x00' * 8)[:8]
    iv_bytes = (iv_bytes + b'\x00' * 8)[:8]

    session = key_bytes + iv_bytes  # Total 16 bytes
    session_int = int.from_bytes(session, "big")

    # RSA encrypt the session integer
    encrypted_session_int = pow(session_int, e, n)
    s.sendall(str(encrypted_session_int).encode())

    print("\nDES Session key dikirim.")
    print("\nChat Starting\n")

    # Chat
    while True:
        msg = input("Client: ")

        if msg.lower() == "exit":
            s.sendall(b"exit")
            break

        # Encrypt
        if mode == "cbc":
            cipher = des_encrypt_cbc(msg, key, iv)
        else:
            cipher = des_encrypt_ecb(msg, key)

        s.sendall(cipher.encode())

        # Receive reply
        reply_cipher = s.recv(4096).decode()
        if reply_cipher.lower() == "exit":
            print("Server exited.")
            break

        if mode == "cbc":
            reply_plain = des_decrypt_cbc(reply_cipher, key, iv)
        else:
            reply_plain = des_decrypt_ecb(reply_cipher, key)

        print("Server: ", reply_plain)

    s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65433)
    parser.add_argument("--key", default=None)
    parser.add_argument("--iv", default=None)
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="ecb")
    args = parser.parse_args()

    start_client(args.host, args.port, args.key, args.iv, args.mode)
