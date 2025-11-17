import socket
import argparse
from rsa import rsa_encrypt, import_public_key
from des import (
    des_encrypt_ecb, des_decrypt_ecb,
    des_encrypt_cbc, des_decrypt_cbc
)
import os


def start_client(host, port, key, iv, mode):
    # ==== IF KEY OR IV NOT PROVIDED ====
    if key is None:
        key = input("Masukkan DES KEY (8 chars) atau tekan Enter untuk random: ")
        if key == "":
            key = os.urandom(8).decode(errors="ignore")[:8]
        print("DES KEY =", key)

    if iv is None:
        iv = input("Masukkan DES IV (8 chars) atau tekan Enter untuk random: ")
        if iv == "":
            iv = os.urandom(8).decode(errors="ignore")[:8]
        print("DES IV =", iv)

    # ==== CONNECT ====
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(f"Connected to server {host}:{port} (mode: {mode.upper()})")

    # ==== RECEIVE PUBLIC KEY ====
    pub_bytes = s.recv(1024)
    public_key = import_public_key(pub_bytes)
    e, n = public_key

    print("\nReceived RSA Public Key:")
    print("e =", e)
    print("n =", n)

    # ==== CREATE SESSION ====
    key_bytes = key.encode()
    iv_bytes = iv.encode()

    session = key_bytes + iv_bytes
    session_int = int.from_bytes(session, "big")

    encrypted_session_int = rsa_encrypt(session_int, public_key)
    s.sendall(str(encrypted_session_int).encode())

    print("\nDES Session key dikirim.")
    print("\n===== Chat dimulai =====\n")

    # ==== CHAT LOOP ====
    while True:
        msg = input("Client > ")

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

        print("Server >", reply_plain)

    s.close()
