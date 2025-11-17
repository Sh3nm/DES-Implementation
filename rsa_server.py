import socket
import argparse
from rsa import rsa_decrypt, generate_keys, export_public_key
from des import (
    des_encrypt_ecb, des_decrypt_ecb,
    des_encrypt_cbc, des_decrypt_cbc
)
import os


def start_server(host, port, mode):

    # Generate RSA Key Pair
    print("Generating RSA key pair...")
    public_key, private_key = generate_keys(bits=256)
    e, n = public_key
    d, n_priv = private_key

    print("RSA Public Key:")
    print("e =", e)
    print("n =", n)
    print("RSA Private Key:")
    print("d =", d)

    # Nyalain server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"\nServer running on {host}:{port} (mode: {mode.upper()})")

    conn, addr = s.accept()
    print(f"Connected from {addr}")

    # Kirim public key
    pub_bytes = export_public_key(public_key)
    conn.sendall(pub_bytes)
    print("Public key sent to client.")

    # Terima enkripsi session key
    encrypted_session = conn.recv(4096).decode()
    encrypted_session_int = int(encrypted_session)

    # Decrypt session key
    decrypted_session_int = pow(encrypted_session_int, d, n)

    # Convert ke 16 byte
    session_bytes = decrypted_session_int.to_bytes(16, "big")

    # Extract key and IV 
    key = session_bytes[:8].rstrip(b'\x00').decode('latin-1')
    iv = session_bytes[8:16].rstrip(b'\x00').decode('latin-1')
    
    # Pasin 8 karakter buat DES
    key = (key + '0' * 8)[:8]
    iv = (iv + '0' * 8)[:8]

    print("\nReceived DES session key:")
    print("KEY =", key)
    print("IV =", iv)
    print("\nChat Starting\n")

    while True:
        data = conn.recv(4096)
        if not data:
            break

        cipher_hex = data.decode()
        if cipher_hex.lower() == "exit":
            print("Client disconnected.")
            break

        # Decrypt message
        if mode == "cbc":
            decrypted = des_decrypt_cbc(cipher_hex, key, iv)
        else:
            decrypted = des_decrypt_ecb(cipher_hex, key)

        print("Client: ", decrypted)

        # Server reply
        reply = input("Server: ")
        if reply.lower() == "exit":
            conn.sendall(b"exit")
            break

        # Encrypt reply
        if mode == "cbc":
            encrypted_reply = des_encrypt_cbc(reply, key, iv)
        else:
            encrypted_reply = des_encrypt_ecb(reply, key)

        conn.sendall(encrypted_reply.encode())

    conn.close()
    s.close()
    print("Server stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65433)
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="ecb")
    args = parser.parse_args()

    start_server(args.host, args.port, args.mode)
