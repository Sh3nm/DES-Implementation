import socket
import argparse
from des import des_encrypt_ecb, des_decrypt_ecb, des_encrypt_cbc, des_decrypt_cbc

def start_server(host, port, key, iv, mode):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Server running on {host}:{port} (mode: {mode.upper()})")

    conn, addr = s.accept()
    print(f"Connected from {addr}\n")

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

        print("Received Message")
        print(f"Ciphertext: {cipher_hex}")
        print(f"Decrypted plaintext: {decrypted}")

        # Server reply
        reply = input("Enter reply to client: ")
        if reply.lower() == "exit":
            conn.sendall(b"exit")
            break

        # Encrypt reply
        if mode == "cbc":
            encrypted_reply = des_encrypt_cbc(reply, key, iv)
        else:
            encrypted_reply = des_encrypt_ecb(reply, key)

        print("Sending Reply")
        print(f"Plaintext: {reply}")
        print(f"Ciphertext: {encrypted_reply}")

        conn.sendall(encrypted_reply.encode())

    conn.close()
    s.close()
    print("Server stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    parser.add_argument("--key", default="rahasiah")
    parser.add_argument("--iv", default="12345678")
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="ecb")
    args = parser.parse_args()

    start_server(args.host, args.port, args.key, args.iv, args.mode)
