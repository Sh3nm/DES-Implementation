import socket
import argparse
from des import des_encrypt_ecb, des_decrypt_ecb, des_encrypt_cbc, des_decrypt_cbc

def start_client(host, port, key, iv, mode):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(f"Connected to server {host}:{port} (mode: {mode.upper()})\n")

    while True:
        message = input("Enter message (or 'exit' to quit): ")

        # Encrypt before sending
        if mode == "cbc":
            encrypted = des_encrypt_cbc(message, key, iv)
        else:
            encrypted = des_encrypt_ecb(message, key)

        print(f"Sending Message")
        print(f"Plaintext: {message}")
        print(f"Ciphertext: {encrypted}")
        s.sendall(encrypted.encode())

        if message.lower() == "exit":
            break

        data = s.recv(4096)
        if not data or data.decode().lower() == "exit":
            print("Server disconnected.")
            break

        cipher_hex = data.decode()

        # Decrypt reply
        if mode == "cbc":
            decrypted = des_decrypt_cbc(cipher_hex, key, iv)
        else:
            decrypted = des_decrypt_ecb(cipher_hex, key)

        print("Received Reply")
        print(f"Ciphertext: {cipher_hex}")
        print(f"Decrypted plaintext: {decrypted}")

    s.close()
    print("Client stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    parser.add_argument("--key", default="rahasiah")
    parser.add_argument("--iv", default="12345678")
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="ecb")
    args = parser.parse_args()

    start_client(args.host, args.port, args.key, args.iv, args.mode)
