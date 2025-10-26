import socket
import argparse
from des import des_encrypt_ecb, des_decrypt_ecb, des_encrypt_cbc, des_decrypt_cbc

def start_server(host, port, key, iv, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server running on {host}:{port} (mode: {mode.upper()})")
        
        conn, addr = s.accept()
        with conn:
            print(f" Connected from  {addr}")
            while True:
                data = conn.recv(4096)
                if not data:
                    break

                cipher_hex = data.decode('utf-8')

                # Dekripsi sesuai mode
                if mode == "cbc":
                    decrypted = des_decrypt_cbc(cipher_hex, key, iv)
                else:
                    decrypted = des_decrypt_ecb(cipher_hex, key)

                print(f"\nMessage encrypted: {cipher_hex}")
                print(f" Message decrypted : {decrypted}")

                # Balasan terenkripsi
                reply = f"Server receive: {decrypted}"
                if mode == "cbc":
                    reply_cipher = des_encrypt_cbc(reply, key, iv)
                else:
                    reply_cipher = des_encrypt_ecb(reply, key)

                conn.sendall(reply_cipher.encode('utf-8'))
                print(f" Send encrypted reply.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Server untuk komunikasi DES")
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="cbc", help="Mode enkripsi (ecb atau cbc)")
    parser.add_argument("--host", default="127.0.0.1", help="Alamat host server")
    parser.add_argument("--port", type=int, default=65432, help="Port server")
    parser.add_argument("--key", default="rahasiah", help="Kunci enkripsi (8 karakter)")
    parser.add_argument("--iv", default="12345678", help="Initialization Vector (8 karakter, untuk CBC)")
    
    args = parser.parse_args()
    start_server(args.host, args.port, args.key, args.iv, args.mode)
