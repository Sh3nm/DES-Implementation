import socket
import argparse
import threading
from rsa import rsa_decrypt, generate_keys, export_public_key
from des import (
    des_encrypt_ecb, des_decrypt_ecb,
    des_encrypt_cbc, des_decrypt_cbc
)


def handle_client(conn, addr, private_key, mode):
    """Handle individual client connection in separate thread"""
    try:
        print(f"\n[{addr}] Client connected")
        
        # Terima enkripsi session key
        encrypted_session = conn.recv(4096).decode()
        encrypted_session_int = int(encrypted_session)

        # Decrypt session key
        d, n = private_key
        decrypted_session_int = pow(encrypted_session_int, d, n)

        # Convert ke 16 byte
        session_bytes = decrypted_session_int.to_bytes(16, "big")

        # Extract key and IV 
        key = session_bytes[:8].rstrip(b'\x00').decode('latin-1')
        iv = session_bytes[8:16].rstrip(b'\x00').decode('latin-1')
        
        # Pasin 8 karakter buat DES
        key = (key + '0' * 8)[:8]
        iv = (iv + '0' * 8)[:8]

        print(f"[{addr}] Session established:")
        print(f"[{addr}]   KEY = {key}")
        print(f"[{addr}]   IV  = {iv}")
        print(f"[{addr}] Chat started\n")

        # Chat loop
        while True:
            data = conn.recv(4096)
            if not data:
                break

            cipher_hex = data.decode()
            if cipher_hex.lower() == "exit":
                print(f"[{addr}] Client disconnected.")
                break

            # Decrypt message
            try:
                if mode == "cbc":
                    decrypted = des_decrypt_cbc(cipher_hex, key, iv)
                else:
                    decrypted = des_decrypt_ecb(cipher_hex, key)
                
                print(f"[{addr}] Client: {decrypted}")
            except Exception as e:
                print(f"[{addr}] Decrypt error: {e}")
                continue

            # Auto-reply (echo)
            reply = f"echo: {decrypted}"
            
            # Encrypt reply
            if mode == "cbc":
                encrypted_reply = des_encrypt_cbc(reply, key, iv)
            else:
                encrypted_reply = des_encrypt_ecb(reply, key)

            conn.sendall(encrypted_reply.encode())
            print(f"[{addr}] Server: {reply}")

    except Exception as e:
        print(f"[{addr}] Error: {e}")
    finally:
        conn.close()
        print(f"[{addr}] Connection closed\n")


def start_server(host, port, mode):
    # Generate RSA Key Pair
    print("🔑 Generating RSA key pair...")
    public_key, private_key = generate_keys(bits=256)
    e, n = public_key
    d, n_priv = private_key

    print("✅ RSA Keys Generated:")
    print(f"   Public Key (e, n):")
    print(f"     e = {e}")
    print(f"     n = {n}")
    print(f"   Modulus size: {n.bit_length()} bits")
    print(f"   Private Key (d): {d}\n")

    # Nyalain server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(2)  #Support multiple clients
    print(f"🚀 Server listening on {host}:{port}")
    print(f"   DES Mode: {mode.upper()}")
    print(f"   Ready for multiple clients...\n")

    try:
        while True:
            conn, addr = s.accept()
            
            # Kirim public key
            pub_bytes = export_public_key(public_key)
            conn.sendall(pub_bytes)
            print(f"[{addr}] Public key sent")
            
            #Create thread for each client
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, private_key, mode),
                daemon=True
            )
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n\n🛑 Server shutting down...")
    finally:
        s.close()
        print("Server stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RSA-DES Encrypted Chat Server (Multi-threaded)')
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=65433, help="Server port")
    parser.add_argument("--mode", choices=["ecb", "cbc"], default="ecb", help="DES mode")
    args = parser.parse_args()

    start_server(args.host, args.port, args.mode)
