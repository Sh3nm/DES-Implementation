import random

def modexp(base, exp, mod):
    return pow(base, exp, mod)


# Generate random angka prima
def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    
    r = int(n ** 0.5)
    for i in range(3, r + 1, 2):
        if n % i == 0:
            return False
    return True


def generate_prime(bits=16):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p


# Generate RSA Key
def generate_keys(bits=16):
    p = generate_prime(bits)
    q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # pilih e
    e = 65537
    if phi % e == 0:
        # fallback
        while True:
            e = random.randrange(3, phi)
            if gcd(e, phi) == 1:
                break

    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key
 
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# RSA Encryption
def rsa_encrypt(data: bytes, public_key):
    e, n = public_key
    c_int = pow(int.from_bytes(data, 'big'), e, n)
    return c_int.to_bytes((c_int.bit_length() + 7) // 8, 'big')

# RSA Decryption
def rsa_decrypt(cipher_bytes: bytes, private_key):
    d, n = private_key
    c_int = int.from_bytes(cipher_bytes, 'big')
    m_int = pow(c_int, d, n)
    return m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')


# Sending Public Key (serialize)
def export_public_key(public_key):
    e, n = public_key
    return f"{e},{n}".encode()

# Receiving Public Key (deserialize)
def import_public_key(data: bytes):
    e, n = data.decode().split(",")
    return int(e), int(n)
