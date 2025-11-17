import random

def modexp(base, exp, mod):
    return pow(base, exp, mod)


# Miller-Rabin primality test (fast for large numbers)
def is_prime(n, k=10):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits=16):
    while True:
        p = random.getrandbits(bits)
        # Ensure odd and high bit set
        p |= (1 << bits - 1) | 1
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
