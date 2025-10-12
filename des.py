from itertools import cycle

# Konversi string ke bit
def text_to_bits(text):
    return ''.join(f'{ord(c):08b}' for c in text)

# Konversi bit ke string
def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

def xor(a, b):
    return ''.join('1' if i != j else '0' for i, j in zip(a, b))

def permute(bits, table):
    return ''.join(bits[i-1] for i in table)

# Tambahkan padding agar panjang kelipatan 64
def pad_to_64_bits(bits):
    while len(bits) % 64 != 0:
        bits += '0'
    return bits

# table DES
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# S-box (pake 1 contoh dulu buat semuanya)
S_BOX = [
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ]
] * 8  

def sbox_substitution(bits):
    output = ''
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = S_BOX[i][row][col]
        output += f'{val:04b}'
    return output

def feistel(right, key):
    expanded = permute(right, E)
    temp = xor(expanded, key)
    substituted = sbox_substitution(temp)
    return substituted  # skip P-box for simplicity

# Hasilkan 16 subkey dari key
def generate_subkeys(key_bits):
    subkeys = []
    key_cycle = cycle(key_bits)
    for i in range(16):
        subkeys.append(''.join(next(key_cycle) for _ in range(48)))
    return subkeys

# DES Core
def des_encrypt_block(block, key_bits):
    block = permute(block, IP)
    L, R = block[:32], block[32:]
    subkeys = generate_subkeys(key_bits)

    for i in range(16):
        new_L = R
        new_R = xor(L, feistel(R, subkeys[i]))
        L, R = new_L, new_R

    cipher_block = permute(R + L, FP)
    return cipher_block

def des_encrypt_text(plaintext, key):
    plaintext_bits = pad_to_64_bits(text_to_bits(plaintext))
    key_bits = text_to_bits(key)
    cipher_bits = ''

    for i in range(0, len(plaintext_bits), 64):
        block = plaintext_bits[i:i+64]
        cipher_bits += des_encrypt_block(block, key_bits)

    return hex(int(cipher_bits, 2))[2:].zfill(len(cipher_bits)//4)

if __name__ == "__main__":
    plaintext = input("Plaintext : ")
    key = input("Key (8 chars): ")

    ciphertext = des_encrypt_text(plaintext, key)
    print("Ciphertext :", ciphertext)
