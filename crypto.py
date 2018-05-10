# 
# Jason Willmore
# 3-17-2018
# crypto.py

import sys
import random

DEBUG_FLAG = True
BLOCK_SIZE = 32
CHAR_BIT_LEN = 8
generator_g = 2 # generator g is a literal value for e1

def read_in_file(filename):
    with open(filename) as f:
        read_data = f.read()
    return read_data


def output_to_file_with_spaces(filename, output_items):
    output_items_as_strings = list(map(str, output_items))
    with open(filename, mode='wt', encoding='utf-8') as f:
        output_thingies = ' '.join(output_items_as_strings)
        f.write(output_thingies)


def chunk_plaintext(plaintext_str):
    chunk_size = int(BLOCK_SIZE / CHAR_BIT_LEN)  # 32 / 8 = 4
    chunks = []
    plaintext_length = len(plaintext_str)
    for i in range(0, plaintext_length, chunk_size):
        if i + chunk_size <= plaintext_length:
            chunks.append(plaintext_str[i : i+chunk_size])
        else:
            chunks.append(plaintext_str[i : plaintext_length])
    return chunks


def square_and_multiply(base, exponent, modulo_val):
    """ This function is a fast way to perform "a^b mod n"
    """
    a = base; b = exponent; n = modulo_val
    c = 0
    f = 1
    k = b.bit_length()
    for i in range(k, -1, -1):
        c = c * 2
        f = (f * f) % n
        if (b >> i) & 1 == 1: # if there is a one in the binary at the i'th spot
            c = c + 1
            f = (f * a) % n
    return f


def is_probable_prime(n, k = 10):
    """use Rabin-Miller algorithm to return True (n is probably prime)
        or False (n is definitely composite). credited to wikibooks (https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Primality_Testing)"""
    if n < 6:  # assuming n >= 0 in all cases... shortcut small cases here
        return [False, False, True, True, False, True][n]
    elif n & 1 == 0:  # should be faster than n % 2
        return False
    else:
        s, d = 0, n - 1
        while d & 1 == 0:
            s, d = s + 1, d >> 1
        for a in random.sample(range(2, min(n - 2, sys.maxsize)), min(n - 4, k)):
            x = pow(a, d, n)
            if x != 1 and x + 1 != n:
                for r in range(1, s):
                    x = pow(x, 2, n)
                    if x == 1:
                        return False  # composite for sure
                    elif x == n - 1:
                        a = 0  # so we know loop didn't continue to end
                        break  # could be strong liar, try another a
                if a:
                    return False  # composite if we reached end of this loop
        return True  # probably prime if reached end of outer loop


def generate_kbit_prime(user_seed, k=BLOCK_SIZE):
    random.seed(user_seed)
    while True:
        q = random.getrandbits(k) | 0x80000001
        if is_probable_prime(q):
            if (q % 12) == 5:
                p = 2 * q + 1
                if is_probable_prime(p):
                    return p


def key_generation():
    seed = input("enter a random number to seed the generator: ")
    p = generate_kbit_prime(seed)
    # select d to be a member of the group {1, ..., p-2}
    d = random.randint(1, p-2)
    e1 = generator_g  # generator_g = 2, this is a shortcut method
    e2 = square_and_multiply(e1, d, p) # (e1 ** d) % p
    public_key = [p, e1, e2]  # (p, g, e2)
    private_key = [p, e1, d]  # (p, g, d)

    print("public key (p: {}, e1/g: {}, e2: {})".format(p,e1, e2))
    print("private key (p: {}, e1/g: {}, d: {})".format(p, e1, d))
    
    output_to_file_with_spaces('pubkey.txt', public_key)
    output_to_file_with_spaces('prikey.txt', private_key)

    return (public_key, private_key)


def encrypt(e1, e2, p, plaintext):
    r = random.randint(1, p-1)
    C1 = square_and_multiply(e1, r, p)
    C2 = ((plaintext % p) * square_and_multiply(e2, r, p)) % p
    # Return (C1,C2) as strings ready for file output
    ciphertext = str(C1) + " " + str(C2) + "\n"
    return (ciphertext)


def encryption():
    plaintext = read_in_file('ptext.txt')
    public_key = read_in_file('pubkey.txt')
    pub_key_list = public_key.split()  # break up public key string on spaces
    p = int(pub_key_list[0])
    e1 = int(pub_key_list[1])
    e2 = int(pub_key_list[2])

    plaintext_chunks = chunk_plaintext(plaintext)
    f = open('ctext.txt', 'w')
    # pass chunks into encrypt() one at  a time
    for m in plaintext_chunks:
        int_m = 0
        for char in m:
            int_m = (int_m << 8) | ord(char)
        ciphertext = encrypt(e1, e2, p, int_m)
        f.write(ciphertext)
    f.close()


def decrypt(d, p, C1, C2):
    b = p - 1 - d
    m = (square_and_multiply(C1, b, p) * (C2 % p)) % p
    return m


def decryption():
    # read in the private-key
    private_key = read_in_file('prikey.txt')
    private_key_list = private_key.split()
    p = int(private_key_list[0])
    d = int(private_key_list[2])
    # read in the whole ciphertext file
    ciphertext = read_in_file('ctext.txt')
    # split file into (C1, C2) pairs which are their own line
    rows = ciphertext.split("\n")
    plaintext = ""
    for row in rows:
        if len(row) < 1: continue
        # split the line into C1 and C2
        c1_c2 = row.split()
        C1 = int(c1_c2[0])
        C2 = int(c1_c2[1])
        block = decrypt(d, p, C1, C2)
        # bitshift magic to rebuild the strings from integers
        plaintext += chr((block >> 24) & 0xff)
        plaintext += chr((block >> 16) & 0xff)
        plaintext += chr((block >> 8) & 0xff)
        plaintext += chr(block & 0xff)
    with open('dtext.txt', 'w') as f:
        f.write(plaintext)


if __name__ == '__main__':
    print("Welcome to Crypto")
    while True:
        print("""Options:
        1) key generation
        2) encryption
        3) decryption.
        4) quit
                """)
        selection = input("option: ")
        if selection == '1' or selection == 'key generation':
            print("-- Generating Key --")
            key_generation()
            print("Key written to prikey.txt and pubkey.txt\n")

        elif selection == '2' or selection == 'encryption':
            print("-- Encrypting ptext.txt --")
            encryption()
            print("Ciphertext written to ctext.txt\n")

        elif selection == '3' or selection == 'decryption':
            print("-- Decrypting ctext.txt --")
            decryption()
            print("Check dtext.txt for the decrypted output.\n")

        elif selection == '4' or selection == 'quit':
            print("quitting...")
            quit()

        else:
            print("\n'{}' is not a valid option, please try again.\n".format(selection))
