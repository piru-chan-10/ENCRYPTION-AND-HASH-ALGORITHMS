import os
import random
import hashlib
import math

class RSA:
    def __init__(self, message: str):
        self.e = 65537  # public exponent
        self.p, self.q = self.choose_p_and_q()
        self.n = self.p * self.q
        self.public_key = {"n": self.n, "e": self.e}
        self.msg = message
        self.hash_len = hashlib.sha256().digest_size  # 32 bytes for SHA-256
        self.key_generation()
        
    @property
    def d(self):
        return self._d
        
    def choose_p_and_q(self, key_bits: int = 2048) -> tuple[int, int]:
        def random_bit(bits: int) -> int:
            """Generate random odd integer of specified bit length."""
            byte_length = (bits + 7) // 8  # round up to bytes
            n = int.from_bytes(os.urandom(byte_length), "big")
            n |= (1 << (bits - 1))  # ensure exactly 'bits' long
            n |= 1                   # ensure odd
            return n
    
        def is_prime(n: int, rounds: int = 40) -> bool:
            """Miller-Rabin primality test with trial division."""
            if n < 2:
                return False
            # Trial division with small primes to speed up generation
            small_primes = [
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
                73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
                157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 
                239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293
            ]
            if n in small_primes:
                return True
            if any(n % p == 0 for p in small_primes):
                return False
        
            # Write n-1 = 2^s * d
            s, d = 0, n - 1
            while d % 2 == 0:
                s += 1
                d //= 2
            
            # Test with multiple random bases
            for _ in range(rounds):
                a = random.randrange(2, n - 1)
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(s - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False  # composite
            return True  # probably prime
        
        def generate_prime(bits: int) -> int:
            """Generate a prime of specified bit length coprime to e."""
            while True:
                candidate = random_bit(bits)
                # Ensure GCD(e, candidate-1) == 1
                if (candidate - 1) % self.e != 0 and is_prime(candidate):
                    return candidate
        
        # p and q are each half the key size
        prime_bits = key_bits // 2
        
        p = generate_prime(prime_bits)
        while True:
            q = generate_prime(prime_bits)
            if q != p:
                break
        
        return p, q
                
    def rsa_decrypt(self, cipher_txt: bytes) -> bytes:
        n, d = self.n, self.d
        k = (n.bit_length() + 7) // 8
        if len(cipher_txt) != k:
            raise ValueError("Decryption error: ciphertext length mismatch")
            
        cipher_int = int.from_bytes(cipher_txt, "big")
        if cipher_int >= n:
            raise ValueError("Decryption error: ciphertext representative out of range")
            
        # RSADP decryption primitive
        m = pow(cipher_int, d, n)
        EM = m.to_bytes(k, "big")
        
        # OAEP decoding
        Y = EM[0]
        masked_seed = EM[1 : 1 + self.hash_len]
        masked_db = EM[1 + self.hash_len :]
        
        seed_mask = self.mgf1(masked_db, self.hash_len)
        seed = bytes(i ^ j for i, j in zip(masked_seed, seed_mask))
        db_mask = self.mgf1(seed, k - self.hash_len - 1)
        db = bytes(i ^ j for i, j in zip(masked_db, db_mask))
        
        l_hash = hashlib.sha256(b"").digest()
        l_hash_dec = db[0 : self.hash_len]
        
        if Y != 0:
            raise ValueError("Decryption error: Y is not 0")
        if l_hash_dec != l_hash:
            raise ValueError("Decryption error: label hash mismatch")
            
        # Find separator byte 0x01 starting at index self.hash_len
        idx = self.hash_len
        while idx < len(db) and db[idx] == 0:
            idx += 1
            
        if idx >= len(db) or db[idx] != 1:
            raise ValueError("Decryption error: separator byte 0x01 not found")
            
        M = db[idx + 1 :]
        return bytes(M)
        
    def rsa_encrypt(self) -> bytes:
        temp = self.msg.encode("utf-8") 
        k = (self.n.bit_length() + 7) // 8
        self.k = k 
        max_len = k - 2 * self.hash_len - 2
        assert len(temp) <= max_len, "too big message"
        
        l_hash = hashlib.sha256(b"").digest()
        PS = bytearray(k - len(temp) - 2 * self.hash_len - 2)
        DB = bytearray(l_hash) + PS + b"\x01" + temp
        
        seed = os.urandom(self.hash_len)
        db_mask = self.mgf1(seed, k - self.hash_len - 1)
        self.masked_db = bytearray(i ^ j for i, j in zip(DB, db_mask))
        
        seed_mask = self.mgf1(self.masked_db, self.hash_len)
        self.masked_seed = bytearray(i ^ j for i, j in zip(seed, seed_mask))
        
        encoded_message = b"\x00" + self.masked_seed + self.masked_db
        m = int.from_bytes(encoded_message, "big")
        self.c = pow(m, self.e, self.n)
        self.C = self.c.to_bytes(k, "big")
        self.l_hash = l_hash
        return self.C
        
    def mgf1(self, seed: bytes, mask_length: int, h_func=hashlib.sha256) -> bytes:
        hash_len = h_func().digest_size
        output = bytearray()
        seed_bytes = bytes(seed)
        for counter in range((mask_length + hash_len - 1) // hash_len):
            c = counter.to_bytes(4, "big")
            digest = h_func(seed_bytes + c).digest()
            output.extend(digest)
        return bytes(output[:mask_length])
        
    def lcm(self, a, b):
        up = abs(a * b)
        down = self.gcd(a, b)
        return up // down
        
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
        
    def mod_mult_inv(self, a: int, m: int) -> int:
        m0 = m
        y = 0
        x = 1
        if m == 1:
            return 0
        while a > 1:
            if m == 0:
                return 0
            q = a // m
            t = m
            m = a % m
            a = t
            t = y
            y = x - q * y
            x = t
        if x < 0:
            x = x + m0
        return x
        
    def key_generation(self) -> int:
        phi = (self.p - 1) * (self.q - 1)
        assert 1 < self.e < phi and self.gcd(self.e, phi) == 1
        self.lambda_n = self.lcm(self.p - 1, self.q - 1)
        assert self.gcd(self.e, self.lambda_n) == 1
        self._d = self.mod_mult_inv(self.e, self.lambda_n)
        return self._d

if __name__ == "__main__":
    model = RSA("well hello there i have a good news")
    ci = model.rsa_encrypt()
    print("Ciphertext (hex):", ci.hex())
    decrypted = model.rsa_decrypt(ci)
    print("Decrypted bytes:", decrypted)
    print("Decrypted string:", decrypted.decode("utf-8"))
