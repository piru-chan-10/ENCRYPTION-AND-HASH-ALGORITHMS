"""
    Hi there I am piru this is my implementation of MD5 hash algorithm
"""
import sys

# MD5 Buffer Initialization Values
A0 = 0x67452301
B0 = 0xefcdab89
C0 = 0x98badcfe
D0 = 0x10325476

# Complete shift table as a single list
S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  # 0..15
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  # 16..31
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  # 32..47
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21   # 48..63
]

# Sine constants
K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

def l_rotate(x: int, s: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF

def message_digest(message: str) -> bytes:
    # Convert string to bytes
    msg_bytes = message.encode('utf-8')
    o_len_bits = len(msg_bytes) * 8
    
    # Append '1' bit (0x80 byte)
    msg_bytes += b'\x80'
    
    # Pad with 0s until length is congruent to 56 mod 64 (448 mod 512 bits)
    while (len(msg_bytes) % 64) != 56:
        msg_bytes += b'\x00'
        
    # Append original length in bits as 64-bit little endian
    msg_bytes += o_len_bits.to_bytes(8, byteorder='little')
    return msg_bytes

def split_512bits(message_digest: bytes) -> list[bytes]:
    # 512 bits is 64 bytes
    res = []
    for i in range(0, len(message_digest), 64):
        res.append(message_digest[i:i+64])
    return res

def break_chunk(chunk: bytes) -> list[int]:
    # MD5 expects 16 32-bit words (each 4 bytes)
    res = []
    for i in range(0, len(chunk), 4):
        # Unpack 4 bytes in little-endian order
        val = chunk[i] | (chunk[i+1] << 8) | (chunk[i+2] << 16) | (chunk[i+3] << 24)
        res.append(val)
    return res

def hash(chunks: list[bytes]) -> str:
    global A0, B0, C0, D0
    
    for chunk in chunks:
        X = break_chunk(chunk)
        A, B, C, D = A0, B0, C0, D0 
        for i in range(64):
            if i < 16:
                F = (B & C) | (~B & D)
                g = i
            elif i < 32:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16
            
            # Mask F to 32 bits to prevent precision expansion
            F = (F + A + K[i] + X[g]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + l_rotate(F, S[i])) & 0xFFFFFFFF
            
        A0 = (A0 + A) & 0xFFFFFFFF
        B0 = (B0 + B) & 0xFFFFFFFF
        C0 = (C0 + C) & 0xFFFFFFFF
        D0 = (D0 + D) & 0xFFFFFFFF
        
    # Standard MD5 outputs registers in little-endian hex format
    final_hash = (
        A0.to_bytes(4, byteorder='little') +
        B0.to_bytes(4, byteorder='little') +
        C0.to_bytes(4, byteorder='little') +
        D0.to_bytes(4, byteorder='little')
    ).hex()
    return final_hash

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python md5.py <text>")
        sys.exit(1)
    text = sys.argv[1]
    M = message_digest(text)
    chunks = split_512bits(M)
    print(hash(chunks))
