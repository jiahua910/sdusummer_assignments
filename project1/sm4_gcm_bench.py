from __future__ import annotations
import struct
import time
import os
from typing import Tuple, Optional

# --------------------- SM4和T-table ---------------------

def rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def bytes_to_u32_list(b: bytes) -> list:
    return list(struct.unpack('>IIII', b))

def u32_list_to_bytes(l: list) -> bytes:
    return struct.pack('>IIII', *l)

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
]

SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
]

class SM4Core:
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError('SM4密钥必须为16字节')
        self._key = key
        self.rks = self._key_schedule(key)

    @staticmethod
    def _tau(word: int) -> int:
        b0 = SBOX[(word >> 24) & 0xFF]
        b1 = SBOX[(word >> 16) & 0xFF]
        b2 = SBOX[(word >> 8) & 0xFF]
        b3 = SBOX[word & 0xFF]
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    @classmethod
    def _L(cls, b: int) -> int:
        return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)

    @classmethod
    def _L_prime(cls, b: int) -> int:
        return b ^ rotl32(b, 13) ^ rotl32(b, 23)

    def _T(self, x: int) -> int:
        return self._L(self._tau(x))

    def _T_prime(self, x: int) -> int:
        return self._L_prime(self._tau(x))

    def _key_schedule(self, key: bytes) -> list:
        MK = bytes_to_u32_list(key)
        K = [MK[i] ^ FK[i] for i in range(4)]
        rks = []
        for i in range(32):
            temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]
            rk = K[i] ^ self._T_prime(temp)
            rks.append(rk & 0xFFFFFFFF)
            K.append(rk)
        return rks

    def encrypt_block(self, block16: bytes) -> bytes:
        X = bytes_to_u32_list(block16)
        for i in range(32):
            tmp = X[i] ^ X[i+1] ^ X[i+2] ^ X[i+3] ^ self.rks[i]
            X.append(X[i] ^ self._T(tmp))
        out = [X[35], X[34], X[33], X[32]]
        return u32_list_to_bytes(out)

class SM4Ttable(SM4Core):
    def __init__(self, key: bytes):
        super().__init__(key)
        self._make_tables()

    def _make_tables(self):
        self.T = [[0]*256 for _ in range(4)]
        for pos in range(4):
            for b in range(256):
                word = b << (24 - 8*pos)
                val = self._L(self._tau(word))
                self.T[pos][b] = val

    def encrypt_block(self, block16: bytes) -> bytes:
        X = bytes_to_u32_list(block16)
        for i in range(32):
            tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ self.rks[i]
            b0 = (tmp >> 24) & 0xFF
            b1 = (tmp >> 16) & 0xFF
            b2 = (tmp >> 8) & 0xFF
            b3 = tmp & 0xFF
            t = (self.T[0][b0] ^ self.T[1][b1] ^ self.T[2][b2] ^ self.T[3][b3]) & 0xFFFFFFFF
            X.append(X[i] ^ t)
        out = [X[35], X[34], X[33], X[32]]
        return u32_list_to_bytes(out)

# --------------------- GHASH/GCM工具(纯Python) ---------------------

def int_from_be_bytes(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def int_to_be_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

R_POLY = 0xE1000000000000000000000000000000

def gf128_mul(x: int, y: int) -> int:
    # 无进位乘法(简单实现)
    z = 0
    v = x
    # 从最高位到最低位遍历y的每一位
    for i in reversed(range(128)):
        if (y >> i) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= R_POLY
    return z & ((1 << 128) - 1)

class GHASH:
    def __init__(self, H: bytes):
        if len(H) != 16:
            raise ValueError('H必须为16字节')
        self.H = int_from_be_bytes(H)

    def ghash(self, aad: bytes, cipher_text: bytes) -> bytes:
        block_size = 16
        def iter_blocks(b: bytes):
            for i in range(0, len(b), block_size):
                chunk = b[i:i+block_size]
                if len(chunk) < block_size:
                    chunk = chunk + b'\x00'*(block_size - len(chunk))
                yield chunk
        y = 0
        for blk in iter_blocks(aad):
            y ^= int_from_be_bytes(blk)
            y = gf128_mul(y, self.H)
        for blk in iter_blocks(cipher_text):
            y ^= int_from_be_bytes(blk)
            y = gf128_mul(y, self.H)
        a_bits = len(aad) * 8
        c_bits = len(cipher_text) * 8
        length_block = int_to_be_bytes(a_bits, 8) + int_to_be_bytes(c_bits, 8)
        y ^= int_from_be_bytes(length_block)
        y = gf128_mul(y, self.H)
        return int_to_be_bytes(y, 16)

# --------------------- SM4-GCM封装 ---------------------

class SM4GCM_Python:
    def __init__(self, key: bytes, use_ttable: bool = False):
        if use_ttable:
            self.cipher = SM4Ttable(key)
        else:
            self.cipher = SM4Core(key)
        self.H = self.cipher.encrypt_block(b'\x00'*16)
        self.ghash = GHASH(self.H)

    @staticmethod
    def _inc32(counter_block: bytes) -> bytes:
        prefix = counter_block[:12]
        ctr = int.from_bytes(counter_block[12:], 'big')
        ctr = (ctr + 1) & 0xFFFFFFFF
        return prefix + ctr.to_bytes(4, 'big')

    def _encrypt_ctr(self, iv: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        if len(iv) == 12:
            J0 = iv + b'\x00\x00\x00\x01'
        else:
            J0 = self.ghash.ghash(b'', iv)
        out = bytearray()
        counter = J0
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            keystream = self.cipher.encrypt_block(counter)
            out_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            out.extend(out_block)
            counter = self._inc32(counter)
        return bytes(out), J0

    def encrypt(self, iv: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        ciphertext, J0 = self._encrypt_ctr(iv, plaintext)
        s = self.ghash.ghash(aad, ciphertext)
        tag_block = self.cipher.encrypt_block(J0)
        tag = bytes(a ^ b for a, b in zip(tag_block, s))
        return ciphertext, tag

    def decrypt(self, iv: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> Tuple[bytes, bool]:
        if len(tag) != 16:
            raise ValueError('标签必须为16字节')
        if len(iv) == 12:
            J0 = iv + b'\x00\x00\x00\x01'
        else:
            J0 = self.ghash.ghash(b'', iv)
        s = self.ghash.ghash(aad, ciphertext)
        tag_block = self.cipher.encrypt_block(J0)
        expected_tag = bytes(a ^ b for a, b in zip(tag_block, s))
        if expected_tag != tag:
            return b'', False
        plaintext, _ = self._encrypt_ctr(iv, ciphertext)
        return plaintext, True

# --------------------- 基于OpenSSL的实现(通过cryptography) ---------------------

HAS_CRYPTOGRAPHY = False
CRYPTO_AVAILABLE_SM4 = False
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # 仅用于可用性检查
    HAS_CRYPTOGRAPHY = True
    try:
        _ = algorithms.SM4  # type: ignore
        CRYPTO_AVAILABLE_SM4 = True
    except Exception:
        CRYPTO_AVAILABLE_SM4 = False
except Exception:
    HAS_CRYPTOGRAPHY = False
    CRYPTO_AVAILABLE_SM4 = False

def openssl_sm4_ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:

    if not (HAS_CRYPTOGRAPHY and CRYPTO_AVAILABLE_SM4):
        raise RuntimeError('不支持SM4的cryptography不可用')
    cipher = Cipher(algorithms.SM4(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct

def openssl_sm4_gcm_encrypt(key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:

    if not (HAS_CRYPTOGRAPHY and CRYPTO_AVAILABLE_SM4):
        raise RuntimeError('不支持SM4的cryptography不可用')
    # 使用低级Cipher与GCM模式获取标签
    cipher = Cipher(algorithms.SM4(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    ct = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return ct, tag

# --------------------- 测试框架及运行 ---------------------

def run_one_mode(mode: str, key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes, float]:

    t0 = time.perf_counter()
    if mode == 'python_ref':
        g = SM4GCM_Python(key, use_ttable=False)
        ct, tag = g.encrypt(iv, aad, plaintext)
        t_elapsed = time.perf_counter() - t0
        # 验证往返
        pt2, ok = g.decrypt(iv, aad, ct, tag)
        if not ok or pt2 != plaintext:
            raise RuntimeError('python_ref往返测试失败')
        return ct, tag, t_elapsed
    elif mode == 'python_ttable':
        g = SM4GCM_Python(key, use_ttable=True)
        ct, tag = g.encrypt(iv, aad, plaintext)
        t_elapsed = time.perf_counter() - t0
        pt2, ok = g.decrypt(iv, aad, ct, tag)
        if not ok or pt2 != plaintext:
            raise RuntimeError('python_ttable往返测试失败')
        return ct, tag, t_elapsed
    elif mode == 'openssl_ctr':
        if not (HAS_CRYPTOGRAPHY and CRYPTO_AVAILABLE_SM4):
            raise RuntimeError('openssl_ctr模式需要支持SM4的cryptography')
        ttable = SM4Ttable(key)
        H = ttable.encrypt_block(b'\x00'*16)
        ghash = GHASH(H)
        if len(iv) == 12:
            J0 = iv + b'\x00\x00\x00\x01'
        else:
            J0 = ghash.ghash(b'', iv)
        ct = openssl_sm4_ctr_encrypt(key, J0, plaintext)
        s = ghash.ghash(aad, ct)
        tag_block = ttable.encrypt_block(J0)
        tag = bytes(a ^ b for a, b in zip(tag_block, s))
        t_elapsed = time.perf_counter() - t0
        # 验证解密：使用OpenSSL CTR解密并通过相同GHASH检查标签
        # 通过CTR解密(再次加密得到明文)
        pt2 = openssl_sm4_ctr_encrypt(key, J0, ct)  # CTR解密 = CTR加密
        if pt2 != plaintext:
            raise RuntimeError('openssl_ctr解密不匹配')
        return ct, tag, t_elapsed
    elif mode == 'openssl_gcm':
        if not (HAS_CRYPTOGRAPHY and CRYPTO_AVAILABLE_SM4):
            raise RuntimeError('openssl_gcm模式需要支持SM4的cryptography')
        ct, tag = openssl_sm4_gcm_encrypt(key, iv, aad, plaintext)
        t_elapsed = time.perf_counter() - t0
        # 使用OpenSSL解密器验证往返
        # 通过cryptography低级API解密
        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        pt2 = decryptor.update(ct) + decryptor.finalize()
        if pt2 != plaintext:
            raise RuntimeError('openssl_gcm解密不匹配')
        return ct, tag, t_elapsed
    else:
        raise ValueError('未知模式')

def benchmark_all(key: bytes, iv: bytes, aad: bytes, plaintext: bytes, repeats: int = 3):
    modes = ['python_ref', 'python_ttable', 'openssl_ctr', 'openssl_gcm']
    results = {}
    for mode in modes:
        times = []
        supported = True
        for i in range(repeats):
            try:
                _, _, t = run_one_mode(mode, key, iv, aad, plaintext)
                times.append(t)
            except RuntimeError as e:
                print(f'[!] 模式 {mode} 失败或不支持: {e}')
                supported = False
                break
            except Exception as e:
                print(f'[!] 模式 {mode} 错误: {e}')
                supported = False
                break
        results[mode] = (supported, times)
    return results

# --------------------- 简单CLI示例及时间格式化 ---------------------

def human_ms(x: float) -> str:
    return f'{x*1000:.3f} mm'

if __name__ == '__main__':
    print('sm4测试')
    print('cryptography 是否可用:', HAS_CRYPTOGRAPHY, '通过cryptography的SM4:', CRYPTO_AVAILABLE_SM4)
    # 测试数据
    KEY = bytes.fromhex('0123456789abcdeffedcba9876543210')
    IV = os.urandom(12)  # GCM常用的96位IV
    AAD = b'header-example'
    TEST_PLAINTEXT_SIZE = 1024 * 1024
    PLAINTEXT = (b'0123456789ABCDEF' * ((TEST_PLAINTEXT_SIZE // 16) + 1))[:TEST_PLAINTEXT_SIZE]

    print(f'测试明文大小: {len(PLAINTEXT)} 字节')

    # 和快速正确性检查
    print('运行正确性检查...')
    try:
        # python_ref
        g = SM4GCM_Python(KEY, use_ttable=False)
        ct, tag = g.encrypt(IV, AAD, PLAINTEXT[:1024])
        pt2, ok = g.decrypt(IV, AAD, ct, tag)
        assert ok and pt2 == PLAINTEXT[:1024]
        # python_ttable
        g2 = SM4GCM_Python(KEY, use_ttable=True)
        ct2, tag2 = g2.encrypt(IV, AAD, PLAINTEXT[:1024])
        pt22, ok2 = g2.decrypt(IV, AAD, ct2, tag2)
        assert ok2 and pt22 == PLAINTEXT[:1024]
    except Exception as e:
        raise

    if HAS_CRYPTOGRAPHY and CRYPTO_AVAILABLE_SM4:
        try:
            ct3, tag3 = openssl_sm4_gcm_encrypt(KEY, IV, AAD, PLAINTEXT[:1024])
            # 解密测试
            cipher = Cipher(algorithms.SM4(KEY), modes.GCM(IV, tag3), backend=default_backend())
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(AAD)
            pt3 = decryptor.update(ct3) + decryptor.finalize()
            assert pt3 == PLAINTEXT[:1024]
            print('OpenSSL-backed SM4-GCM 正常。')
        except Exception as e:
            print('OpenSSL-backed 快速测试失败:', e)
    else:
        print('不支持SM4/GCM的cryptography - 将跳过OpenSSL-backed模式。')

    # 测试
    print('开始测试...')
    results = benchmark_all(KEY, IV, AAD, PLAINTEXT, repeats=2)

    print('\n=== 测试结果===')
    for mode, (supported, times) in results.items():
        if not supported:
            print(f'{mode:20s}: 不支持/失败')
            continue
        avg = sum(times) / len(times)
        print(f'{mode:20s}: 运行次数:{len(times)} 耗时:{[human_ms(t) for t in times]} 平均:{human_ms(avg)}')