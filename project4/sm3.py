import struct
import time
import os

# ===== SM3 基础实现 =====
IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

T_j = [0x79CC4519] * 16 + [0x7A879D8A] * 48

def _rotl(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def _ff(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))

def _gg(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x) & z))

def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)

def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def sm3_basic(msg: bytes):
    length = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += struct.pack('>Q', length)

    V = IV[:]
    for i in range(0, len(msg), 64):
        B = msg[i:i+64]
        W = list(struct.unpack('>16I', B))
        for j in range(16, 68):
            W.append(_p1(W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)) ^ _rotl(W[j-13], 7) ^ W[j-6])
        W_ = [W[j] ^ W[j+4] for j in range(64)]
        A, B_, C, D, E, F, G, H = V
        for j in range(64):
            SS1 = _rotl((_rotl(A, 12) + E + _rotl(T_j[j], j % 32)) & 0xffffffff, 7)
            SS2 = SS1 ^ _rotl(A, 12)
            TT1 = (_ff(A, B_, C, j) + D + SS2 + W_[j]) & 0xffffffff
            TT2 = (_gg(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
            D, C, B_, A = C, _rotl(B_, 9), A, TT1
            H, G, F, E = G, _rotl(F, 19), E, _p0(TT2)
        V = [a ^ b for a, b in zip(V, [A, B_, C, D, E, F, G, H])]
    return b''.join(struct.pack('>I', x) for x in V)

# ===== 优化实现 =====
def sm3_optimized(msg: bytes):
    length = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += struct.pack('>Q', length)

    V = IV[:]
    rotl = _rotl
    for i in range(0, len(msg), 64):
        B = msg[i:i+64]
        W = list(struct.unpack('>16I', B))
        for j in range(16, 68):
            W.append(_p1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6])
        W_ = [W[j] ^ W[j+4] for j in range(64)]
        A, B_, C, D, E, F, G, H = V
        for j in range(64):
            T = T_j[j]
            A12 = rotl(A, 12)
            SS1 = rotl((A12 + E + rotl(T, j % 32)) & 0xffffffff, 7)
            SS2 = SS1 ^ A12
            if j < 16:
                TT1 = ((A ^ B_ ^ C) + D + SS2 + W_[j]) & 0xffffffff
                TT2 = ((E ^ F ^ G) + H + SS1 + W[j]) & 0xffffffff
            else:
                TT1 = (((A & B_) | (A & C) | (B_ & C)) + D + SS2 + W_[j]) & 0xffffffff
                TT2 = (((E & F) | ((~E) & G)) + H + SS1 + W[j]) & 0xffffffff
            D, C, B_, A = C, rotl(B_, 9), A, TT1
            H, G, F, E = G, rotl(F, 19), E, _p0(TT2)
        V = [a ^ b for a, b in zip(V, [A, B_, C, D, E, F, G, H])]
    return b''.join(struct.pack('>I', x) for x in V)


# ===== Merkle 树实现 =====
class MerkleTree:
    def __init__(self, leaves):
        self.leaves = [sm3_basic(leaf) for leaf in leaves]
        self.levels = []
        self.build()

    def build(self):
        self.levels = [self.leaves]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = []
            for i in range(0, len(cur), 2):
                if i + 1 < len(cur):
                    nxt.append(sm3_basic(cur[i] + cur[i+1]))
                else:
                    nxt.append(cur[i])
            self.levels.append(nxt)

    def root(self):
        return self.levels[-1][0]

    def prove_inclusion(self, leaf_index):
        proof = []
        idx = leaf_index
        for level in self.levels[:-1]:
            sibling = idx ^ 1
            if sibling < len(level):
                proof.append(level[sibling])
            idx //= 2
        return proof

    def prove_non_inclusion(self, leaf_data):
        leaf_hash = sm3_basic(leaf_data)
        if leaf_hash in self.leaves:
            return None
        return "非包含证明"

# ===== 主函数 =====
def main():
    data = os.urandom(1024 * 1024)  # 1MB 数据
    rounds = 5
    print("==== SM3 性能比较 ====")
    for name, func in [("基础实现", sm3_basic), ("优化实现", sm3_optimized)]:
        times = []
        for _ in range(rounds):
            start = time.perf_counter()
            func(data)
            end = time.perf_counter()
            times.append(end - start)
        avg_time = sum(times) / rounds
        print(f"{name} 每轮耗时: {[f'{t:.6f}' for t in times]} 秒")
        print(f"{name} 平均耗时: {avg_time:.6f} 秒\n")



    print("\n==== Merkle 树测试（小规模） ====")
    leaves = [f"leaf{i}".encode() for i in range(8)]
    tree = MerkleTree(leaves)
    print("Merkle 根:", tree.root().hex())
    proof = tree.prove_inclusion(3)
    print("叶子3的包含证明:", [p.hex() for p in proof])
    non_proof = tree.prove_non_inclusion(b"not_in_tree")
    print("非包含证明:", non_proof)

    print("\n==== Merkle 树构建（10万叶子）性能测试 ====")
    big_leaves = [f"leaf{i}".encode() for i in range(100_000)]
    start = time.perf_counter()
    MerkleTree(big_leaves)
    end = time.perf_counter()
    print(f"构建10万叶子节点的Merkle树耗时: {end - start:.3f} 秒")

if __name__ == "__main__":
    main()
