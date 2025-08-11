import hashlib, random, time
from dataclasses import dataclass
from typing import Tuple

ALLOW_REAL_POC = False
CONFIRM_AUTHORIZED = False
PARAM_SET = "toy"

def inv_mod(x: int, m: int) -> int:
    x = x % m
    if x == 0:
        raise ZeroDivisionError(f"inv_mod: denominator is 0 mod {m}")
    return pow(x, -1, m)

def sha256_int(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

@dataclass
class CurveParams:
    p: int; a: int; b: int; Gx: int; Gy: int; n: int

# curve（素数 p，G 在曲线上）
TOY = CurveParams(p=197, a=0, b=7, Gx=42, Gy=107, n=191)

def load_real_sm2_params() -> CurveParams:
    p  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    a  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
    b  = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
    return CurveParams(p=p, a=a, b=b, Gx=gx, Gy=gy, n=n)

# 点与算术
Point = Tuple[int,int]
O = (None, None)
def is_o(P): return P[0] is None

def point_add(P: Point, Q: Point, curve: CurveParams) -> Point:
    if is_o(P): return Q
    if is_o(Q): return P
    p, a = curve.p, curve.a
    x1, y1 = P[0] % p, P[1] % p
    x2, y2 = Q[0] % p, Q[1] % p
    if (x1 - x2) % p == 0 and (y1 + y2) % p == 0:
        return O
    if (x1 - x2) % p == 0 and (y1 - y2) % p == 0:
        denom = (2 * y1) % p
        lam = ((3 * x1 * x1 + a) * inv_mod(denom, p)) % p
    else:
        denom = (x2 - x1) % p
        lam = ((y2 - y1) * inv_mod(denom, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_neg(P: Point, curve: CurveParams) -> Point:
    if is_o(P): return P
    return (P[0], (-P[1]) % curve.p)

def scalar_mul_naive(k: int, P: Point, curve: CurveParams) -> Point:
    if k % curve.n == 0 or is_o(P): return O
    Q = O; N = P; kk = k % curve.n
    while kk > 0:
        if kk & 1: Q = point_add(Q, N, curve)
        N = point_add(N, N, curve)
        kk >>= 1
    return Q

# 简单 wNAF
def wnaf(k: int, w: int):
    if k == 0: return [0]
    res=[]
    while k>0:
        if k&1:
            mod = 1<<w
            val = k%mod
            if val >= (1<<(w-1)): val -= mod
            res.append(val); k -= val
        else:
            res.append(0)
        k >>= 1
    return res

def scalar_mul_wnaf(k:int,P:Point,curve:CurveParams,width:int=4)->Point:
    if k%curve.n==0 or is_o(P): return O
    limit = 1 << (width-1)
    pre={}
    for i in range(1, limit, 2):
        pre[i] = scalar_mul_naive(i, P, curve)
    w = wnaf(k, width)
    Q = O
    for d in reversed(w):
        Q = point_add(Q, Q, curve)
        if d != 0:
            if d>0: Q = point_add(Q, pre[d], curve)
            else: Q = point_add(Q, point_neg(pre[-d], curve), curve)
    return Q

# 签名/验签（教学版）
def ecdsa_sign(msg: bytes, d: int, curve: CurveParams, k: int):
    n = curve.n
    e = sha256_int(msg) % n
    P = scalar_mul_naive(k, (curve.Gx, curve.Gy), curve)
    r = P[0] % n
    s = (inv_mod(k, n) * (e + d * r)) % n
    return r, s

def ecdsa_verify(msg: bytes, Q: Point, sig, curve: CurveParams):
    n = curve.n
    r,s = sig
    if not (1<=r<n and 1<=s<n): return False
    e = sha256_int(msg) % n
    w = inv_mod(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    P1 = scalar_mul_naive(u1, (curve.Gx, curve.Gy), curve)
    P2 = scalar_mul_naive(u2, Q, curve)
    R = point_add(P1, P2, curve)
    if is_o(R): return False
    return (R[0] % n) == r

def sm2_sign(msg: bytes, d: int, curve: CurveParams, k: int):
    n = curve.n
    e = sha256_int(msg) % n
    P = scalar_mul_naive(k, (curve.Gx, curve.Gy), curve)
    x1 = P[0] % n
    r = (e + x1) % n
    s = (inv_mod(1 + d, n) * (k - r * d)) % n
    return r, s

def sm2_verify(msg: bytes, Q: Point, sig, curve: CurveParams):
    n = curve.n
    r,s = sig
    if not (1<=r<n and 1<=s<n): return False
    e = sha256_int(msg) % n
    t = (r + s) % n
    P1 = scalar_mul_naive(s, (curve.Gx, curve.Gy), curve)
    P2 = scalar_mul_naive(t, Q, curve)
    R = point_add(P1, P2, curve)
    if is_o(R): return False
    x1 = R[0] % n
    return r == ((e + x1) % n)

# -------------------------
# Verbose PoC1: ECDSA 重用 k
# -------------------------
def poc_ecdsa_nonce_reuse_demo_verbose(curve: CurveParams):
    print("=== PoC1: ECDSA 重用 nonce k 导致私钥泄露")
    d = random.randint(2, curve.n-2)
    k = random.randint(2, curve.n-2)
    Q = scalar_mul_naive(d, (curve.Gx, curve.Gy), curve)
    m1 = b"Message-A"
    m2 = b"Message-B"
    r1, s1 = ecdsa_sign(m1, d, curve, k)
    r2, s2 = ecdsa_sign(m2, d, curve, k)
    n = curve.n
    e1 = sha256_int(m1) % n
    e2 = sha256_int(m2) % n

    print("\n已知：两条签名 (r1,s1), (r2,s2) 使用同一 nonce k。")
    print("ECDSA 签名公式:")
    print("  s = k^{-1} (e + d*r)  （模 n）")
    print("于是对两条消息有：")
    print("  s1 = k^{-1}(e1 + d*r1)")
    print("  s2 = k^{-1}(e2 + d*r2)")
    print("减两式得： s1 - s2 = k^{-1} (e1 - e2)  =>  k = (e1 - e2) * inv(s1 - s2)")
    num = (e1 - e2) % n
    den = (s1 - s2) % n
    print(f"\n计算中间量 (模 n={n}):")
    print(f"  e1 = {e1}")
    print(f"  e2 = {e2}")
    print(f"  s1 = {s1}")
    print(f"  s2 = {s2}")
    print(f"  num = e1 - e2 = {num}")
    print(f"  den = s1 - s2 = {den}")
    try:
        k_rec = (num * inv_mod(den, n)) % n
    except ZeroDivisionError as ex:
        print("  无法求逆：s1 - s2 在模 n 下为 0，示例退化，请重试。")
        raise
    print(f"  恢复的 k = {k_rec}")

    # 使用 k 恢复私钥 d： s1 = k^{-1} (e1 + d*r1) => d = (s1*k - e1) * inv(r1)
    d_rec = ((s1 * k_rec - e1) * inv_mod(r1, n)) % n
    print(f"  恢复的 d = {d_rec}")
    print(f"  原始 d   = {d}")
    print("验证：", "成功" if d_rec == d else "失败")
    assert d_rec == d
    print("=== PoC1 完成 ===\n")

# -------------------------
# Verbose PoC2: ECDSA + SM2 共用 k
# -------------------------
def poc_mix_sm2_ecdsa_nonce_reuse_demo_verbose(curve: CurveParams):
    d = random.randint(2, curve.n-2)
    k = random.randint(2, curve.n-2)
    re, se = ecdsa_sign(b"ECDSA-msg", d, curve, k)
    rs, ss = sm2_sign(b"SM2-msg", d, curve, k)
    n = curve.n
    ee = sha256_int(b"ECDSA-msg") % n
    # 列出两个算法的等式（教学版）
    print("\n已知：")
    print("  ECDSA: k = (e_e + d * r_e) * inv(s_e)  （等式 1）")
    print("  SM2  : k = s_s*(1 + d) + r_s * d        （等式 2）")
    print("将两式相等并整理，得到线性方程（关于 d）：")
    print("  (re - se*ss - se*rs) * d = (se*ss - ee)  （模 n）")
    A = (re - se * ss - se * rs) % n
    B = (se * ss - ee) % n
    print(f"\n中间量 (模 n={n}): A = {A}, B = {B}")
    if A % n == 0:
        print("退化情况：A == 0（模 n），本次示例不可解，请重试以获得非退化样本。")
        raise RuntimeError("degenerate sample")
    d_rec = (B * inv_mod(A, n)) % n
    print(f"  恢复的 d = {d_rec}")
    print(f"  原始 d   = {d}")
    print("验证：", "成功" if d_rec == d else "失败")
    assert d_rec == d
    print("=== PoC2 完成 ===\n")

# -------------------------
# Verbose ForgeSim: 用恢复到的私钥伪造签名（toy 模拟）
# -------------------------
def simulate_forge_after_recovery_verbose(curve: CurveParams, max_try=16):
    print("流程：用 PoC1 中恢复到的私钥，签名一个任意消息并验证")
    d = random.randint(2, curve.n-2)
    k = random.randint(2, curve.n-2)
    # 先制造两条使用同 k 的 ECDSA 签名，从中恢复私钥
    m1 = b"Tx-A"
    m2 = b"Tx-B"
    r1, s1 = ecdsa_sign(m1, d, curve, k)
    r2, s2 = ecdsa_sign(m2, d, curve, k)
    n = curve.n
    e1 = sha256_int(m1) % n
    e2 = sha256_int(m2) % n
    k_rec = ((e1 - e2) * inv_mod((s1 - s2) % n, n)) % n
    d_rec = ((s1 * k_rec - e1) * inv_mod(r1, n)) % n
    print(f"  恢复到的私钥 d_rec = {d_rec}（原始 d = {d}）")
    # 尝试用 d_rec 签名任意消息，并验证；小曲线上有时会产生退化签名，故用重试机制
    fake_msg = b"Satoshi simulation (toy)"
    success = False
    for i in range(max_try):
        k2 = random.randint(2, curve.n-2)
        try:
            sig = ecdsa_sign(fake_msg, d_rec, curve, k2)
        except Exception as ex:
            # 退化签名，重试
            continue
        Q = scalar_mul_naive(d_rec, (curve.Gx, curve.Gy), curve)
        ok = ecdsa_verify(fake_msg, Q, sig, curve)
        print(f"  尝试 {i+1}: 使用 k2={k2} 生成签名 {sig}，验证结果 = {ok}")
        if ok:
            success = True
            break
    print("伪造结果：", "成功" if success else "失败（多次重试未产生有效签名）")


# -------------------------
# 性能比较（打印中文）
# -------------------------
def perf_compare_scalar_mul(curve: CurveParams, iters=200):
    print("=== 性能比较（朴素 vs wNAF） ===")
    P = (curve.Gx, curve.Gy)
    scalars = [random.randint(1, curve.n-1) for _ in range(iters)]
    t0 = time.perf_counter()
    for k in scalars: scalar_mul_naive(k, P, curve)
    t_naive = time.perf_counter() - t0
    t1 = time.perf_counter()
    for k in scalars: scalar_mul_wnaf(k, P, curve, width=4)
    t_wnaf = time.perf_counter() - t1
    print(f"  朴素总耗时（{iters} 次）: {t_naive:.6f} s")
    print(f"  wNAF 总耗时（{iters} 次）: {t_wnaf:.6f} s")
    if t_wnaf>0:
        print(f"  近似加速比: {t_naive / t_wnaf:.2f}x")
    print()

# -------------------------
# 主流程
# -------------------------
def get_curve_for_poc():
    if PARAM_SET == "real" and ALLOW_REAL_POC and CONFIRM_AUTHORIZED:
        return load_real_sm2_params()
    return TOY

def main():
    random.seed(42)
    curve = get_curve_for_poc()
    perf_compare_scalar_mul(curve, iters=400)
    poc_ecdsa_nonce_reuse_demo_verbose(curve)
    poc_mix_sm2_ecdsa_nonce_reuse_demo_verbose(curve)
    simulate_forge_after_recovery_verbose(curve)

if __name__ == "__main__":
    main()
