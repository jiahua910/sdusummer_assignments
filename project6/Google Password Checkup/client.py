import hashlib
import requests
from tinyec import registry, ec
import secrets

curve = registry.get_curve('secp192r1')
G = curve.g

m = 256
k = 3


def k_hashes(value: str, k: int, m: int):
    return [int(hashlib.sha256((value + str(i)).encode()).hexdigest(), 16) % m for i in range(k)]


def point_to_bytes(p):
    if p is None:
        return None
    x = p.x.to_bytes((p.x.bit_length() + 7) // 8, 'big')
    y_parity = p.y % 2
    return bytes([0x02 + y_parity]) + x


def bytes_to_point(hex_str):
    data = bytes.fromhex(hex_str)
    y_parity = data[0] - 0x02
    x = int.from_bytes(data[1:], 'big')

    p = curve.field.p
    a = curve.a
    b = curve.b

    # 计算 y^2 = x^3 + ax + b mod p
    y_squared = pow(x, 3, p) + (a * x) % p + b % p
    y_squared %= p

    # 计算平方根
    y = pow(y_squared, (p + 1) // 4, p)

    # 检查 y 的奇偶性是否匹配
    if y % 2 != y_parity:
        y = p - y

    # 使用 ec.Point 创建点
    return ec.Point(curve, x, y)


class ECCElGamal:
    def keygen(self):
        sk = secrets.randbelow(curve.field.n)
        pk = sk * G
        return sk, pk

    def encrypt(self, pk, m_int):
        M = m_int * G
        r = secrets.randbelow(curve.field.n)
        c1 = r * G
        c2 = M + r * pk
        return c1, c2

    def decrypt(self, sk, c1, c2):
        M = c2 - sk * c1
        for i in range(0, m):
            if i * G == M:
                return i
        return None


#客户端所存本地弱密码库
local_weak_passwords = {"123456", "654321"}


def run_protocol(password: str):
    if password in local_weak_passwords:
        print(f"密码 '{password}' 属于已知弱密码库")
        return

    elgamal = ECCElGamal()
    sk, pk = elgamal.keygen()
    positions = k_hashes(password, k, m)
    ciphertexts = [elgamal.encrypt(pk, pos) for pos in positions]
    serialized = [[point_to_bytes(c1).hex(), point_to_bytes(c2).hex()] for (c1, c2) in ciphertexts]

    response = requests.post("http://localhost:5000/check_password", json={
        "positions": positions,
        "ciphertexts": serialized
    })

    results = response.json()["masked_ciphertexts"]
    decrypted = []
    for i in range(k):
        c1 = bytes_to_point(results[i][0])
        c2 = bytes_to_point(results[i][1])
        m_dec = elgamal.decrypt(sk, c1, c2)
        decrypted.append(m_dec)

    print(f"Password: {password}")
    print(f"Original positions: {positions}")
    print(f"Decrypted results:  {decrypted}")
    if decrypted == positions:
        print("密码已泄露")
    else:
        print("密码未泄露")


if __name__ == "__main__":
    print("Password Checkup 客户端")
    while True:
        pw = input("请输入密码（exit退出）: ").strip()
        if pw.lower() == "exit":
            break
        run_protocol(pw)
        print()