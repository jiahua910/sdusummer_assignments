from flask import Flask, request, jsonify
from bitarray import bitarray
from tinyec import registry
import hashlib
import secrets
from tinyec import registry, ec

app = Flask(__name__)


curve = registry.get_curve('secp192r1')
G = curve.g

m = 256
k = 3


def k_hashes(value: str, k: int, m: int):
    return [int(hashlib.sha256((value + str(i)).encode()).hexdigest(), 16) % m for i in range(k)]


class BloomFilter:
    def __init__(self, size, k):
        self.size = size
        self.k = k
        self.bits = bitarray(size)
        self.bits.setall(0)

    def add(self, value: str):
        for pos in k_hashes(value, self.k, self.size):
            self.bits[pos] = 1


class ECCElGamal:
    def homomorphic_mask(self, c1, c2):
        r = secrets.randbelow(curve.field.n)
        return c1, c2 + r * G


def point_to_bytes(p):
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
    y_squared %= p  # 确保在模 p 范围内

    # 计算平方根
    y = pow(y_squared, (p + 1) // 4, p)

    # 检查 y 的奇偶性是否匹配
    if y % 2 != y_parity:
        y = p - y


    return ec.Point(curve, x, y)



elgamal = ECCElGamal()
#服务器端已泄露密码
leaked_db = ["password", "qwerty"]
bf = BloomFilter(m, k)
for pwd in leaked_db:
    bf.add(pwd)


@app.route("/check_password", methods=["POST"])
def check_password():
    data = request.get_json()
    positions = data["positions"]
    ciphertexts = data["ciphertexts"]

    processed = []
    for i in range(len(positions)):
        pos = positions[i]
        c1 = bytes_to_point(ciphertexts[i][0])
        c2 = bytes_to_point(ciphertexts[i][1])
        if bf.bits[pos]:
            processed.append([point_to_bytes(c1).hex(), point_to_bytes(c2).hex()])
        else:
            mc1, mc2 = elgamal.homomorphic_mask(c1, c2)
            processed.append([point_to_bytes(mc1).hex(), point_to_bytes(mc2).hex()])

    return jsonify({"masked_ciphertexts": processed})


if __name__ == "__main__":
    app.run(port=5000, debug=True)