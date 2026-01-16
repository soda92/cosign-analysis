import base64
import secrets
import sys
import hashlib
from .sm2 import SM2Math, SM2_N, SM2_Gx, SM2_Gy

# Using gmssl for SM3
try:
    from gmssl import sm3, func
except ImportError:
    print("Error: gmssl not installed. Please run: uv pip install gmssl")
    sys.exit(1)


class CossCrypto:
    @staticmethod
    def sm3_hash(data: bytes) -> bytes:
        data_list = func.bytes_to_list(data)
        hex_digest = sm3.sm3_hash(data_list)
        return bytes.fromhex(hex_digest)

    @staticmethod
    def sha1_hash(data: bytes) -> bytes:
        return hashlib.sha1(data).digest()

    @staticmethod
    def xor_bytes(b1: bytes, b2: bytes) -> bytes:
        target = bytearray(b1 if len(b1) >= len(b2) else b2)
        source = b1 if len(b1) < len(b2) else b2
        for i in range(min(len(b1), len(b2))):
            target[i] ^= source[i]
        return bytes(target)

    @staticmethod
    def decrypt_qr_o(encrypted_b64: str) -> str:
        data = base64.b64decode(encrypted_b64)
        key = b"MSSPoper@2018"

        result = bytearray(len(data))
        key_idx = 0

        for i in range(len(data)):
            key_idx += 1
            if key_idx == len(key):
                key_idx = 0

            result[i] = data[i] ^ key[key_idx]

        return result.decode("utf-8")

    @staticmethod
    def calculate_client_secret_scalar(
        imei: str, random_secret: bytes, pin: str
    ) -> bytes:
        h_imei = CossCrypto.sm3_hash(imei.encode("utf-8"))
        h_pin = CossCrypto.sm3_hash(pin.encode("utf-8"))
        xor1 = CossCrypto.xor_bytes(h_imei, h_pin)
        return CossCrypto.xor_bytes(xor1, random_secret)

    @staticmethod
    def calculate_client_secret_point(scalar_bytes: bytes) -> bytes:
        """
        Calculates P = d^-1 * G (Inverse!)
        Based on Java: this.provider.SM2PointMul(null, this.provider.bigIntegerModInverse(bArr, ...))
        """
        d = SM2Math.bytes_to_int(scalar_bytes)

        # Calculate Modular Inverse of d
        d_inv = SM2Math.inverse(d, SM2_N)

        G = (SM2_Gx, SM2_Gy)
        P = SM2Math.point_mul(d_inv, G)

        x_bytes = SM2Math.int_to_bytes(P[0])
        y_bytes = SM2Math.int_to_bytes(P[1])

        return b"\x04" + x_bytes + y_bytes

    @staticmethod
    def java_bigint_to_bytes(num):
        """
        Emulates Java BigInteger.toByteArray()
        Returns signed big-endian representation with minimal bytes.
        """
        if num == 0:
            return b"\x00"

        bit_len = num.bit_length()
        byte_len = (bit_len + 8) // 8

        b = num.to_bytes(byte_len, "big", signed=False)

        if b[0] & 0x80:
            return b"\x00" + b
        return b

    @staticmethod
    def server_sem_sign(sign_param_point_bytes, client_secret_bytes, hash_scalar_bytes):
        P = SM2Math.decode_point(sign_param_point_bytes)
        d_client = SM2Math.bytes_to_int(client_secret_bytes)
        e_val = SM2Math.bytes_to_int(hash_scalar_bytes)

        # Use range [1, N-1]
        k1 = 1 + secrets.randbelow(SM2_N - 1)
        k2 = 1 + secrets.randbelow(SM2_N - 1)

        P1 = SM2Math.point_mul(k1, P)
        G = (SM2_Gx, SM2_Gy)
        P2 = SM2Math.point_mul(k2, G)
        R = SM2Math.point_add(P1, P2)
        r_x = R[0]

        s1 = (r_x + e_val) % SM2_N
        s2 = (d_client * k1) % SM2_N
        s3 = (d_client * (s1 + k2)) % SM2_N

        return [
            CossCrypto.java_bigint_to_bytes(s1),
            CossCrypto.java_bigint_to_bytes(s2),
            CossCrypto.java_bigint_to_bytes(s3),
        ]

    @staticmethod
    def generate_fake_imei(package_name="cn.org.bjca.signet.coss.app") -> str:
        android_id = secrets.token_hex(8)
        combined = android_id + package_name
        hashed = CossCrypto.sha1_hash(combined.encode("utf-8"))
        return base64.b64encode(hashed).decode("utf-8")
