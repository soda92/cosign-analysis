import base64
import secrets
import sys
from .sm2 import SM2Math, SM2_N, SM2_Gx, SM2_Gy

# Try to import gmssl for SM3
try:
    from gmssl import sm3
except ImportError:
    print("Error: gmssl not installed. Please run: uv pip install gmssl")
    sys.exit(1)

class CossCrypto:
    @staticmethod
    def sm3_hash(data: bytes) -> bytes:
        hasher = sm3.SM3()
        hasher.update(data)
        return bytes.fromhex(hasher.digest())

    @staticmethod
    def xor_bytes(b1: bytes, b2: bytes) -> bytes:
        target = bytearray(b1 if len(b1) >= len(b2) else b2)
        source = b1 if len(b1) < len(b2) else b2
        for i in range(min(len(b1), len(b2))):
            target[i] ^= source[i]
        return bytes(target)

    @staticmethod
    def generate_client_secret(imei: str, random_secret: bytes, pin: str) -> bytes:
        """
        Replicates utils.a.a logic: b(b(hash(IMEI), hash(PIN)), random_secret)
        Returns RAW bytes (not base64) for use in math.
        """
        h_imei = CossCrypto.sm3_hash(imei.encode('utf-8'))
        h_pin = CossCrypto.sm3_hash(pin.encode('utf-8'))
        xor1 = CossCrypto.xor_bytes(h_imei, h_pin)
        return CossCrypto.xor_bytes(xor1, random_secret)

    @staticmethod
    def server_sem_sign(sign_param_point_bytes, client_secret_bytes, hash_scalar_bytes):
        """
        Replicates CollaborateUtil.serverSemSign logic.
        """
        # 1. Parse Inputs
        # bArr -> Point P (SignParam)
        P = SM2Math.decode_point(sign_param_point_bytes)
        
        # bArr2 -> Scalar d (ClientSecret)
        d_client = SM2Math.bytes_to_int(client_secret_bytes)
        
        # bArr3 -> Scalar e (Hash)
        e_val = SM2Math.bytes_to_int(hash_scalar_bytes)
        
        # 2. Generate Randoms k1, k2
        k1 = secrets.randbelow(SM2_N)
        k2 = secrets.randbelow(SM2_N)
        
        # 3. Curve Math
        # P1 = k1 * P
        P1 = SM2Math.point_mul(k1, P)
        
        # P2 = k2 * G
        G = (SM2_Gx, SM2_Gy)
        P2 = SM2Math.point_mul(k2, G)
        
        # R = P1 + P2
        R = SM2Math.point_add(P1, P2)
        
        # r = R.x
        r_x = R[0]
        
        # 4. Result Calculation
        # res[0] = (r_x + e) % n
        s1 = (r_x + e_val) % SM2_N
        
        # res[1] = (d_client * k1) % n
        s2 = (d_client * k1) % SM2_N
        
        # res[2] = (d_client * (s1 + k2)) % n
        s3 = (d_client * (s1 + k2)) % SM2_N
        
        return [
            SM2Math.int_to_bytes(s1),
            SM2Math.int_to_bytes(s2),
            SM2Math.int_to_bytes(s3)
        ]
