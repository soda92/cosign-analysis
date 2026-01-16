import base64
import secrets
import sys
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
    def xor_bytes(b1: bytes, b2: bytes) -> bytes:
        target = bytearray(b1 if len(b1) >= len(b2) else b2)
        source = b1 if len(b1) < len(b2) else b2
        for i in range(min(len(b1), len(b2))):
            target[i] ^= source[i]
        return bytes(target)

    @staticmethod
    def decrypt_qr_o(encrypted_b64: str) -> str:
        """
        Replicates utils.a.a(String str) to decrypt the 'o' field in QR JSON.
        Key is 'MSSPoper@2018'.
        Logic: XOR with cyclic key, but key index is (i+1)%key_len.
        """
        data = base64.b64decode(encrypted_b64)
        key = b"MSSPoper@2018"
        
        result = bytearray(len(data))
        key_idx = 0
        
        for i in range(len(data)):
            # Java: i++; if (i == len) i=0; xor key[i]
            # This means for data[0], we use key[1].
            key_idx += 1
            if key_idx == len(key):
                key_idx = 0
            
            result[i] = data[i] ^ key[key_idx]
            
        return result.decode('utf-8')

    @staticmethod
    def generate_client_secret(imei: str, random_secret: bytes, pin: str) -> bytes:
        h_imei = CossCrypto.sm3_hash(imei.encode('utf-8'))
        h_pin = CossCrypto.sm3_hash(pin.encode('utf-8'))
        xor1 = CossCrypto.xor_bytes(h_imei, h_pin)
        return CossCrypto.xor_bytes(xor1, random_secret)

    @staticmethod
    def server_sem_sign(sign_param_point_bytes, client_secret_bytes, hash_scalar_bytes):
        P = SM2Math.decode_point(sign_param_point_bytes)
        d_client = SM2Math.bytes_to_int(client_secret_bytes)
        e_val = SM2Math.bytes_to_int(hash_scalar_bytes)
        
        k1 = secrets.randbelow(SM2_N)
        k2 = secrets.randbelow(SM2_N)
        
        P1 = SM2Math.point_mul(k1, P)
        G = (SM2_Gx, SM2_Gy)
        P2 = SM2Math.point_mul(k2, G)
        R = SM2Math.point_add(P1, P2)
        r_x = R[0]
        
        s1 = (r_x + e_val) % SM2_N
        s2 = (d_client * k1) % SM2_N
        s3 = (d_client * (s1 + k2)) % SM2_N
        
        return [
            SM2Math.int_to_bytes(s1),
            SM2Math.int_to_bytes(s2),
            SM2Math.int_to_bytes(s3)
        ]
