import requests
import json
import base64
import secrets
import sys
import random

# SM2 Curve Parameters
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# Try to import gmssl for SM3, otherwise use a placeholder (user must install it)
try:
    from gmssl import sm3
except ImportError:
    print("Error: gmssl not installed. Please run: uv pip install gmssl")
    sys.exit(1)

class SM2Math:
    """
    Pure Python implementation of SM2 Elliptic Curve operations required for the protocol.
    """
    @staticmethod
    def inverse(a, n):
        return pow(a, n - 2, n)

    @staticmethod
    def point_add(P, Q):
        if P is None: return Q
        if Q is None: return P
        
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 != y2:
            return None
        
        if x1 == x2:
            m = (3 * x1 * x1 + SM2_A) * SM2Math.inverse(2 * y1, SM2_P)
        else:
            m = (y2 - y1) * SM2Math.inverse(x2 - x1, SM2_P)
            
        m = m % SM2_P
        x3 = (m * m - x1 - x2) % SM2_P
        y3 = (m * (x1 - x3) - y1) % SM2_P
        return (x3, y3)

    @staticmethod
    def point_mul(k, P):
        """Scalar multiplication: k * P"""
        R = None
        for i in range(k.bit_length() - 1, -1, -1):
            R = SM2Math.point_add(R, R)
            if (k >> i) & 1:
                R = SM2Math.point_add(R, P)
        return R

    @staticmethod
    def bytes_to_int(b):
        return int.from_bytes(b, 'big')

    @staticmethod
    def int_to_bytes(i, length=32):
        return i.to_bytes(length, 'big')

    @staticmethod
    def decode_point(b):
        """Decodes uncompressed (0x04) or compressed point"""
        if b[0] == 0x04:
            x = int.from_bytes(b[1:33], 'big')
            y = int.from_bytes(b[33:65], 'big')
            return (x, y)
        # Add compressed point handling if needed (rare in this specific protocol step)
        raise Exception("Unsupported point format")

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

class CossClient:
    def __init__(self, base_url="https://coss.bjca.org.cn", app_id="BJCA_COSS_APP"):
        self.base_url = base_url
        self.app_id = app_id
        # Hardcoded for reproducibility, in reality use random or real device ID
        self.imei = "865483011111111" 
        self.device_name = "Python_Client"
        self.os_version = "Android 14"
        self.access_token = None
        self.mssp_id = None
        self.policy = None
        self.key_map = {} # Stores the 'random_secret' (Share A)

    def register_with_auth_code(self, auth_code_str: str):
        url = f"{self.base_url}/mobile/v1/regwithauthcode"
        
        # Handle JSON auth code format
        real_auth_code = auth_code_str
        try:
            j = json.loads(auth_code_str)
            if j.get('type') == 'ACTIVEUSER':
                real_auth_code = j.get('data')
        except:
            pass

        payload = {
            "authCode": real_auth_code,
            "appId": self.app_id,
            "imei": self.imei,
            "appVersion": "2.1.2",
            "osVersion": self.os_version,
            "deviceName": self.device_name,
            "mobileID": ""
        }
        
        print(f"[*] Registering...")
        resp = requests.post(url, json=payload)
        resp_json = resp.json()
        
        if resp_json.get('status') != 200:
            raise Exception(f"Registration failed: {resp_json}")
            
        data = resp_json['data']
        self.access_token = data['accessToken']
        self.mssp_id = data['msspId']
        self.policy = json.loads(data['policy'])
        
        print(f"[+] Registered! MSSP_ID: {self.mssp_id}")
        return self.policy

    def generate_keys(self, pin: str):
        if not self.policy: raise Exception("Register first")
        
        url = f"{self.base_url}/mobile/v1/genkey"
        gen_key_list = []
        
        print(f"[*] Generating Keys...")
        
        for pol in self.policy.get('certPolicys', []):
            if pol.get('certGenType') == 'COORDINATION':
                # 1. Generate local secret (Share A)
                random_secret = secrets.token_bytes(32)
                self.key_map[pol['id']] = random_secret
                
                # 2. Compute ClientSecret to bind with PIN
                # Note: We send base64 string
                client_secret_bytes = CossCrypto.generate_client_secret(self.imei, random_secret, pin)
                client_secret_b64 = base64.b64encode(client_secret_bytes).decode('utf-8')
                
                gen_key_list.append({
                    "id": pol['id'],
                    "clientSecret": client_secret_b64
                })
        
        payload = {
            "data": json.dumps(gen_key_list),
            "accessToken": self.access_token
        }
        
        resp = requests.post(url, json=payload)
        resp_json = resp.json()
        
        if resp_json.get('status') != 200:
            raise Exception(f"GenKey failed: {resp_json}")
            
        server_data_str = resp_json['data']['data']
        server_data_list = json.loads(server_data_str)
        key_id = resp_json['data']['keyId']
        
        print("[+] Keys generated on server. Proceeding to Request Cert...")
        return self._request_cert(pin, server_data_list)

    def _request_cert(self, pin: str, server_params_list: list):
        url = f"{self.base_url}/mobile/v1/reqcert"
        
        req_list = []
        
        print(f"[*] Computing Co-Signatures for Certificate Request...")
        
        for param in server_params_list:
            policy_id = param['id']
            random_secret = self.key_map.get(policy_id)
            
            # Params from server
            sign_param_bytes = base64.b64decode(param['signParam']) # Point P
            hash_bytes = base64.b64decode(param['hash']) # Scalar e
            
            # Re-calculate our client secret (d_A)
            client_secret_bytes = CossCrypto.generate_client_secret(self.imei, random_secret, pin)
            
            # Perform SM2 Co-Sign Math (CollaborateUtil.serverSemSign)
            # Returns [s1, s2, s3] bytes
            res_bytes_list = CossCrypto.server_sem_sign(
                sign_param_bytes, 
                client_secret_bytes, 
                hash_bytes
            )
            
            # Format: Base64(s1);Base64(s2);Base64(s3)
            client_sign_str = ";".join([
                base64.b64encode(b).decode('utf-8') for b in res_bytes_list
            ])
            
            req_list.append({
                "id": policy_id,
                "clientSign": client_sign_str
            })
            
        payload = {
            "data": json.dumps(req_list),
            "accessToken": self.access_token
        }
        
        resp = requests.post(url, json=payload)
        resp_json = resp.json()
        
        if resp_json.get('status') != 200:
            raise Exception(f"ReqCert failed: {resp_json}")
            
        final_cert_list = json.loads(resp_json['data']['data'])
        
        print("\n[SUCCESS] Certificate Downloaded!")
        print("-" * 40)
        
        for cert_item in final_cert_list:
            cert_b64 = cert_item.get('cert')
            if cert_b64:
                print(f"Policy: {cert_item['id']}")
                print(f"Certificate (Base64): {cert_b64[:50]}...")
                # You can save this to a .cer file
                
        # Save keys for future login
        self._save_state()

    def _save_state(self):
        state = {
            "imei": self.imei,
            "mssp_id": self.mssp_id,
            "key_map": {k: base64.b64encode(v).decode('utf-8') for k, v in self.key_map.items()}
        }
        with open("coss_identity.json", "w") as f:
            json.dump(state, f, indent=2)
        print("[*] Identity saved to coss_identity.json")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python reproduce_coss.py <AUTH_CODE> <PIN>")
        sys.exit(1)
        
    code = sys.argv[1]
    pin = sys.argv[2]
    
    client = CossClient()
    client.register_with_auth_code(code)
    client.generate_keys(pin)