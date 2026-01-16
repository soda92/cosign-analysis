import requests
import json
import base64
import secrets
from ..crypto.utils import CossCrypto

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
