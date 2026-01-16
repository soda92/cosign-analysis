import requests
import json
import base64
import secrets
import os
from urllib.parse import urlparse
from ..crypto.utils import CossCrypto

class CossClient:
    def __init__(self, base_url="https://coss.bjca.org.cn", app_id="BJCA_COSS_APP", state_file="coss_identity.json"):
        self.base_url = base_url
        self.app_id = app_id
        self.state_file = state_file
        
        self.device_name = "Python_Client"
        self.os_version = "Android 14"
        self.access_token = None
        self.mssp_id = None
        self.policy = None
        self.key_map = {} 
        
        self._load_or_generate_identity()

    def _load_or_generate_identity(self):
        """Loads IMEI and keys from state file, or generates a new random IMEI."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    
                self.imei = data.get("imei")
                if not self.imei:
                    raise ValueError("IMEI missing in state file")
                
                print(f"[*] Loaded existing identity: IMEI={self.imei}")
                
                # Load other fields if they exist (useful for re-running or login)
                self.mssp_id = data.get("mssp_id")
                if data.get("base_url"):
                    self.base_url = data.get("base_url")
                
                # Restore keys (stored as Base64 strings)
                key_map_b64 = data.get("key_map", {})
                self.key_map = {k: base64.b64decode(v) for k, v in key_map_b64.items()}
                
                return
            except Exception as e:
                print(f"[!] Failed to load state file: {e}")
        
        # Generate new random IMEI (15 digits, starting with 86 for China)
        # 86 + 13 random digits
        suffix = "".join([str(secrets.randbelow(10)) for _ in range(13)])
        self.imei = f"86{suffix}"
        print(f"[*] Generated new identity: IMEI={self.imei}")

    def register_with_auth_code(self, qr_content: str):
        # 1. Parse QR JSON
        try:
            qr_json = json.loads(qr_content)
            
            # Update Base URL if present
            if 'sUrl' in qr_json:
                if '/mobile/' in qr_json['sUrl']:
                    self.base_url = qr_json['sUrl'].split('/mobile/')[0]
                else:
                    self.base_url = qr_json['sUrl']
                print(f"[*] Updated Base URL: {self.base_url}")

            # Decrypt 'o' field
            if 'o' in qr_json:
                decrypted_o = CossCrypto.decrypt_qr_o(qr_json['o'])
                print(f"[*] Decrypted 'o': {decrypted_o}")
                # This should be JSON: {"type":"ACTIVEUSER","data":"..."}
                o_json = json.loads(decrypted_o)
                if o_json.get('type') == 'ACTIVEUSER':
                    real_auth_code = o_json.get('data')
                else:
                    real_auth_code = decrypted_o # Fallback
            else:
                real_auth_code = qr_content # Raw string fallback

        except json.JSONDecodeError:
            # Maybe it's just the raw auth code string
            real_auth_code = qr_content

        url = f"{self.base_url}/mobile/v1/regwithauthcode"
        
        payload = {
            "authCode": real_auth_code,
            "appId": self.app_id,
            "imei": self.imei,
            "appVersion": "2.1.2",
            "osVersion": self.os_version,
            "deviceName": self.device_name,
            "mobileID": ""
        }
        
        print(f"[*] Registering with code: {real_auth_code[:10]}...")
        resp = requests.post(url, json=payload)
        resp_json = resp.json()
        
        if resp_json.get('status') != 200:
            raise Exception(f"Registration failed: {resp_json}")
            
        data = resp_json['data']
        self.access_token = data['accessToken']
        self.mssp_id = data['msspId']
        self.policy = json.loads(data['policy'])
        
        print(f"[+] Registered! MSSP_ID: {self.mssp_id}")
        
        # Save state immediately after registration to persist MSSP_ID/URL
        self._save_state()
        
        return self.policy

    def generate_keys(self, pin: str):
        if not self.policy: raise Exception("Register first")
        
        url = f"{self.base_url}/mobile/v1/genkey"
        gen_key_list = []
        
        print(f"[*] Generating Keys...")
        
        for pol in self.policy.get('certPolicys', []):
            if pol.get('certGenType') == 'COORDINATION':
                random_secret = secrets.token_bytes(32)
                self.key_map[pol['id']] = random_secret
                
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
            
            sign_param_bytes = base64.b64decode(param['signParam']) 
            hash_bytes = base64.b64decode(param['hash']) 
            
            client_secret_bytes = CossCrypto.generate_client_secret(self.imei, random_secret, pin)
            
            res_bytes_list = CossCrypto.server_sem_sign(
                sign_param_bytes, 
                client_secret_bytes, 
                hash_bytes
            )
            
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
            "key_map": {k: base64.b64encode(v).decode('utf-8') for k, v in self.key_map.items()},
            "base_url": self.base_url
        }
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)
        print(f"[*] Identity saved to {self.state_file}")
