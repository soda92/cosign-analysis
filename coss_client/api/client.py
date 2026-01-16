import requests
import json
import base64
import secrets
import os
import time
from urllib.parse import urlparse
from ..crypto.utils import CossCrypto

# Disable warnings for self-signed certs (mitmproxy)
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CossClient:
    DEFAULT_APP_ID = "APP_09613F880BA343DC95E31B17096A0471"

    def __init__(
        self,
        base_url="https://coss.bjca.org.cn",
        app_id=None,
        state_file="coss_identity.json",
    ):
        self.base_url = base_url
        self.app_id = app_id or self.DEFAULT_APP_ID
        self.state_file = state_file

        self.device_name = "Python_Client"
        self.os_version = "Android 14"
        self.access_token = None
        self.mssp_id = None
        self.policy = None
        self.key_map = {}

        # Proxy settings (reads env vars)
        self.session = requests.Session()
        self.session.verify = False

        self._load_or_generate_identity()

    def _get_trans_id(self):
        ts = str(int(time.time() * 1000))
        return ts.encode("utf-8").hex()

    def _load_or_generate_identity(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)

                self.imei = data.get("imei")
                if not self.imei:
                    raise ValueError("IMEI missing in state file")

                print(f"[*] Loaded existing identity: IMEI={self.imei}")

                self.mssp_id = data.get("mssp_id")
                if data.get("base_url"):
                    self.base_url = data.get("base_url")
                if data.get("app_id"):
                    self.app_id = data.get("app_id")

                key_map_b64 = data.get("key_map", {})
                self.key_map = {k: base64.b64decode(v) for k, v in key_map_b64.items()}

                return
            except Exception as e:
                print(f"[!] Failed to load state file: {e}")

        self.imei = CossCrypto.generate_fake_imei()
        print(f"[*] Generated new identity: IMEI={self.imei}")

    def register_with_auth_code(self, qr_content: str):
        real_auth_code, _ = self._parse_qr(qr_content)

        url = f"{self.base_url}/mobile/v1/regwithauthcode"

        payload = {
            "authCode": real_auth_code,
            "appId": self.app_id,
            "imei": self.imei,
            "appVersion": "2.1.2",
            "osVersion": self.os_version,
            "deviceName": self.device_name,
            "mobileID": "",
            "transId": self._get_trans_id(),
            "version": "1.0",
        }

        print(f"[*] Registering with code: {real_auth_code[:10]}...")
        resp = self.session.post(url, json=payload)
        resp_json = resp.json()

        if resp_json.get("status") != 200:
            raise Exception(f"Registration failed: {resp_json}")

        data = resp_json["data"]
        self.access_token = data["accessToken"]
        self.mssp_id = data["msspId"]
        self.policy = json.loads(data["policy"])

        print(f"[+] Registered! MSSP_ID: {self.mssp_id}")
        self._save_state()
        return self.policy

    def generate_keys(self, pin: str):
        if not self.policy:
            raise Exception("Register first")

        url = f"{self.base_url}/mobile/v1/genkey"
        gen_key_list = []

        print(f"[*] Generating Keys...")

        for pol in self.policy.get("certPolicys", []):
            if pol.get("certGenType") == "COORDINATION":
                random_secret = secrets.token_bytes(32)
                self.key_map[pol["id"]] = random_secret

                client_secret_scalar = CossCrypto.calculate_client_secret_scalar(
                    self.imei, random_secret, pin
                )
                client_secret_point = CossCrypto.calculate_client_secret_point(
                    client_secret_scalar
                )
                client_secret_b64 = base64.b64encode(client_secret_point).decode(
                    "utf-8"
                )

                gen_key_list.append(
                    {"id": pol["id"], "clientSecret": client_secret_b64}
                )

        payload = {
            "data": json.dumps(gen_key_list),
            "accessToken": self.access_token,
            "transId": self._get_trans_id(),
            "version": "1.0",
        }

        resp = self.session.post(url, json=payload)
        resp_json = resp.json()

        if resp_json.get("status") != 200:
            raise Exception(f"GenKey failed: {resp_json}")

        server_data_str = resp_json["data"]["data"]
        server_data_list = json.loads(server_data_str)

        print("[+] Keys generated on server. Proceeding to Request Cert...")
        return self._request_cert(pin, server_data_list)

    def _request_cert(self, pin: str, server_params_list: list):
        url = f"{self.base_url}/mobile/v1/reqcert"

        req_list = []

        print(f"[*] Computing Co-Signatures for Certificate Request...")

        for param in server_params_list:
            policy_id = param["id"]
            random_secret = self.key_map.get(policy_id)

            sign_param_bytes = base64.b64decode(param["signParam"])
            hash_bytes = base64.b64decode(param["hash"])

            client_secret_scalar = CossCrypto.calculate_client_secret_scalar(
                self.imei, random_secret, pin
            )

            res_bytes_list = CossCrypto.server_sem_sign(
                sign_param_bytes, client_secret_scalar, hash_bytes
            )

            client_sign_str = ";".join(
                [base64.b64encode(b).decode("utf-8") for b in res_bytes_list]
            )

            req_list.append({"id": policy_id, "clientSign": client_sign_str})

        payload = {
            "data": json.dumps(req_list),
            "accessToken": self.access_token,
            "transId": self._get_trans_id(),
            "version": "1.0",
        }

        resp = self.session.post(url, json=payload)
        resp_json = resp.json()

        if resp_json.get("status") != 200:
            raise Exception(f"ReqCert failed: {resp_json}")

        final_cert_list = json.loads(resp_json["data"]["data"])

        print("\n[SUCCESS] Certificate Downloaded!")
        print("-" * 40)

        for cert_item in final_cert_list:
            cert_b64 = cert_item.get("cert")
            if cert_b64:
                print(f"Policy: {cert_item['id']}")
                print(f"Certificate (Base64): {cert_b64[:50]}...")

        self._save_state()

    def login(self, qr_content: str, pin: str):
        if not self.key_map:
            raise Exception("No keys found. Please register/download cert first.")

        job_data, type_val = self._parse_qr(qr_content)
        sign_job_id = job_data

        self._user_login()

        print(f"[*] Initializing Sign Job: {sign_job_id}")
        url_init = f"{self.base_url}/mobile/v1/signinit"
        payload_init = {
            "signJobId": sign_job_id,
            "accessToken": self.access_token,
            "transId": self._get_trans_id(),
            "version": "1.0",
        }
        resp = self.session.post(url_init, json=payload_init)
        resp_init = resp.json()

        if resp_init.get("status") != 200:
            raise Exception(f"SignInit failed: {resp_init}")

        sign_data = resp_init["data"]

        policy_id = "4"
        random_secret = self.key_map.get(policy_id)
        if not random_secret:
            policy_id = list(self.key_map.keys())[0]
            random_secret = self.key_map[policy_id]

        print(f"[*] Computing Signature using Policy {policy_id}...")

        sign_param_bytes = base64.b64decode(sign_data["signParame"])
        hash_bytes = base64.b64decode(sign_data["data"])

        client_secret_scalar = CossCrypto.calculate_client_secret_scalar(
            self.imei, random_secret, pin
        )

        res_bytes_list = CossCrypto.server_sem_sign(
            sign_param_bytes, client_secret_scalar, hash_bytes
        )

        client_sign_str = ";".join(
            [base64.b64encode(b).decode("utf-8") for b in res_bytes_list]
        )

        url_finish = f"{self.base_url}/mobile/v1/signfinish"
        payload_finish = {
            "clientSignature": client_sign_str,
            "signJobId": sign_job_id,
            "accessToken": self.access_token,
            "transId": self._get_trans_id(),
            "version": "1.0",
        }

        resp = self.session.post(url_finish, json=payload_finish)
        resp_finish = resp.json()

        if resp_finish.get("status") != 200:
            raise Exception(f"SignFinish failed: {resp_finish}")

        print("\n[SUCCESS] Login/Signing Complete!")
        print(f"Server Signature: {resp_finish['data'].get('signature')}")

    def _user_login(self):
        url = f"{self.base_url}/mobile/v1/userlogin"
        # TODO: Implement full login if needed
        pass

    def _parse_qr(self, qr_content):
        real_data = qr_content
        type_val = "UNKNOWN"
        try:
            qr_json = json.loads(qr_content)

            if "sUrl" in qr_json:
                if "/mobile/" in qr_json["sUrl"]:
                    self.base_url = qr_json["sUrl"].split("/mobile/")[0]
                else:
                    self.base_url = qr_json["sUrl"]
            if "id" in qr_json:
                self.app_id = qr_json["id"]

            if "o" in qr_json:
                decrypted = CossCrypto.decrypt_qr_o(qr_json["o"])
                try:
                    inner = json.loads(decrypted)
                    real_data = inner.get("data", decrypted)
                    type_val = inner.get("type", "UNKNOWN")
                except:
                    real_data = decrypted

        except json.JSONDecodeError:
            pass

        return real_data, type_val

    def _save_state(self):
        state = {
            "imei": self.imei,
            "mssp_id": self.mssp_id,
            "key_map": {
                k: base64.b64encode(v).decode("utf-8") for k, v in self.key_map.items()
            },
            "base_url": self.base_url,
            "app_id": self.app_id,
        }
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)
        print(f"[*] Identity saved to {self.state_file}")
