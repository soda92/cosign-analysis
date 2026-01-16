import requests
import base64
import io
import json
from pathlib import Path
from coss_client import CossClient

# Optional: Auto-decode QR
try:
    from pyzbar.pyzbar import decode
    from PIL import Image

    HAS_ZBAR = True
except ImportError:
    HAS_ZBAR = False
    print("[*] pyzbar/pillow not installed. You must scan qr.jpg manually.")
    print("    Install them with: uv pip install pyzbar pillow")


def fetch_and_process(user_id, pin="123456"):
    url = "http://192.168.6.88:10082/jkdadx/application/modules/jsp/regdown"
    print(f"[*] Fetching QR for user: {user_id}...")

    try:
        resp = requests.post(url, data={"inputValue": user_id})
        if resp.status_code != 200:
            print(f"[-] HTTP Error: {resp.status_code}")
            return

        j = resp.json()
        b64_img = j.get("jsCode")
        if not b64_img:
            print("[-] No jsCode in response")
            return

        if b64_img.startswith("data:image"):
            b64_img = b64_img.split(",")[1]

        img_data = base64.b64decode(b64_img)

        with open("qr.jpg", "wb") as f:
            f.write(img_data)
        print("[+] QR Code saved to 'qr.jpg'.")

        qr_content = None
        if HAS_ZBAR:
            try:
                img = Image.open(io.BytesIO(img_data))
                decoded = decode(img)
                if decoded:
                    qr_content = decoded[0].data.decode("utf-8")
                    print(f"[+] Decoded QR: {qr_content}")
                else:
                    print("[-] Could not decode QR code from image.")
            except Exception as e:
                print(f"[-] QR Decode error: {e}")

        if not qr_content:
            print("[!] Please scan 'qr.jpg' and enter the string below:")
            qr_content = input("QR String > ").strip()

        if not qr_content:
            return

        print("\n[*] Starting CossClient Flow...")
        client = CossClient()

        print("\n1. Registering...")
        client.register_with_auth_code(qr_content)

        print("\n2. Generating Keys & Downloading Cert...")
        client.generate_keys(pin)

        print("\n[SUCCESS] Flow complete.")

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    if not Path("coss_identity.json").exists():
        print("[-] Error: coss_identity.json not found. Please create it with 'user_id' field.")
        exit(1)
        
    file = json.loads(Path("coss_identity.json").read_text())
    uid = file.get("user_id")
    
    if not uid:
        print("[-] Error: 'user_id' not found in coss_identity.json")
        exit(1)

    pin = "123456"

    fetch_and_process(uid, pin)
