import sys
import json
from coss_client.crypto.utils import CossCrypto

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decrypt_qr.py <QR_JSON_STRING>")
        sys.exit(1)

    qr_content = sys.argv[1]
    try:
        qr_json = json.loads(qr_content)
        if "o" in qr_json:
            decrypted = CossCrypto.decrypt_qr_o(qr_json["o"])
            print(f"Decrypted Content: {decrypted}")

            try:
                inner_json = json.loads(decrypted)
                print(f"Parsed Inner JSON: {json.dumps(inner_json, indent=2)}")
            except:
                print("Inner content is not JSON.")
        else:
            print("No 'o' field found in JSON.")
    except Exception as e:
        print(f"Error: {e}")
