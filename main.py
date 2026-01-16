import sys
from coss_client import CossClient

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Register: python main.py register <QR_JSON> <PIN>")
        print("  Login:    python main.py login <QR_JSON> <PIN>")
        sys.exit(1)

    cmd = sys.argv[1]
    qr_code = sys.argv[2]
    pin = sys.argv[3]

    client = CossClient()

    try:
        if cmd == "register":
            client.register_with_auth_code(qr_code)
            client.generate_keys(pin)
        elif cmd == "login":
            client.login(qr_code, pin)
        else:
            print("Unknown command")
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
