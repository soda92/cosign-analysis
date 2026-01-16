import sys
from coss_client import CossClient

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py <AUTH_CODE> <PIN>")
        print("Example: python main.py '{\"type\":\"ACTIVEUSER\",...}' '123456'")
        sys.exit(1)
        
    code = sys.argv[1]
    pin = sys.argv[2]
    
    client = CossClient()
    try:
        client.register_with_auth_code(code)
        client.generate_keys(pin)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()