import sys
import json
import zlib

def parse_tnetstring(data):
    """
    Parses a TNetString from bytes.
    Returns (value, remainder_bytes)
    Format: length:value,
    """
    if not data:
        return None, b""
    
    try:
        if b':' not in data:
            return None, b""
            
        colon_index = data.index(b':')
        length_str = data[:colon_index]
        if not length_str.isdigit():
             return None, b""
             
        length = int(length_str)
        
        start_data = colon_index + 1
        end_data = start_data + length
        
        if end_data >= len(data):
            return None, b"" # Incomplete
            
        type_char = data[end_data:end_data+1] # The type tag
        
        value_bytes = data[start_data:end_data]
        remainder = data[end_data+1:]
        
        if type_char == b'}': # Dictionary
            value = {}
            while value_bytes:
                k, value_bytes = parse_tnetstring(value_bytes)
                v, value_bytes = parse_tnetstring(value_bytes)
                if k is not None:
                    # key is usually bytes, decode to string if possible
                    if isinstance(k, bytes):
                        k = k.decode('utf-8', errors='ignore')
                    value[k] = v
        elif type_char == b']': # List
            value = []
            while value_bytes:
                v, value_bytes = parse_tnetstring(value_bytes)
                value.append(v)
        elif type_char == b'#': # Integer
            value = int(value_bytes)
        elif type_char == b'^': # Float
            value = float(value_bytes)
        elif type_char == b'!': # Boolean
            value = value_bytes == b'true'
        elif type_char == b'~': # Null
            value = None
        elif type_char == b',': # String (bytes)
            value = value_bytes
        else:
            value = value_bytes # Unknown

        return value, remainder
    except Exception as e:
        return None, b""

def decode_flow(flow_data):
    """
    Extracts relevant info from a flow dictionary.
    """
    if not isinstance(flow_data, dict):
        return
    
    req = flow_data.get('request')
    res = flow_data.get('response')
    
    if not req:
        return

    method = req.get('method', b'').decode() if isinstance(req.get('method'), bytes) else str(req.get('method'))
    scheme = req.get('scheme', b'').decode() if isinstance(req.get('scheme'), bytes) else str(req.get('scheme'))
    host = req.get('host', b'').decode() if isinstance(req.get('host'), bytes) else str(req.get('host'))
    port = req.get('port')
    path = req.get('path', b'').decode() if isinstance(req.get('path'), bytes) else str(req.get('path'))
    
    url = f"{scheme}://{host}:{port}{path}"
    
    print(f"=== {method} {url} ===")
    
    # Request Body
    req_content = req.get('content')
    if req_content:
        # Check for gzip
        headers = req.get('headers', [])
        # Headers in TNetString are usually a list of [name, value]
        is_gzip = False
        # Mitmproxy headers format varies by version, sometimes dict, sometimes list of tuples
        if isinstance(headers, dict):
             for k, v in headers.items():
                 if k.lower() == 'content-encoding' and 'gzip' in v.lower():
                     is_gzip = True
        elif isinstance(headers, list):
            for h in headers:
                # h might be [b'name', b'value']
                if len(h) >= 2:
                    k = h[0].decode().lower() if isinstance(h[0], bytes) else str(h[0]).lower()
                    v = h[1].decode().lower() if isinstance(h[1], bytes) else str(h[1]).lower()
                    if k == 'content-encoding' and 'gzip' in v:
                        is_gzip = True
        
        if is_gzip:
            try:
                req_content = zlib.decompress(req_content, 16+zlib.MAX_WBITS)
            except:
                pass

        try:
            json_body = json.loads(req_content)
            print("Request Body:")
            print(json.dumps(json_body, indent=2, ensure_ascii=False))
        except:
            pass # print(f"Request Body (Raw): {req_content[:200]}...")

    # Response Body
    if res:
        status = res.get('status_code')
        print(f"Response Status: {status}")
        
        res_content = res.get('content')
        if res_content:
            headers = res.get('headers', [])
            is_gzip = False
            if isinstance(headers, dict):
                 for k, v in headers.items():
                     if k.lower() == 'content-encoding' and 'gzip' in v.lower():
                         is_gzip = True
            elif isinstance(headers, list):
                for h in headers:
                    if len(h) >= 2:
                        k = h[0].decode().lower() if isinstance(h[0], bytes) else str(h[0]).lower()
                        v = h[1].decode().lower() if isinstance(h[1], bytes) else str(h[1]).lower()
                        if k == 'content-encoding' and 'gzip' in v:
                            is_gzip = True
            
            if is_gzip:
                try:
                    res_content = zlib.decompress(res_content, 16+zlib.MAX_WBITS)
                except:
                    pass

            try:
                json_body = json.loads(res_content)
                print("Response Body:")
                print(json.dumps(json_body, indent=2, ensure_ascii=False))
            except:
                pass # print(f"Response Body (Raw): {res_content[:200]}...")
    
    print("\n" + "-"*50 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_flows.py <flows_file>")
        sys.exit(1)
        
    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Try to parse concatenated TNetStrings
    offset = 0
    while offset < len(data):
        # Find next TNetString
        # This is a naive parser that assumes valid tnetstring stream
        try:
            # We pass a slice, but efficient parsing would pass index. 
            # For simplicity with the recursive func, we slice.
            val, remainder = parse_tnetstring(data[offset:])
            if val is None and not remainder:
                break
            
            # If we got a value, 'val' is the flow object
            if val:
                decode_flow(val)
            
            # Calculate how much we consumed
            consumed = len(data[offset:]) - len(remainder)
            if consumed == 0:
                break
            offset += consumed
            
        except Exception as e:
            # print(f"Error parsing at offset {offset}: {e}")
            break
