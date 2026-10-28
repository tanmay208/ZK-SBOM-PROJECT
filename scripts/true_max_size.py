import json
from backend.shared.crypto.field_encoding import encode_bytes_to_fields
import math

def calculate_max_size():
    # Maximum escaping expansion is \uXXXX which is 6 bytes for 1 char.
    # Control characters \x00 to \x1f are escaped this way, except \b \t \n \f \r which use 2 bytes.
    # So using \x01 maximizes the length.
    
    # 1. 4-byte unicode characters
    name_unicode = "\U0001F600" * 512 # 4 bytes each
    version_unicode = "\U0001F600" * 128
    purl_unicode = "pkg:a/" + "\U0001F600" * (1024 - 6) # PURL must start with pkg:a/
    
    obj_unicode = {
        "name": name_unicode,
        "purl": purl_unicode,
        "version": version_unicode,
    }
    b_unicode = json.dumps(obj_unicode, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode('utf-8')
    
    # 2. Control characters (escaped)
    name_ctrl = "\x01" * 512
    version_ctrl = "\x01" * 128
    purl_ctrl = "pkg:a/" + "\x01" * (1024 - 6)
    
    obj_ctrl = {
        "name": name_ctrl,
        "purl": purl_ctrl,
        "version": version_ctrl,
    }
    b_ctrl = json.dumps(obj_ctrl, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode('utf-8')

    print(f"Max Unicode bytes: {len(b_unicode)}")
    print(f"Max Ctrl (escaped) bytes: {len(b_ctrl)}")
    
    max_b = max(len(b_unicode), len(b_ctrl))
    
    # Now compute the max fields for this max bytes
    max_fields = len(encode_bytes_to_fields(b'x' * max_b))
    print(f"Theoretical Max Bytes: {max_b}")
    print(f"Theoretical Max Fields: {max_fields}")
    
    # Let's also check if 1024 is the correct number
    # PURL regex is `^pkg:[a-z]+/`. So the shortest prefix is `pkg:a/` (6 chars). The rest can be \x01.
    
if __name__ == "__main__":
    calculate_max_size()
