import json
from backend.shared.crypto.field_encoding import encode_bytes_to_fields

def analyze():
    # 1. Minimal component
    minimal = {"name": "a"}
    b_min = json.dumps(minimal, separators=(",", ":"), ensure_ascii=False).encode('utf-8')
    f_min = encode_bytes_to_fields(b_min)
    
    # 2. Typical component
    typical = {"name": "openssl", "purl": "pkg:pypi/openssl", "version": "1.1.1t"}
    b_typ = json.dumps(typical, separators=(",", ":"), ensure_ascii=False).encode('utf-8')
    f_typ = encode_bytes_to_fields(b_typ)
    
    # 3. Maximum allowed by Day 3 validation
    max_comp = {
        "name": "a" * 512,
        "purl": "pkg:a/" + "b" * 1018, # up to 1024
        "version": "v" * 128
    }
    b_max = json.dumps(max_comp, separators=(",", ":"), ensure_ascii=False).encode('utf-8')
    f_max = encode_bytes_to_fields(b_max)
    
    print(f"Minimal: {len(b_min)} bytes, {len(f_min)} fields")
    print(f"Typical: {len(b_typ)} bytes, {len(f_typ)} fields")
    print(f"Maximum: {len(b_max)} bytes, {len(f_max)} fields")

if __name__ == "__main__":
    analyze()
