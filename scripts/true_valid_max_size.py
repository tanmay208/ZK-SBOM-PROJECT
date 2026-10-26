import json
from backend.shared.crypto.field_encoding import encode_bytes_to_fields

def calculate_true_max_size():
    # 4-byte unicode characters (emojis) are NOT control characters, 
    # but they take 4 bytes per character in UTF-8.
    # The DB limits are character lengths.
    
    name_unicode = "\U0001F600" * 512
    version_unicode = "\U0001F600" * 128
    purl_unicode = "pkg:a/" + "\U0001F600" * (1024 - 6)
    
    obj_unicode = {
        "name": name_unicode,
        "purl": purl_unicode,
        "version": version_unicode,
    }
    
    b_unicode = json.dumps(obj_unicode, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode('utf-8')
    
    print(f"Max bytes with valid characters: {len(b_unicode)}")
    
    # Calculate fields
    fields = encode_bytes_to_fields(b'x' * len(b_unicode))
    print(f"Fields required: {len(fields)}")
    
if __name__ == "__main__":
    calculate_true_max_size()
