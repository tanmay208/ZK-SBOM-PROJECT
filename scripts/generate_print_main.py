import json
from backend.shared.crypto.field_encoding import encode_bytes_to_fields
from backend.shared.crypto.component_hash import MAX_COMPONENT_FIELDS, hash_component

comp_json = '{"name":"pkg:npm/left-pad","version":"1.3.0"}'
fields = encode_bytes_to_fields(comp_json.encode('utf-8'))
padded_fields = fields + [0] * (MAX_COMPONENT_FIELDS - len(fields))

def hex_fmt(val): return f"0x{val:064x}"
fields_str = ', '.join([hex_fmt(f) for f in padded_fields])

expected_h = hex_fmt(hash_component(comp_json))

noir_code = f"""
use dep::std;

fn main() {{
    let input: [Field; 216] = [{fields_str}];
    let h = std::hash::poseidon::bn254::sponge(input);
    std::println(h);
    std::println({expected_h});
}}
"""
with open('scripts/noir_compatibility/src/main.nr', 'w') as f:
    f.write(noir_code)
