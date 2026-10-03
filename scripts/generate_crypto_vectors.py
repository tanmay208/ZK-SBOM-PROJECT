"""
Authoritative Cryptographic Vector Generator — Stage 4.7.

Generates the `backend/shared/tests/vectors/crypto_vectors.json` fixture.

PROVENANCE:
The output of this script produces frozen regression fixtures derived from 
the previously validated Python/Noir 0.32.0 reference-vector execution 
and are subsequently treated as immutable test fixtures.

This script should NOT be run as part of the normal test suite.
The generated vectors are frozen and committed to source control as the
cryptographic ground truth.

Do NOT regenerate vectors merely because tests fail.
If tests fail against the frozen vectors, the implementation is broken.
"""

import json
import os
from backend.sbom_service.app.schemas.parsed_sbom import ParsedComponent
from backend.sbom_service.app.services.canonicalization import SBOMCanonicalizer
from backend.shared.utils.purl import canonicalize_purl
from backend.shared.crypto.field_encoding import encode_bytes_to_fields
from backend.shared.crypto.component_hash import hash_component
from backend.shared.crypto.merkle import compute_merkle_root

def generate_vectors():
    vectors = {
        "canonicalization": [],
        "purl": [],
        "byte_to_field": [],
        "component_hash": [],
        "merkle": [],
        "security": []
    }
    
    canonicalizer = SBOMCanonicalizer()
    
    def get_canonical_json(name, purl=None, version=None):
        comp = ParsedComponent(name=name, purl=purl, version=version)
        p_canon = None
        if purl:
            try:
                p_canon = canonicalize_purl(purl)
            except:
                p_canon = purl
        return canonicalizer._canonical_json(comp, p_canon)

    # 1. Canonicalization
    cases = [
        ("name only", "a", None, None),
        ("name + version", "a", None, "1.0"),
        ("name + purl", "a", "pkg:a/b", None),
        ("name + purl + version", "a", "pkg:a/b", "1.0"),
        ("purl absent", "a", None, "1.0"),
        ("version absent", "a", "pkg:a/b", None),
        ("both absent", "a", None, None)
    ]
    for desc, n, p, v in cases:
        cj = get_canonical_json(n, p, v)
        vectors["canonicalization"].append({
            "description": desc,
            "input": {"name": n, "purl": p, "version": v},
            "canonical_json": cj
        })

    # 2. PURL
    purl_cases = [
        ("normal valid", "pkg:npm/foo@1.0.0"),
        ("case normalization", "pkg:NPM/FOO@1.0.0"),
        ("pypi normalization", "pkg:pypi/My_Package@1.0"),
        ("qualifiers", "pkg:npm/foo@1.0.0?b=2&a=1"),
        ("subpaths", "pkg:npm/foo@1.0.0#sub/path"),
        ("invalid", "not_a_purl")
    ]
    for desc, p in purl_cases:
        try:
            canon = canonicalize_purl(p)
        except Exception as e:
            canon = "ERROR"
        vectors["purl"].append({
            "description": desc,
            "input": p,
            "canonical": canon
        })

    # 3. Byte-to-Field
    b_cases = [
        ("empty", b""),
        ("one-byte", b"a"),
        ("30-byte", b"a" * 30),
        ("31-byte", b"a" * 31),
        ("32-byte", b"a" * 32),
        ("ending in zero", b"a" * 30 + b"\x00"),
        ("high-bit UTF-8", "ñ".encode("utf-8")),
        ("unicode component", get_canonical_json("\U0001F600").encode("utf-8")),
        ("near-maximum valid", get_canonical_json("\U0001F600"*511, "pkg:a/" + "\U0001F600"*1018, "\U0001F600"*128).encode("utf-8")),
        ("maximum valid", get_canonical_json("\U0001F600"*512, "pkg:a/" + "\U0001F600"*1018, "\U0001F600"*128).encode("utf-8"))
    ]
    for desc, b in b_cases:
        fields = encode_bytes_to_fields(b)
        vectors["byte_to_field"].append({
            "description": desc,
            "input_hex": b.hex(),
            "original_length": len(b),
            "padded_length": len(b) + 1,
            "field_count": len(fields),
            "fields_hex": [hex(f) for f in fields]
        })

    # 4. Component Hash
    ch_cases = [
        ("minimal", get_canonical_json("a")),
        ("normal", get_canonical_json("my-pkg", "pkg:npm/my-pkg", "1.0.0")),
        ("purl only", get_canonical_json("purl-pkg", "pkg:pypi/my_pkg")),
        ("unicode", get_canonical_json("\U0001F600", None, "1.0\U0001F600")),
        ("long", get_canonical_json("a" * 512, "pkg:a/" + "b" * 1018, "1" * 128)),
        ("maximum valid", get_canonical_json("\U0001F600"*512, "pkg:a/" + "\U0001F600"*1018, "\U0001F600"*128))
    ]
    for desc, cj in ch_cases:
        h = hash_component(cj)
        b = cj.encode('utf-8')
        fields = encode_bytes_to_fields(b)
        vectors["component_hash"].append({
            "description": desc,
            "canonical_json": cj,
            "utf8_length": len(b),
            "unpadded_field_count": len(fields),
            "first_field": hex(fields[0]) if fields else None,
            "last_field": hex(fields[-1]) if fields else None,
            "hash": hex(h)
        })

    # 5. Merkle Tree
    h_a = hash_component(get_canonical_json("a"))
    h_b = hash_component(get_canonical_json("b"))
    h_c = hash_component(get_canonical_json("c"))
    h_d = hash_component(get_canonical_json("d"))
    h_e = hash_component(get_canonical_json("e"))
    
    mt_cases = [
        ("zero components", []),
        ("one component", [h_a]),
        ("two components", [h_a, h_b]),
        ("three components", [h_a, h_b, h_c]),
        ("four components", [h_a, h_b, h_c, h_d]),
        ("duplicate components", [h_a, h_a]),
        ("reordered components", [h_b, h_a]),
        ("multiple distinct", [h_a, h_b, h_c, h_d, h_e]),
        ("near power-of-two (7)", [h_a, h_b, h_c, h_d, h_e, h_a, h_b]),
        ("larger tree (15)", [h_a] * 15)
    ]
    for desc, leaves in mt_cases:
        root = compute_merkle_root(leaves)
        vectors["merkle"].append({
            "description": desc,
            "leaf_hashes": [hex(l) for l in leaves],
            "root": hex(root)
        })
        
    # 6. Security (Mutations)
    base_cj = get_canonical_json("base", "pkg:a/base", "1.0")
    base_h = hash_component(base_cj)
    
    mutations = [
        ("changing one character", get_canonical_json("casf", "pkg:a/base", "1.0")),
        ("changing version", get_canonical_json("base", "pkg:a/base", "1.1")),
        ("changing purl", get_canonical_json("base", "pkg:a/basf", "1.0"))
    ]
    for desc, cj in mutations:
        h = hash_component(cj)
        vectors["security"].append({
            "type": "hash_mutation",
            "description": desc,
            "base_hash": hex(base_h),
            "mutated_hash": hex(h),
            "is_different": h != base_h
        })

    base_tree = [h_a, h_b, h_c]
    base_root = compute_merkle_root(base_tree)
    tree_mutations = [
        ("changing component order", [h_b, h_a, h_c]),
        ("adding a duplicate", [h_a, h_b, h_c, h_a]),
        ("removing a component", [h_a, h_b]),
        ("replacing a component", [h_a, h_d, h_c]),
        ("truncating sequence", [h_a])
    ]
    for desc, tree in tree_mutations:
        root = compute_merkle_root(tree)
        vectors["security"].append({
            "type": "tree_mutation",
            "description": desc,
            "base_root": hex(base_root),
            "mutated_root": hex(root),
            "is_different": root != base_root
        })

    out_dir = os.path.join("backend", "shared", "tests", "vectors")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "crypto_vectors.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2, ensure_ascii=False)
    
    print(f"Vectors written to {out_path}")

if __name__ == "__main__":
    generate_vectors()
