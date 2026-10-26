import json
import subprocess
import os

with open('backend/shared/tests/vectors/crypto_vectors.json', 'r', encoding='utf-8') as f:
    vectors = json.load(f)

def hex_fmt(val): return f'0x{val:064x}'

os.chdir('scripts/noir_compatibility')

case = vectors['merkle'][0]
noir_code = ['use dep::std;', 'fn main() {']
active_count = len(case['leaf_hashes'])
noir_code.append(f'    let _leaves: [Field; 0] = [];')
noir_code.append(f'    let root = compute_merkle_root(_leaves);')
noir_code.append(f'    std::println(root);')
noir_code.append(f'    let expected = {hex_fmt(int(case["root"], 16))};')
noir_code.append(f'    std::println(expected);')
noir_code.append(f'    assert(root == expected);')
noir_code.append('}')

merkle_fn = """
fn compute_merkle_root<let N: u32>(leaves: [Field; N]) -> Field {
    let mut current_level_hashes: [Field; 1024] = [0; 1024];
    let empty_leaf = std::hash::poseidon::bn254::hash_1([0]);

    for i in 0..1024 {
        if i < N {
            current_level_hashes[i] = leaves[i];
        } else {
            current_level_hashes[i] = empty_leaf;
        }
    }

    let mut num_nodes = 1024;
    for _level in 0..10 {
        num_nodes = num_nodes / 2;
        for i in 0..512 {
            if i < num_nodes {
                let left = current_level_hashes[i * 2];
                let right = current_level_hashes[i * 2 + 1];
                current_level_hashes[i] = std::hash::poseidon::bn254::hash_2([left, right]);
            }
        }
    }
    current_level_hashes[0]
}
"""
noir_code.append(merkle_fn)

with open('src/main.nr', 'w') as f:
    f.write('\n'.join(noir_code))

res = subprocess.run(['wsl', '/home/kali/.nargo/bin/nargo', 'execute'], capture_output=True)
if res.returncode != 0:
    print('FAILED')
    print('STDOUT:', res.stdout.decode('utf-8'))
    print('STDERR:', res.stderr.decode('utf-8'))
else:
    print('PASSED')
    print('STDOUT:', res.stdout.decode('utf-8'))
