use dep::std;
fn main() {
    let _leaves: [Field; 0] = [];
    let root = compute_merkle_root(_leaves);
    std::println(root);
    let expected = 0x0b01ab3090cbdc900fab5c56945ae060c3c43471a6c421235e5c9fb7d9d08382;
    std::println(expected);
    assert(root == expected);
}

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
