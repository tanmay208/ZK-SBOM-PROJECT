use dep::std;

fn main(x: Field, y: pub Field) {
    assert(x != y);
}

#[test]
fn test_merkle_4() {
    let h1 = std::hash::poseidon::bn254::hash_1([1]);
    let h2 = std::hash::poseidon::bn254::hash_1([2]);
    let h3 = std::hash::poseidon::bn254::hash_1([3]);
    let h4 = std::hash::poseidon::bn254::hash_1([4]);
    
    let internal1 = std::hash::poseidon::bn254::hash_2([h1, h2]);
    let internal2 = std::hash::poseidon::bn254::hash_2([h3, h4]);
    
    let root = std::hash::poseidon::bn254::hash_2([internal1, internal2]);
    std::println(root);
}
