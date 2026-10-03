import os
import subprocess
import shutil

def run_cmd(cmd, cwd):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr

def run_negative_test(name, mutation_func, expect_verify_fail=False):
    print(f"Running negative test: {name} ...", end=" ", flush=True)
    # Start from known good
    shutil.copy("segment_mid/Prover.toml.good", "segment_mid/Prover.toml")
    
    with open("segment_mid/Prover.toml", "r") as f:
        lines = f.readlines()
        
    lines = mutation_func(lines)
    
    with open("segment_mid/Prover.toml", "w") as f:
        f.writelines(lines)
        
    # Execute witness
    nargo = os.path.expanduser("~/.nargo/bin/nargo")
    bb = os.path.expanduser("~/.bb/bb")
    
    code, out, err = run_cmd([nargo, "execute", "segment_mid"], cwd="segment_mid")
    if not expect_verify_fail:
        if code != 0:
            print("PASS (Failed witness generation as expected)")
            return True
        else:
            print("FAIL (Witness generation succeeded unexpectedly)")
            return False
            
    # If expect verify fail, we generate a valid proof for a DIFFERENT circuit or manipulate the proof?
    # Actually, the prompt says "Every rejection must be documented".
    # For some attacks (like wrong component hash), the witness generation itself fails because `assert` fails in Noir.
    # But wait, in a true ZKP system, the prover might try to submit a valid proof for *different* public inputs.
    # To simulate a verifier rejection, we can change the public inputs in the `Verifier.toml`?
    # Noir 0.32 doesn't use Verifier.toml natively in `bb verify`, `bb verify` just verifies the proof against the vk.
    # But wait, `bb prove` embeds the public inputs in the proof.
    # If the prover changes private inputs, witness generation fails (if it violates assert).
    pass

def setup():
    # Save the known good prover
    shutil.copy("segment_mid/Prover.toml", "segment_mid/Prover.toml.good")

def main():
    setup()
    
    # Test 1: Modified hash_out_commit
    def mut1(lines):
        return [l.replace('hash_out_commit = "', 'hash_out_commit = "0x01') if l.startswith('hash_out_commit') else l for l in lines]
    run_negative_test("Modified hash_out_commit", mut1)

    # Test 2: Modified hash_in_commit
    def mut2(lines):
        return [l.replace('hash_in_commit = "', 'hash_in_commit = "0x01') if l.startswith('hash_in_commit') else l for l in lines]
    run_negative_test("Modified hash_in_commit", mut2)
    
    # Test 3: Wrong segment_index
    def mut3(lines):
        return [l.replace('segment_index = "1"', 'segment_index = "2"') if l.startswith('segment_index') else l for l in lines]
    run_negative_test("Wrong segment_index", mut3)

    # Test 4: Modified components_commit
    def mut4(lines):
        return [l.replace('components_commit = "', 'components_commit = "0x01') if l.startswith('components_commit') else l for l in lines]
    run_negative_test("Modified components_commit", mut4)
    
    # Test 5: Wrong component hash (breaks components_commit)
    def mut5(lines):
        return [l.replace('component = "', 'component = "0x01') if l.startswith('component =') else l for l in lines]
    run_negative_test("Wrong component hash", mut5)

    # Restore
    shutil.copy("segment_mid/Prover.toml.good", "segment_mid/Prover.toml")
    print("Negative tests completed.")

if __name__ == "__main__":
    main()
