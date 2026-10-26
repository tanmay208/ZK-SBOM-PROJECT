import os
import shutil
import subprocess
import time
import json

def generate_circuit(components, depth, exp_dir):
    if os.path.exists(exp_dir):
        shutil.rmtree(exp_dir)
    os.makedirs(exp_dir)
    os.makedirs(os.path.join(exp_dir, "src"))
    
    with open(os.path.join(exp_dir, "Nargo.toml"), "w") as f:
        f.write('[package]\nname = "smt_exp"\ntype = "bin"\nauthors = [""]\ncompiler_version = "0.32.0"\n')
        
    main_code = f"""
mod smt;

fn main(
    vulnerability_db_root: pub Field,
    components: [Field; {components}],
    vulnerability_scores: [u32; {components}],
    vulnerability_smt_paths: [[Field; {depth}]; {components}]
) {{
    for i in 0..{components} {{
        let leaf = std::hash::poseidon::bn254::hash_2([components[i], vulnerability_scores[i] as Field]);
        smt::verify_smt_path(vulnerability_db_root, components[i], leaf, vulnerability_smt_paths[i]);
    }}
}}
"""
    with open(os.path.join(exp_dir, "src", "main.nr"), "w") as f:
        f.write(main_code)
        
    smt_code = f"""
use dep::std;

pub fn verify_smt_path(root: Field, key: Field, leaf_value: Field, path: [Field; {depth}]) {{
    let mut current_hash = leaf_value;
    let key_bits = key.to_le_bits({depth});

    for i in 0..{depth} {{
        let is_right = key_bits[i];

        let mut left = path[i];
        let mut right = current_hash;

        if is_right == 0 {{
            left = current_hash;
            right = path[i];
        }}

        current_hash = std::hash::poseidon::bn254::hash_2([left, right]);
    }}

    assert(current_hash == root);
}}
"""
    with open(os.path.join(exp_dir, "src", "smt.nr"), "w") as f:
        f.write(smt_code)

def run_test(components, depth):
    exp_dir = f"circuits_exp_{components}c_{depth}d"
    generate_circuit(components, depth, exp_dir)
    
    print(f"Testing {components} components at depth {depth}...")
    
    import threading
    peak_vm_kb = 0
    peak_rss_kb = 0
    
    def poll_mem(proc):
        nonlocal peak_vm_kb, peak_rss_kb
        pid = proc.pid
        while proc.poll() is None:
            try:
                with open(f"/proc/{pid}/status", "r") as f:
                    for line in f:
                        if line.startswith("VmPeak:"):
                            val = int(line.split()[1])
                            if val > peak_vm_kb: peak_vm_kb = val
                        if line.startswith("VmHWM:"):
                            val = int(line.split()[1])
                            if val > peak_rss_kb: peak_rss_kb = val
            except:
                pass
            time.sleep(0.05)

    start_time = time.time()
    nargo_path = os.path.expanduser("~/.nargo/bin/nargo")
    try:
        proc = subprocess.Popen(
            [nargo_path, "compile"], 
            cwd=exp_dir, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        t = threading.Thread(target=poll_mem, args=(proc,))
        t.start()
        try:
            import sys
            sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))
            from shared.crypto.config import get_crypto_profile
            timeout_seconds = get_crypto_profile().proof_timeout_seconds
        except Exception:
            timeout_seconds = 300

        proc.wait(timeout=timeout_seconds)
        t.join()
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        exit_code = 124
        t.join()

    end_time = time.time()
    elapsed = end_time - start_time
    
    artifact_path = os.path.join(exp_dir, "target", "smt_exp.json")
    artifact_size = os.path.getsize(artifact_path) if os.path.exists(artifact_path) else 0
    
    status = "SUCCESS" if exit_code == 0 else "FAIL"
    
    return {
        "components": components,
        "depth": depth,
        "status": status,
        "exit_code": exit_code,
        "elapsed_s": elapsed,
        "peak_rss_mb": peak_rss_kb / 1024,
        "peak_vm_mb": peak_vm_kb / 1024,
        "artifact_mb": artifact_size / 1024 / 1024
    }

def main():
    results = []
    
    # Part 1: SMT Depth Scaling (1 component)
    for depth in [16, 32, 64, 128, 256]:
        res = run_test(1, depth)
        results.append(res)
        
    # Part 2: Component Scaling (at depth 32)
    # Only if depth 32 succeeded for 1 component
    depth_32_success = next((r for r in results if r["depth"] == 32 and r["status"] == "SUCCESS"), None)
    if depth_32_success:
        for c in [2, 4, 8]:
            res = run_test(c, 32)
            results.append(res)
            
    with open("smt_scaling_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("DONE")

if __name__ == '__main__':
    main()
