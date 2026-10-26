import os
import shutil
import subprocess
import time

def run_feasibility_test():
    n = 64
    bench_dir = f"circuits_exp_{n}"
    if os.path.exists(bench_dir):
        shutil.rmtree(bench_dir)
    
    # We will copy from circuits_dev because circuits has the arithmetic predication changes
    shutil.copytree("circuits_dev", bench_dir)
    
    # Modify for 64 components
    main_path = os.path.join(bench_dir, "src", "main.nr")
    with open(main_path, "r") as f:
        main_content = f.read()
    
    main_content = main_content.replace("global MAX_COMPONENTS: u32 = 8;", f"global MAX_COMPONENTS: u32 = {n};")
    main_content = main_content.replace("components: [Field; 8]", f"components: [Field; {n}]")
    main_content = main_content.replace("vulnerability_scores: [u32; 8]", f"vulnerability_scores: [u32; {n}]")
    main_content = main_content.replace("vulnerability_smt_paths: [[Field; 3]; 8]", f"vulnerability_smt_paths: [[Field; 256]; {n}]") # Must preserve SMT depth 256
    main_content = main_content.replace("for i in 0..8 {", f"for i in 0..{n} {{")
    
    with open(main_path, "w") as f:
        f.write(main_content)
        
    merkle_path = os.path.join(bench_dir, "src", "merkle.nr")
    with open(merkle_path, "r") as f:
        merkle_content = f.read()
        
    # In circuits_dev, it's 8.
    merkle_content = merkle_content.replace("pub fn compute_merkle_root(active_leaves: [Field; 8]", f"pub fn compute_merkle_root(active_leaves: [Field; {n}]")
    merkle_content = merkle_content.replace("let mut current_level_hashes: [Field; 8] = [0; 8];", f"let mut current_level_hashes: [Field; {n}] = [0; {n}];")
    merkle_content = merkle_content.replace("for i in 0..8 {", f"for i in 0..{n} {{")
    merkle_content = merkle_content.replace("let mut num_nodes = 8;", f"let mut num_nodes = {n};")
    merkle_content = merkle_content.replace("for _level in 0..3 {", f"for _level in 0..6 {{") # log2(64) = 6
    merkle_content = merkle_content.replace("for i in 0..4 {", f"for i in 0..32 {{") # 64/2 = 32
    
    with open(merkle_path, "w") as f:
        f.write(merkle_content)

    smt_path = os.path.join(bench_dir, "src", "smt.nr")
    with open(smt_path, "r") as f:
        smt_content = f.read()
        
    smt_content = smt_content.replace("path: [Field; 3]", "path: [Field; 256]")
    smt_content = smt_content.replace("for i in 0..3 {", "for i in 0..256 {")
    
    with open(smt_path, "w") as f:
        f.write(smt_content)

    print("Running feasibility test...")
    
    # We will poll /proc/PID/status for VmPeak and VmHWM
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
            time.sleep(0.1)

    start_time = time.time()
    nargo_path = os.path.expanduser("~/.nargo/bin/nargo")
    try:
        proc = subprocess.Popen(
            [nargo_path, "compile"], 
            cwd=bench_dir, 
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
        stdout = proc.stdout.read().decode('utf-8')
        stderr = proc.stderr.read().decode('utf-8')
    except subprocess.TimeoutExpired:
        proc.kill()
        exit_code = 124
        stdout = ""
        stderr = "Timeout"

    end_time = time.time()
    elapsed = end_time - start_time
    
    status = "SUCCESS" if exit_code == 0 else "FAIL"
    print(f"Status: {status} (Exit Code {exit_code})")
    print(f"Time: {elapsed:.2f}s")
    print(f"Peak RSS: {peak_rss_kb/1024:.2f} MB")
    print(f"Peak VM: {peak_vm_kb/1024:.2f} MB")
    if exit_code != 0:
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")

if __name__ == '__main__':
    run_feasibility_test()
