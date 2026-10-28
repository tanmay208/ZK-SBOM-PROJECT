import os
import subprocess
import time

def poll_mem(proc, peak_vm_kb, peak_rss_kb):
    pid = proc.pid
    while proc.poll() is None:
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("VmPeak:"):
                        val = int(line.split()[1])
                        if val > peak_vm_kb[0]: peak_vm_kb[0] = val
                    if line.startswith("VmHWM:"):
                        val = int(line.split()[1])
                        if val > peak_rss_kb[0]: peak_rss_kb[0] = val
        except:
            pass
        time.sleep(0.05)

def run_cmd_mem(cmd, cwd):
    import threading
    peak_vm_kb = [0]
    peak_rss_kb = [0]
    start = time.time()
    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    t = threading.Thread(target=poll_mem, args=(proc, peak_vm_kb, peak_rss_kb))
    t.start()
    proc.wait()
    t.join()
    elapsed = time.time() - start
    return proc.returncode, elapsed, peak_rss_kb[0]/1024, peak_vm_kb[0]/1024, proc.stdout.read().decode(), proc.stderr.read().decode()

def run_cmd(cmd, cwd):
    start = time.time()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    elapsed = time.time() - start
    return proc.returncode, elapsed, proc.stdout, proc.stderr

def measure_segment(name):
    print(f"--- Measuring {name} ---")
    nargo = os.path.expanduser("~/.nargo/bin/nargo")
    bb = os.path.expanduser("~/.bb/bb")
    
    # 1. Compile
    code, c_time, c_rss, c_vm, out, err = run_cmd_mem([nargo, "compile"], cwd=name)
    print(f"Compile: code={code} time={c_time:.2f}s RSS={c_rss:.2f}MB VM={c_vm:.2f}MB")
    if code != 0:
        print(err)
        return
        
    circuit_size = os.path.getsize(f"{name}/target/{name}.json") / 1024 / 1024
    print(f"Circuit Size: {circuit_size:.2f}MB")
    
    # 2. Execute (Witness Generation)
    code, w_time, out, err = run_cmd([nargo, "execute", name], cwd=name)
    print(f"Witness Gen: code={code} time={w_time:.2f}s")
    if code != 0:
        print(err)
        return
        
    # 3. Write VK
    code, vk_time, out, err = run_cmd([bb, "write_vk", "-b", f"./target/{name}.json", "-o", "./target/vk"], cwd=name)
    print(f"Write VK: code={code} time={vk_time:.2f}s")
    
    # 4. Prove
    code, p_time, out, err = run_cmd([bb, "prove", "-b", f"./target/{name}.json", "-w", f"./target/{name}.gz", "-o", "./target/proof"], cwd=name)
    print(f"Prove: code={code} time={p_time:.2f}s")
    if code != 0:
        print(err)
        return
        
    proof_size = os.path.getsize(f"{name}/target/proof") / 1024
    print(f"Proof Size: {proof_size:.2f}KB")
    
    # 5. Verify
    code, v_time, out, err = run_cmd([bb, "verify", "-k", "./target/vk", "-p", "./target/proof"], cwd=name)
    print(f"Verify: code={code} time={v_time:.2f}s result={'SUCCESS' if code == 0 else 'FAIL'}")

if __name__ == "__main__":
    measure_segment("segment_init_32")
    measure_segment("segment_mid_32")
    measure_segment("segment_final_32")
