import requests
import time

BASE_URL = "http://api-gateway/api/v1"

upload_id = "542e6e26-8a44-4573-b209-e1f0fe580605"
snapshot_id = "67860175-0935-4770-853b-84ff0cd85d33"
sbom_root = "0x19885c209f550e127998ed816fca0d54a91810ad699ddad8cb73f6343e3ff5bc"
vulnerability_db_root = "0x1cfc169b50f494414cd8fd079178c0310fb404ba99bf84f430114bbf25845446"

def login(username, password):
    r = requests.post(
        f"{BASE_URL}/auth/login",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    r.raise_for_status()
    return r.json()["access_token"]

def main():
    print("STEP 1: Authentication")
    vendor_token = login("vendor", "password123")
    admin_token = login("admin", "password123")
    print("Tokens retrieved.")

    print("\nSTEP 6: Retrieve Policy (Admin)")
    r = requests.get(f"{BASE_URL}/policy", headers={"Authorization": f"Bearer {admin_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    policies = r.json()
    active_policy = next(p for p in policies if p.get("active") is True)
    policy_id = active_policy["id"]
    policy_hash = active_policy["policy_hash"]
    print(f"Policy ID: {policy_id}")
    print(f"Policy Hash: {policy_hash}")

    print("\nSTEP 7: Generate Proof (Vendor)")
    proof_payload = {
        "sbom_upload_id": upload_id,
        "snapshot_id": snapshot_id,
        "policy_id": policy_id
    }
    r = requests.post(f"{BASE_URL}/zkp/generate", json=proof_payload, headers={"Authorization": f"Bearer {vendor_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    job_data = r.json()
    job_id = job_data["id"]

    print("\nSTEP 8: Wait for Proof Completion")
    while True:
        r = requests.get(f"{BASE_URL}/zkp/jobs/{job_id}", headers={"Authorization": f"Bearer {vendor_token}"})
        status_data = r.json()
        status = status_data["status"]
        print(f"Job status: {status}")
        if status in ["completed", "failed"]:
            break
        time.sleep(2)
    
    if status == "failed":
        print("Proof generation failed!")
        return

    print("\nSTEP 9: Verify Proof (Vendor)")
    verify_payload = {
        "sbom_root": sbom_root,
        "vulnerability_db_root": vulnerability_db_root,
        "policy_hash": policy_hash,
        "proof_job_id": job_id
    }
    r = requests.post(f"{BASE_URL}/verification/verify", json=verify_payload, headers={"Authorization": f"Bearer {vendor_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    
    print("\nALL STEPS COMPLETED SUCCESSFULLY")

if __name__ == "__main__":
    main()
