import requests
import json
import time

BASE_URL = "http://api-gateway/api/v1"

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
    importer_token = login("trusted_importer", "password123")
    admin_token = login("admin", "password123")
    print("Tokens retrieved.")

    print("\nSTEP 2: SBOM Upload (Vendor)")
    sbom_payload = {
        "application_name": "MyApp",
        "vendor": "ACME Corp",
        "format": "CycloneDX",
        "content": '{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"library","name":"requests","version":"2.25.1","purl":"pkg:pypi/requests@2.25.1"}]}'
    }
    r = requests.post(f"{BASE_URL}/sbom/upload", json=sbom_payload, headers={"Authorization": f"Bearer {vendor_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    sbom_data = r.json()
    upload_id = sbom_data["upload_id"]
    sbom_root = sbom_data["sbom_root"]

    print("\nSTEP 3: Vulnerability Ingestion (Trusted Importer)")
    vuln_payload = {
        "source_identity": "NVD",
        "provenance": {"feed_version": "test"},
        "vulnerabilities": [
            {"purl": "pkg:pypi/requests@2.25.1", "cvss_score": 7.5}
        ]
    }
    r = requests.post(f"{BASE_URL}/vulnerability/ingest", json=vuln_payload, headers={"Authorization": f"Bearer {importer_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    snapshot_data = r.json()
    snapshot_id = snapshot_data["snapshot_id"]

    print("\nSTEP 4: Approve Snapshot (Admin)")
    r = requests.post(f"{BASE_URL}/vulnerability/snapshots/{snapshot_id}/approve", headers={"Authorization": f"Bearer {admin_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()

    print("\nSTEP 5: Freeze Snapshot (Admin)")
    r = requests.post(f"{BASE_URL}/vulnerability/snapshots/{snapshot_id}/freeze", headers={"Authorization": f"Bearer {admin_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    freeze_data = r.json()
    assert r.status_code == 200, f"Expected status 200, got {r.status_code}"
    assert freeze_data["id"] == snapshot_id, "Snapshot ID mismatch"
    assert freeze_data["status"] == "frozen", "Snapshot status is not frozen"
    vulnerability_db_root = freeze_data["authoritative_smt_root"]
    assert vulnerability_db_root and isinstance(vulnerability_db_root, str), "authoritative_smt_root is missing or empty"

    print("\nSTEP 6: Retrieve Policy (Admin)")
    r = requests.get(f"{BASE_URL}/policy", headers={"Authorization": f"Bearer {admin_token}"})
    print(r.status_code, r.text)
    r.raise_for_status()
    policies = r.json()
    active_policy = next(p for p in policies if p["status"] == "active")
    policy_id = active_policy["id"]
    policy_hash = active_policy["policy_hash"]

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
