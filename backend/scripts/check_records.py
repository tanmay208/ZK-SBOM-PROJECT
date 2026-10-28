import os
import psycopg2
import sys
import dotenv
dotenv.load_dotenv('.env')

def check_records():
    conn = psycopg2.connect(
        host=os.environ.get('DB_HOST'),
        port=os.environ.get('DB_PORT', 5432),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        dbname=os.environ.get('DB_NAME'),
        sslmode=os.environ.get('DB_SSL_MODE', 'require')
    )
    cursor = conn.cursor()
    
    # 1. Verification request ae93d187-8fba-49b3-9d7a-ffa219b92c6f
    try:
        cursor.execute("SELECT id, result, verified_at, sbom_root, vulnerability_db_root, policy_hash, proof_job_id FROM verification.verification_requests WHERE id = 'ae93d187-8fba-49b3-9d7a-ffa219b92c6f'")
        req = cursor.fetchone()
        print("=== Verification Request ===")
        if req:
            print(f"ID: {req[0]}")
            print(f"Result: {req[1]}")
            print(f"Verified At: {req[2]}")
            print(f"SBOM Root: {req[3]}")
            print(f"Vuln DB Root: {req[4]}")
            print(f"Policy Hash: {req[5]}")
            print(f"Proof Job ID: {req[6]}")
        else:
            print("NOT FOUND")
    except Exception as e:
        print("Error:", e)
        conn.rollback()

    # 2. Certificate
    try:
        cursor.execute("SELECT id, verification_request_id, sbom_root, vulnerability_db_root, policy_hash FROM verification.verification_certificates WHERE verification_request_id = 'ae93d187-8fba-49b3-9d7a-ffa219b92c6f'")
        cert = cursor.fetchone()
        print("\n=== Certificate ===")
        if cert:
            print(f"ID: {cert[0]}")
            print(f"Verification Request ID: {cert[1]}")
            print(f"SBOM Root: {cert[2]}")
            print(f"Vuln DB Root: {cert[3]}")
            print(f"Policy Hash: {cert[4]}")
        else:
            print("NOT FOUND")
    except Exception as e:
        print("Error:", e)
        conn.rollback()

    # 3. Snapshot
    try:
        if req:
            vuln_root = req[4]
            cursor.execute("SELECT id, authoritative_smt_root, provisional_smt_root, status FROM vulnerability.vulnerability_snapshots WHERE authoritative_smt_root = %s", (vuln_root,))
            snapshot = cursor.fetchone()
            print("\n=== Vulnerability Snapshot ===")
            if snapshot:
                print(f"ID: {snapshot[0]}")
                print(f"Authoritative SMT Root: {snapshot[1]}")
                print(f"Provisional SMT Root: {snapshot[2]}")
                print(f"Status: {snapshot[3]}")
            else:
                print(f"NOT FOUND for root {vuln_root}")
    except Exception as e:
        print("Error:", e)
        conn.rollback()

if __name__ == "__main__":
    check_records()
