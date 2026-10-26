import os
import psycopg2

def normalize_hashes():
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')

    print("Connecting to database...")
    conn = psycopg2.connect(
        dbname=db_name,
        user=db_user,
        password=db_password,
        host=db_host,
        port=db_port
    )
    cur = conn.cursor()

    cur.execute("SELECT id, policy_hash, max_allowed_cvss_int FROM policy.security_policies")
    rows = cur.fetchall()

    updates = []
    print(f"Found {len(rows)} policies.")

    for policy_id, policy_hash, cvss_int in rows:
        if not policy_hash or not policy_hash.startswith("0x"):
            print(f"Skipping {policy_id}: hash is not 0x-prefixed")
            continue
            
        if len(policy_hash) == 66:
            print(f"Skipping {policy_id}: hash is already canonical length (66)")
            continue

        if len(policy_hash) < 66:
            stripped = policy_hash[2:]
            padded = f"0x{stripped:0>64}"
            
            # Verify the integer value remains identical
            if int(policy_hash, 16) != int(padded, 16):
                print(f"ERROR: Collision or value mismatch for {policy_id}! Aborting.")
                return

            print(f"Prepared update for {policy_id}:")
            print(f"  Old: {policy_hash} (len {len(policy_hash)})")
            print(f"  New: {padded} (len {len(padded)})")
            updates.append((padded, policy_id))
            
    if not updates:
        print("No records require normalization.")
        return

    # Wait for explicit execution
    print(f"\nReady to apply {len(updates)} updates.")
    apply = os.getenv("APPLY_NORMALIZATION")
    if apply == "1":
        for new_hash, pid in updates:
            cur.execute("UPDATE policy.security_policies SET policy_hash = %s WHERE id = %s", (new_hash, pid))
        conn.commit()
        print("Updates committed successfully.")
    else:
        print("DRY RUN completed. Set APPLY_NORMALIZATION=1 to commit.")
        
    cur.close()
    conn.close()

if __name__ == "__main__":
    normalize_hashes()
