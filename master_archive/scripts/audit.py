import psycopg2

try:
    conn = psycopg2.connect(
        host="aws-0-ap-southeast-2.pooler.supabase.com",
        port=5432,
        user="postgres.gwbbvucrzltxsvavhgpd",
        password="***REMOVED***",
        dbname="postgres",
        sslmode="require"
    )
    cur = conn.cursor()

    print("=== PROOF JOBS ===")
    cur.execute("""
        SELECT id, status, created_at, completed_at, error_message, policy_id
        FROM zkp.proof_jobs
        ORDER BY created_at DESC
        LIMIT 5
    """)
    jobs = cur.fetchall()
    for row in jobs:
        print(row)

    print("\n=== LATEST JOB CHUNKS & SEGMENTS ===")
    if jobs:
        latest_job_id = jobs[0][0]
        cur.execute("SELECT status, count(*) FROM zkp.chunk_proof_sets WHERE proof_job_id=%s GROUP BY status", (latest_job_id,))
        print("Chunks:", cur.fetchall())

        cur.execute("SELECT count(*) FROM zkp.segment_proofs sp JOIN zkp.chunk_proof_sets cps ON sp.chunk_id = cps.id WHERE cps.proof_job_id=%s", (latest_job_id,))
        print("Segments:", cur.fetchone())
        
        cur.execute("SELECT error_message FROM zkp.proof_jobs WHERE id=%s", (latest_job_id,))
        print("Latest job error:", cur.fetchone()[0])
        
    print("\n=== ACTIVE POLICIES ===")
    cur.execute("SELECT id, name, max_allowed_cvss, policy_hash, is_active FROM policy.security_policies WHERE is_active=1")
    for row in cur.fetchall():
        print(row)

    cur.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
