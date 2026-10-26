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

    job_id = '0859e5a5-b449-4ac9-93ad-1f0bb66ed882'
    cur.execute("SELECT status, completed_at, error_message FROM zkp.proof_jobs WHERE id=%s", (job_id,))
    print("Job Info:", cur.fetchone())

    cur.execute("SELECT status, count(*) FROM zkp.chunk_proof_sets WHERE proof_job_id=%s GROUP BY status", (job_id,))
    print("Chunks by Status:", cur.fetchall())

    cur.execute("SELECT count(*) FROM zkp.segment_proofs sp JOIN zkp.chunk_proof_sets cps ON sp.chunk_id = cps.id WHERE cps.proof_job_id=%s AND proof_artifact IS NOT NULL", (job_id,))
    print("Segments Proved:", cur.fetchone()[0])
    
    cur.execute("SELECT count(*) FROM zkp.segment_proofs sp JOIN zkp.chunk_proof_sets cps ON sp.chunk_id = cps.id WHERE cps.proof_job_id=%s", (job_id,))
    print("Total Segments Assembled:", cur.fetchone()[0])

    cur.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
