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
    cur.execute("UPDATE zkp.proof_jobs SET status='failed' WHERE status IN ('pending', 'assembling_witness', 'running')")
    conn.commit()
    cur.close()
    conn.close()
    print("Marked jobs as failed.")
except Exception as e:
    print(f"Error: {e}")
