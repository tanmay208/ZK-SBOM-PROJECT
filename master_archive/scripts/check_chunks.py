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
    cur.execute("SELECT prover_str FROM zkp.segment_proofs WHERE segment_index=0 ORDER BY created_at DESC LIMIT 1")
    row = cur.fetchone()
    if row:
        with open("Prover.toml", "w") as f:
            f.write(row[0])
        print("Wrote Prover.toml")
    cur.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
