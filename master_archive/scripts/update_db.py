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
    cur.execute("UPDATE policy.security_policies SET is_active=0 WHERE name='test_policy'")
    conn.commit()
    cur.close()
    conn.close()
    print("Deactivated test_policy")
except Exception as e:
    print(f"Error: {e}")
