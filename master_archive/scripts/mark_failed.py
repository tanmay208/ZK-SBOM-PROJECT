import os
import psycopg2

def mark_failed():
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
        cur.execute("UPDATE zkp.proof_jobs SET status = 'failed', error_message = 'Orphaned by server restart' WHERE id = 'fcb8b532-a152-4aa0-977d-4a3e9d9b1a27'")
        conn.commit()
        print(f"Rows updated: {cur.rowcount}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    mark_failed()
