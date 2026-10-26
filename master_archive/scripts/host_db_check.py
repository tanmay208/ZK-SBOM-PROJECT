import os
import psycopg2
from psycopg2.extras import DictCursor

def check_db():
    try:
        conn = psycopg2.connect(
            host="aws-0-ap-southeast-2.pooler.supabase.com",
            port=5432,
            user="postgres.gwbbvucrzltxsvavhgpd",
            password="***REMOVED***",
            dbname="postgres",
            sslmode="require"
        )
        cur = conn.cursor(cursor_factory=DictCursor)
        print("--- JOB STATUS ---")
        cur.execute("SELECT id, status, created_at, error_message FROM zkp.proof_jobs WHERE id='fcb8b532-a152-4aa0-977d-4a3e9d9b1a27'")
        row = cur.fetchone()
        if row:
            print(dict(row))
        else:
            print("Job not found")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_db()
