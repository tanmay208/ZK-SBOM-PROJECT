import os
import psycopg2
from psycopg2.extras import RealDictCursor
import sys

# Load env manually to not depend on app config
import dotenv
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

def inspect_db():
    conn = psycopg2.connect(
        host=os.environ.get('DB_HOST'),
        port=os.environ.get('DB_PORT', 5432),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        dbname=os.environ.get('DB_NAME'),
        sslmode=os.environ.get('DB_SSL_MODE', 'require')
    )
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT query, calls, total_exec_time, rows 
            FROM pg_stat_statements 
            WHERE query ILIKE '%vulnerability_snapshots%'
            ORDER BY calls DESC;
        """)
        print("Queries mentioning vulnerability_snapshots:")
        for row in cursor.fetchall():
            print(f"- {row['calls']} calls | {row['query'][:150]}")
    except Exception as e:
        print("error:", e)

if __name__ == "__main__":
    inspect_db()
