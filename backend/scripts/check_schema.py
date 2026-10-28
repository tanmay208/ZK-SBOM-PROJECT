import os
import psycopg2
import sys
import dotenv
dotenv.load_dotenv('.env')

def check_schema():
    conn = psycopg2.connect(
        host=os.environ.get('DB_HOST'),
        port=os.environ.get('DB_PORT', 5432),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        dbname=os.environ.get('DB_NAME'),
        sslmode=os.environ.get('DB_SSL_MODE', 'require')
    )
    cursor = conn.cursor()
    
    # Check if authoritative_smt_root exists
    try:
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_schema = 'vulnerability' AND table_name = 'vulnerability_snapshots';
        """)
        columns = [row[0] for row in cursor.fetchall()]
        print("Columns in vulnerability_snapshots:")
        print(", ".join(columns))
        print("Has authoritative_smt_root:", "authoritative_smt_root" in columns)
        print("Has provisional_smt_root:", "provisional_smt_root" in columns)
    except Exception as e:
        print("Error checking columns:", e)
        conn.rollback()

    # Check migration version
    try:
        cursor.execute("SELECT version_num FROM alembic_version")
        print("\nAlembic version:", cursor.fetchone()[0])
    except Exception as e:
        print("Error checking alembic_version:", e)

    # Check the specific records mentioned
    try:
        cursor.execute("SELECT id, result, verified_at, sbom_root, vulnerability_db_root, policy_hash, proof_job_id FROM verification.verification_requests WHERE id = 'ae93d187-8fba-49b3-9d7a-ffa219b92c6f'")
        req = cursor.fetchone()
        print("\nVerification Request ae93d187-8fba-49b3-9d7a-ffa219b92c6f:")
        print(req)
        
        cursor.execute("SELECT id, verification_request_id, sbom_root, vulnerability_db_root, policy_hash FROM verification.verification_certificates WHERE id = '444d6620-8e13-4511-8b11-ff78c6294cf0'")
        cert = cursor.fetchone()
        print("\nCertificate 444d6620-8e13-4511-8b11-ff78c6294cf0:")
        print(cert)
        
    except Exception as e:
        print("Error querying specific records:", e)


if __name__ == "__main__":
    check_schema()
