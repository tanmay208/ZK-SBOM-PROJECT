import os
import psycopg2


def get_db_connection():
    """Connect to PostgreSQL using environment-based configuration.

    Fails safely if required connection parameters are missing.
    Does not use hardcoded credentials or fallback to production endpoints.
    """
    db_url = os.environ.get("DATABASE_URL")
    if db_url and db_url.strip():
        return psycopg2.connect(db_url.strip())

    host = os.environ.get("DB_HOST")
    port = os.environ.get("DB_PORT", "5432")
    user = os.environ.get("DB_USER")
    password = os.environ.get("DB_PASSWORD")
    dbname = os.environ.get("DB_NAME")
    sslmode = os.environ.get("DB_SSL_MODE", "prefer")

    missing = []
    if not host or not host.strip():
        missing.append("DB_HOST")
    if not user or not user.strip():
        missing.append("DB_USER")
    if not password or not password.strip():
        missing.append("DB_PASSWORD")
    if not dbname or not dbname.strip():
        missing.append("DB_NAME")

    if missing:
        raise ValueError(
            f"Missing required database environment variable(s): {', '.join(missing)}. "
            "Please configure DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME (or DATABASE_URL)."
        )

    try:
        port_int = int(port.strip())
    except ValueError:
        raise ValueError(f"Invalid DB_PORT: must be an integer, got '{port}'.")

    connect_kwargs = {
        "host": host.strip(),
        "port": port_int,
        "user": user.strip(),
        "password": password.strip(),
        "dbname": dbname.strip(),
    }
    if sslmode and sslmode.strip():
        connect_kwargs["sslmode"] = sslmode.strip()

    return psycopg2.connect(**connect_kwargs)


def main():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE policy.security_policies SET is_active=0 WHERE name='test_policy'")
        conn.commit()
        cur.close()
        conn.close()
        print("Deactivated test_policy")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
