import sys
sys.path.insert(0, '/app')
from shared.database import get_session
from sqlalchemy import text, inspect

engine = get_session().__next__().get_bind()
with engine.connect() as conn:
    result = conn.execute(text("SELECT version_num FROM alembic_version;"))
    version = result.fetchone()
    print("Alembic version in DB:", version[0] if version else "None")

columns = inspect(engine).get_columns('vulnerability_snapshots', schema='vulnerability')
print("Columns:", [c['name'] for c in columns])
