import sys
sys.path.insert(0, '/app')
from shared.database import get_session
from sqlalchemy import text

engine = get_session().__next__().get_bind()
with engine.connect() as conn:
    print('--- PROOF JOBS ---')
    result = conn.execute(text("SELECT id, status, created_at FROM zkp.proof_jobs WHERE id='fcb8b532-a152-4aa0-977d-4a3e9d9b1a27'"))
    for row in result:
        print(row)
