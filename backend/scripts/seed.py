import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.orm import sessionmaker
from shared.database import init_engine
from shared.models.user import User
from shared.auth import get_password_hash
from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.services.policy_service import create_policy

def seed():
    engine = init_engine()
    SessionLocal = sessionmaker(bind=engine)
    
    users_to_seed = [
        {"username": "admin", "role": "admin"},
        {"username": "vendor", "role": "vendor"},
        {"username": "trusted_importer", "role": "trusted_importer"},
    ]
    
    with SessionLocal() as db:
        for u in users_to_seed:
            existing = db.query(User).filter(User.username == u["username"]).first()
            if not existing:
                print(f"Creating user: {u['username']} ({u['role']})")
                new_user = User(
                    username=u["username"],
                    hashed_password=get_password_hash("password123"),
                    role=u["role"]
                )
                db.add(new_user)
            else:
                print(f"User {u['username']} already exists.")
                
        # Check policy
        active_policy = db.query(SecurityPolicy).filter(SecurityPolicy.is_active == 1).first()
        if not active_policy:
            print("Creating default SecurityPolicy...")
            create_policy(db, max_cvss_score=7.0, name="Default ZKP Policy")
        else:
            print(f"Active policy already exists: {active_policy.name} (Max CVSS: {active_policy.max_allowed_cvss})")
            
        db.commit()
        print("Seeding complete.")

if __name__ == "__main__":
    seed()
