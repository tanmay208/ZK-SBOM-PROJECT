import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Uuid

from shared.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="auditor")  # e.g., admin, auditor, vendor
    created_at = Column(DateTime, default=datetime.utcnow)
