import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, String, Uuid, text, true

from shared.database import Base


PRIMARY_ROLES = ("vendor", "buyer", "admin")
LEGACY_ROLES = ("auditor", "trusted_importer")
ALL_SUPPORTED_ROLES = PRIMARY_ROLES


class User(Base):
    __tablename__ = "users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="buyer")  # primary roles: vendor, buyer, admin
    is_active = Column(Boolean, nullable=False, default=True, server_default=true())
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=text("CURRENT_TIMESTAMP"),
    )
