from __future__ import annotations

from shared.logging import audit_log

from contextlib import contextmanager
from datetime import datetime
import logging
import threading
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.auth import require_roles
from shared.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/users", tags=["admin_users"])

PRIMARY_ROLES = ("vendor", "buyer", "admin")
LEGACY_ROLES = ("auditor", "trusted_importer")
ALLOWED_FILTER_ROLES = PRIMARY_ROLES + LEGACY_ROLES

# Deterministic 64-bit integer for admin lifecycle synchronization across PostgreSQL sessions
# Derived from ASCII 'ZKP_ADMI' -> 0x5A4B505F41444D49 -> 6506399120658742601
ADMIN_LIFECYCLE_LOCK_KEY = 6506399120658742601

_process_admin_mutex = threading.Lock()


@contextmanager
def admin_lifecycle_lock(db: Session):
    """
    Concurrency-safe context manager for administrative role/status mutations.
    In PostgreSQL:
      Acquires a transaction-scoped advisory lock via pg_advisory_xact_lock.
      This strictly serializes all admin lifecycle mutations across all database
      connections/workers. The lock is automatically released upon COMMIT or ROLLBACK.
    In SQLite (offline testing):
      Uses an in-process threading lock to serialize concurrent worker threads.
    """
    bind = db.get_bind()
    dialect_name = bind.dialect.name if bind else ""

    _process_admin_mutex.acquire()
    try:
        if dialect_name == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": ADMIN_LIFECYCLE_LOCK_KEY},
            )
        yield
    finally:
        _process_admin_mutex.release()


class AdminUserResponse(BaseModel):
    id: UUID
    username: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserRoleUpdateRequest(BaseModel):
    role: str = Field(..., description="Target role from the approved five-role model")


class UserStatusUpdateRequest(BaseModel):
    is_active: bool = Field(..., description="Target account activation status")


@router.get("", response_model=List[AdminUserResponse])
def list_users(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    role: Optional[str] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
    db: Session = Depends(get_session),
    current_admin: User = Depends(require_roles("admin")),
):
    """List registered users with pagination and optional filters. Restricted to admin."""
    query = db.query(User)

    if role is not None:
        normalized_role = role.strip().lower()
        if normalized_role not in ALLOWED_FILTER_ROLES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid role filter '{role}'. Must be one of: {', '.join(sorted(ALLOWED_FILTER_ROLES))}",
            )
        query = query.filter(User.role == normalized_role)

    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    users = (
        query.order_by(User.created_at.desc(), User.username.asc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return users


@router.get("/{user_id}", response_model=AdminUserResponse)
def get_user(
    user_id: UUID,
    db: Session = Depends(get_session),
    current_admin: User = Depends(require_roles("admin")),
):
    """Retrieve details for a specific user by UUID. Restricted to admin."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.patch("/{user_id}/role", response_model=AdminUserResponse)
def update_user_role(
    user_id: UUID,
    payload: UserRoleUpdateRequest,
    db: Session = Depends(get_session),
    current_admin: User = Depends(require_roles("admin")),
):
    """
    Update a user's role to one of the 3 supported primary roles (vendor, buyer, admin).
    Enforces concurrency-safe protection against losing the last active administrator.
    """
    normalized_role = payload.role.strip().lower()
    if normalized_role not in PRIMARY_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{payload.role}'. Supported primary roles are: {', '.join(sorted(PRIMARY_ROLES))}",
        )

    with admin_lifecycle_lock(db):
        target_user = db.query(User).filter(User.id == user_id).first()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Idempotent no-op
        if target_user.role == normalized_role:
            audit_log(
                "admin_service",
                "user_role_change",
                f"User {user_id} role unchanged ({normalized_role})",
                actor_id=str(current_admin.id),
                resource_type="user",
                resource_id=str(user_id),
                outcome="noop",
            )
            return target_user

        # Query and lock currently active administrators
        active_admins = (
            db.query(User)
            .filter(User.role == "admin", User.is_active == True)
            .with_for_update()
            .all()
        )

        # If zero active admins exist due to prior corrupted state:
        if len(active_admins) == 0:
            # Recovery path: allow promoting an active user to admin
            if normalized_role == "admin" and target_user.is_active:
                target_user.role = normalized_role
                target_user.updated_at = datetime.utcnow()
                db.commit()
                db.refresh(target_user)
                return target_user
            else:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="System integrity violation: no active administrators exist. Administrative recovery requires promoting an active user to admin.",
                )

        # Invariant check: if demoting an active admin to a non-admin role
        is_active_admin = (target_user.role == "admin" and target_user.is_active is True)
        if is_active_admin and normalized_role != "admin":
            remaining_active_admins = [u for u in active_admins if u.id != target_user.id]
            if len(remaining_active_admins) < 1:
                audit_log(
                    "admin_service",
                    "user_role_change",
                    f"Demotion of last active administrator rejected for user {user_id}",
                    actor_id=str(current_admin.id),
                    resource_type="user",
                    resource_id=str(user_id),
                    outcome="denied",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot demote the last active administrator",
                )

        # Apply update
        old_role = target_user.role
        target_user.role = normalized_role
        target_user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(target_user)

        audit_log(
            "admin_service",
            "user_role_change",
            f"User {user_id} role updated from {old_role} to {normalized_role} by admin {current_admin.id}",
            actor_id=str(current_admin.id),
            resource_type="user",
            resource_id=str(user_id),
            outcome="success",
        )
        return target_user


@router.patch("/{user_id}/status", response_model=AdminUserResponse)
def update_user_status(
    user_id: UUID,
    payload: UserStatusUpdateRequest,
    db: Session = Depends(get_session),
    current_admin: User = Depends(require_roles("admin")),
):
    """
    Update a user's account activation status.
    Enforces self-deactivation prevention and protection against losing the last active administrator.
    """
    with admin_lifecycle_lock(db):
        target_user = db.query(User).filter(User.id == user_id).first()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Self-deactivation guard: an admin cannot deactivate their own account
        if target_user.id == current_admin.id and payload.is_active is False:
            audit_log(
                "admin_service",
                "user_status_change",
                f"Self-deactivation rejected for administrator {user_id}",
                actor_id=str(current_admin.id),
                resource_type="user",
                resource_id=str(user_id),
                outcome="denied",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot deactivate their own account",
            )

        # Idempotent no-op
        if target_user.is_active == payload.is_active:
            audit_log(
                "admin_service",
                "user_status_change",
                f"User {user_id} status unchanged (is_active={payload.is_active})",
                actor_id=str(current_admin.id),
                resource_type="user",
                resource_id=str(user_id),
                outcome="noop",
            )
            return target_user

        # Query and lock currently active administrators
        active_admins = (
            db.query(User)
            .filter(User.role == "admin", User.is_active == True)
            .with_for_update()
            .all()
        )

        # If zero active admins exist:
        if len(active_admins) == 0:
            # Recovery path: allow activating a user who has role "admin"
            if payload.is_active is True and target_user.role == "admin":
                target_user.is_active = True
                target_user.updated_at = datetime.utcnow()
                db.commit()
                db.refresh(target_user)
                return target_user
            else:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="System integrity violation: no active administrators exist. Administrative recovery requires activating an admin account.",
                )

        # Invariant check: if deactivating an active admin
        is_active_admin = (target_user.role == "admin" and target_user.is_active is True)
        if is_active_admin and payload.is_active is False:
            remaining_active_admins = [u for u in active_admins if u.id != target_user.id]
            if len(remaining_active_admins) < 1:
                audit_log(
                    "admin_service",
                    "user_status_change",
                    f"Deactivation of last active administrator rejected for user {user_id}",
                    actor_id=str(current_admin.id),
                    resource_type="user",
                    resource_id=str(user_id),
                    outcome="denied",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate the last active administrator",
                )

        # Apply update
        target_user.is_active = payload.is_active
        target_user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(target_user)

        audit_log(
            "admin_service",
            "user_status_change",
            f"User {user_id} active status updated to {payload.is_active} by admin {current_admin.id}",
            actor_id=str(current_admin.id),
            resource_type="user",
            resource_id=str(user_id),
            outcome="success",
        )
        return target_user
