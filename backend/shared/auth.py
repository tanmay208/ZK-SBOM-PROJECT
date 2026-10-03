import os
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.config import ConfigurationError
from shared.models.user import User

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# Precomputed dummy hash for constant-time comparison when a user does not exist
DUMMY_PASSWORD_HASH = "$2b$12$/9NZ3/0UUvl/Q2HI5pMq1.13pOxkyJ4zVnrkkkrypcyqIYIeg3j7G"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_jwt_secret() -> str:
    """Retrieve the JWT secret from environment configuration.

    Production services must fail closed when the signing secret is absent.
    """
    secret = os.environ.get("JWT_SECRET_KEY")
    if not secret:
        raise ConfigurationError("JWT_SECRET_KEY is not set")
    return secret


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pw_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pw_bytes, hash_bytes)
    except Exception:
        return False


def verify_dummy_password(plain_password: str) -> None:
    """Mitigate username enumeration timing attacks by running bcrypt on non-existent users."""
    try:
        pw_bytes = plain_password.encode("utf-8")[:72]
        bcrypt.checkpw(pw_bytes, DUMMY_PASSWORD_HASH.encode("utf-8"))
    except Exception:
        pass


def get_password_hash(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pw_bytes, salt).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, get_jwt_secret(), algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_session)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def require_roles(*allowed_roles: str) -> Callable:
    """Build a dependency that enforces server-side role authorization."""
    if not allowed_roles:
        raise ValueError("At least one role is required")

    def role_dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_dependency
