from datetime import timedelta
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.models.user import User
from shared.auth import (
    verify_password,
    verify_dummy_password,
    get_password_hash,
    create_access_token,
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_session)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        # Constant-time dummy verification to protect against account enumeration
        verify_dummy_password(form_data.password)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_session)):
    if not form_data.username or not form_data.username.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username cannot be empty",
        )
    if not form_data.password or not form_data.password.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password cannot be empty",
        )

    user = db.query(User).filter(User.username == form_data.username).first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    
    # Roles cannot be chosen or escalated through request payloads — all new users receive base role 'auditor'
    hashed_password = get_password_hash(form_data.password)
    new_user = User(
        username=form_data.username.strip(),
        hashed_password=hashed_password,
        role="auditor",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Password hash is NEVER returned in response
    return {
        "message": "User registered successfully",
        "username": new_user.username,
        "role": new_user.role,
    }


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    """Return verified caller identity. Password hashes are never disclosed."""
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "role": current_user.role,
    }
