import secrets
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database import SessionLocal
import models

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

TOKEN_EXPIRE_MINUTES = 60
TOKEN_BYTE_LENGTH = 32  # 256-bit opaque token — stored & looked up in DB


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def generate_opaque_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTE_LENGTH)


def create_oauth_token(db: Session, student_id: int) -> models.OAuthToken:
    # Revoke any existing tokens for this student
    db.query(models.OAuthToken).filter(
        models.OAuthToken.student_id == student_id
    ).delete()

    raw_token = generate_opaque_token()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)

    db_token = models.OAuthToken(
        student_id=student_id,
        access_token=raw_token,
        expires_at=expires_at,
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
) -> models.Student:
    raw_token = credentials.credentials

    token_record = db.query(models.OAuthToken).filter(
        models.OAuthToken.access_token == raw_token
    ).first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiry
    now = datetime.now(timezone.utc)
    expires = token_record.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if now > expires:
        db.delete(token_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    student = db.query(models.Student).filter(
        models.Student.id == token_record.student_id
    ).first()

    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    return student
