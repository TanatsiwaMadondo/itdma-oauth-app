from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional


class StudentCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str


class StudentOut(BaseModel):
    id: int
    full_name: str
    email: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    scope: str
    expires_in: int
