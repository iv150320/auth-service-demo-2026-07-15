import hashlib
import secrets
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt
from fastapi import APIRouter, Request, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import settings
from app.models import User, RefreshToken


router = APIRouter()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(user_id: str, role: str = "user") -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": user_id, "role": role, "exp": expire, "type": "access"}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token() -> str:
    return secrets.token_urlsafe(64)


async def get_current_user(request: Request, db: AsyncSession = Depends(lambda: None)) -> User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid token")
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request: Request, db: AsyncSession = Depends(lambda: None)):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Email and password required")
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Password too short")

    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(email=email, password_hash=password_hash)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"id": str(user.id), "email": user.email, "role": user.role, "is_verified": user.is_verified}


@router.post("/login")
async def login(request: Request, db: AsyncSession = Depends(lambda: None)):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Email and password required")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(str(user.id), user.role)
    refresh_token_raw = create_refresh_token()
    refresh_token_hash = hash_token(refresh_token_raw)
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    refresh_token_record = RefreshToken(
        user_id=user.id,
        token_hash=refresh_token_hash,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=expires_at,
    )
    db.add(refresh_token_record)
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_raw,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "token_type": "Bearer",
    }


@router.post("/refresh")
async def refresh(request: Request, db: AsyncSession = Depends(lambda: None)):
    body = await request.json()
    refresh_token_raw = body.get("refresh_token")
    if not refresh_token_raw:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Refresh token required")

    token_hash = hash_token(refresh_token_raw)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if token_record.revoked_at is not None:
        if token_record.replaced_by_token_id is not None:
            all_active = (await db.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == token_record.user_id,
                    RefreshToken.revoked_at.is_(None),
                )
            )).scalars().all()
            for t in all_active:
                t.revoked_at = datetime.utcnow()
            await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token reuse detected, all sessions revoked")

    if token_record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    result = await db.execute(select(User).where(User.id == token_record.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_record.revoked_at = datetime.utcnow()

    new_refresh_raw = create_refresh_token()
    new_refresh_hash = hash_token(new_refresh_raw)
    new_expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    new_token_record = RefreshToken(
        user_id=user.id,
        token_hash=new_refresh_hash,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=new_expires_at,
    )
    db.add(new_token_record)
    await db.flush()

    token_record.replaced_by_token_id = new_token_record.id
    await db.commit()

    access_token = create_access_token(str(user.id), user.role)
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_raw,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "token_type": "Bearer",
    }


@router.get("/users/me")
async def get_me(request: Request, db: AsyncSession = Depends(lambda: None)):
    user = await get_current_user(request, db)
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "is_verified": user.is_verified,
    }
