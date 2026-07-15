from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/auth_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    RATE_LIMIT_LOGIN_IP_CAPACITY: int = 10
    RATE_LIMIT_LOGIN_IP_REFILL_SECONDS: int = 60
    RATE_LIMIT_LOGIN_USER_CAPACITY: int = 5
    RATE_LIMIT_LOGIN_USER_REFILL_SECONDS: int = 300


settings = Settings()
