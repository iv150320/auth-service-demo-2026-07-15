import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from redis.asyncio import Redis

from app.config import settings
from app.models import Base
from app.api import router

engine = create_async_engine(settings.DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

redis_client: Redis = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    yield
    await redis_client.close()
    await engine.dispose()


app = FastAPI(title="Auth Service", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/api/v1/login" and request.method == "POST":
        if redis_client:
            client_ip = request.client.host if request.client else "unknown"
            ip_key = f"ratelimit:login:ip:{client_ip}"
            current = await redis_client.get(ip_key)
            current = int(current) if current else settings.RATE_LIMIT_LOGIN_IP_CAPACITY
            if current <= 0:
                raise HTTPException(status_code=429, detail="Too Many Requests", headers={"Retry-After": str(settings.RATE_LIMIT_LOGIN_IP_REFILL_SECONDS)})
            await redis_client.decr(ip_key)
            if current == settings.RATE_LIMIT_LOGIN_IP_CAPACITY:
                await redis_client.expire(ip_key, settings.RATE_LIMIT_LOGIN_IP_REFILL_SECONDS)

            try:
                body = await request.json()
                email = body.get("email")
                if email:
                    user_key = f"ratelimit:login:user:{email}"
                    user_current = await redis_client.get(user_key)
                    user_current = int(user_current) if user_current else settings.RATE_LIMIT_LOGIN_USER_CAPACITY
                    if user_current <= 0:
                        raise HTTPException(status_code=429, detail="Too Many Requests", headers={"Retry-After": str(settings.RATE_LIMIT_LOGIN_USER_REFILL_SECONDS)})
                    await redis_client.decr(user_key)
                    if user_current == settings.RATE_LIMIT_LOGIN_USER_CAPACITY:
                        await redis_client.expire(user_key, settings.RATE_LIMIT_LOGIN_USER_REFILL_SECONDS)
            except Exception:
                pass

    response = await call_next(request)
    return response


@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    async with async_session() as session:
        request.state.db = session
        request.state.redis = redis_client
        response = await call_next(request)
    return response


app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok"}
