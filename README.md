# Auth Service Demo

Микросервис аутентификации на **FastAPI + PostgreSQL + Redis + JWT**.

Сгенерирован AI-пайплайном: CrewAI (DeepSeek V4 Pro, GLM 5.2, Nemotron 3 Ultra, Qwen 3.5, Mistral Large 3, Nemotron 3 Super) + Gemini 3.1 Pro.

## Эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/v1/register` | Регистрация (email + password) |
| POST | `/api/v1/login` | Вход, выдача JWT access + refresh |
| POST | `/api/v1/refresh` | Обновление токенов (с ротацией) |
| GET | `/api/v1/users/me` | Профиль (требует Bearer token) |
| GET | `/health` | Healthcheck |

## Быстрый старт

```bash
# Зависимости
pip install -r requirements.txt

# Запуск (нужны PostgreSQL и Redis)
uvicorn app.main:app --reload
```

## Стек

- **Python 3.12** + **FastAPI**
- **PostgreSQL** (SQLAlchemy async)
- **Redis** (rate limiting, token store)
- **JWT** (HS256 access + refresh с ротацией)
- **bcrypt** (хеширование паролей)
- **Docker** (см. docker-compose.yml)

## Лицензия

MIT
