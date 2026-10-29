
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from database import engine

app = FastAPI(
    title="FryCount API",
    description="Milkfish Fry Counting and Density Estimation System",
    version="1.0.0",
)

password_hasher = PasswordHash.recommended()

# CORS configuration for local Flutter Web development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:51405",
        "http://127.0.0.1:51405",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# REQUEST MODELS
# =========================

class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    phone_number: str | None = Field(default=None, max_length=30)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


# =========================
# HOME
# =========================

@app.get("/")
def home():
    return {
        "message": "Welcome to FryCount API",
        "status": "running",
    }


# =========================
# HEALTH CHECK
# =========================

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "FryCount API",
    }


# =========================
# DATABASE CHECK
# =========================

@app.get("/api/db-check")
def database_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "status": "connected",
            "database": "frycount_db",
        }

    except SQLAlchemyError:
        raise HTTPException(
            status_code=503,
            detail="Database connection failed. Check backend configuration.",
        )


# =========================
# REGISTER USER
# =========================

@app.post(
    "/api/auth/register",
    status_code=status.HTTP_201_CREATED,
)
def register_user(data: RegisterRequest):
    full_name = data.full_name.strip()
    email = str(data.email).strip().lower()

    phone_number = (
        data.phone_number.strip()
        if data.phone_number and data.phone_number.strip()
        else None
    )

    if len(full_name) < 2:
        raise HTTPException(
            status_code=422,
            detail="Full name must contain at least 2 characters.",
        )

    password_hash = password_hasher.hash(data.password)

    try:
        with engine.begin() as connection:
            result = connection.execute(
                text("""
                    INSERT INTO users (
                        full_name,
                        email,
                        phone_number,
                        password_hash,
                        role
                    )
                    VALUES (
                        :full_name,
                        :email,
                        :phone_number,
                        :password_hash,
                        'farmer'
                    )
                    RETURNING
                        id,
                        full_name,
                        email,
                        phone_number,
                        role,
                        created_at
                """),
                {
                    "full_name": full_name,
                    "email": email,
                    "phone_number": phone_number,
                    "password_hash": password_hash,
                },
            )

            user = result.mappings().one()

        return {
            "message": "Registration successful.",
            "user": dict(user),
        }

    except IntegrityError as exc:
        error_text = str(exc.orig).lower()

        if "email" in error_text or "unique" in error_text:
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists.",
            ) from exc

        raise HTTPException(
            status_code=500,
            detail="Could not create the account. Check the users table schema.",
        ) from exc

    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not save the account. Check the database configuration.",
        ) from exc


# =========================
# LOGIN USER
# =========================

@app.post("/api/auth/login")
def login_user(data: LoginRequest):
    email = str(data.email).strip().lower()

    try:
        with engine.connect() as connection:
            user = connection.execute(
                text("""
                    SELECT
                        id,
                        full_name,
                        email,
                        phone_number,
                        password_hash,
                        role,
                        is_active
                    FROM users
                    WHERE email = :email
                """),
                {"email": email},
            ).mappings().first()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        if not user["is_active"]:
            raise HTTPException(
                status_code=403,
                detail="This account is inactive. Contact the administrator.",
            )

        if not password_hasher.verify(
            data.password,
            user["password_hash"],
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        return {
            "message": "Login successful.",
            "user": {
                "id": user["id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "phone_number": user["phone_number"],
                "role": user["role"],
            },
        }

    except HTTPException:
        raise

    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="Login failed because of a database error.",
        ) from exc
