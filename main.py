from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import sqlite3
import hashlib
import secrets
import hmac
import os
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing from .env")

app = FastAPI()

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        user_id = payload.get("sub")

        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

        return {
            "user_id": int(user_id),
            "username": payload.get("username")
        }

    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )

@app.get("/me")
def read_current_user(
    current_user: dict = Depends(get_current_user)
):
    return {
        "success": True,
        "user": current_user
    }

@app.on_event("startup")
def startup():
    create_tables()

DATABASE = "educational_platform.db"

def create_tables():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            display_name TEXT,
            bio TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS whatsapp_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            whatsapp_id TEXT UNIQUE NOT NULL,
            linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    connection.close()


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def username_exists(username):
    connection = get_db_connection()

    try:
        cursor = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        )
        return cursor.fetchone() is not None

    finally:
        connection.close()


def hash_password(password):
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return salt.hex() + ":" + password_hash.hex()


def verify_password(password, stored_hash):
    salt_hex, hash_hex = stored_hash.split(":")

    salt = bytes.fromhex(salt_hex)
    expected_hash = bytes.fromhex(hash_hex)

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return hmac.compare_digest(actual_hash, expected_hash)

@app.get("/")
def home():
    return {
        "message": "Educational Platform API is running"
    }


@app.get("/status")
def status():
    return {
        "status": "online",
        "project": "Educational Platform"
    }


@app.get("/database")
def database_status():
    connection = get_db_connection()
    connection.close()

    return {
        "database": "connected",
        "database_file": DATABASE
    }
@app.get("/users")
def list_users():
    connection = get_db_connection()

    cursor = connection.execute(
        "SELECT id, username, created_at FROM users"
    )

    users = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return {
        "count": len(users),
        "users": users
    }


from pydantic import BaseModel

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ProfileUpdateRequest(BaseModel):
    display_name: str
    bio: str = ""

@app.post("/register")
def register_user(user: RegisterRequest):
    username = user.username.strip()

    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters long"
        )

    if len(user.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )

    if username_exists(username):
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    password_hash = hash_password(user.password)

    connection = get_db_connection()

    try:
        cursor = connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

        user_id = cursor.lastrowid

        connection.execute(
            "INSERT INTO profiles (user_id, display_name) VALUES (?, ?)",
            (user_id, username)
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.rollback()
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    finally:
        connection.close()

    return {
        "success": True,
        "message": "Account created successfully",
        "username": username
    }


@app.post("/login")
def login_user(user: LoginRequest):
    username = user.username.strip()

    connection = get_db_connection()

    try:
        cursor = connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        )
        account = cursor.fetchone()
    finally:
        connection.close()

    if account is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not verify_password(user.password, account["password_hash"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(account["id"]),
        "username": account["username"],
        "iat": now,
        "exp": now + timedelta(minutes=30)
    }

    access_token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    return {
        "success": True,
        "message": "Login successful",
        "user_id": account["id"],
        "username": account["username"],
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/profile")
def get_profile(
    current_user: dict = Depends(get_current_user)
):
    connection = get_db_connection()

    try:
        cursor = connection.execute(
            """
            SELECT u.id, u.username, p.display_name, p.bio
            FROM users u
            LEFT JOIN profiles p ON p.user_id = u.id
            WHERE u.id = ?
            """,
            (current_user["user_id"],)
        )
        profile = cursor.fetchone()

    finally:
        connection.close()

    if profile is None:
        raise HTTPException(
            status_code=404,
            detail="User account not found"
        )

    if profile["display_name"] is None:
        raise HTTPException(
            status_code=404,
            detail="Student profile not found"
        )

    return {
        "success": True,
        "profile": {
            "user_id": profile["id"],
            "username": profile["username"],
            "display_name": profile["display_name"],
            "bio": profile["bio"]
        }
    }

@app.put("/profile")
def update_profile(
    profile_data: ProfileUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    display_name = profile_data.display_name.strip()

    if not display_name:
        raise HTTPException(
            status_code=400,
            detail="Display name cannot be empty"
        )

    connection = get_db_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE profiles
            SET display_name = ?,
                bio = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
            """,
            (
                display_name,
                profile_data.bio.strip(),
                current_user["user_id"]
            )
        )

        connection.commit()

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Student profile not found"
            )

    finally:
        connection.close()

    return {
        "success": True,
        "message": "Profile updated successfully",
        "display_name": display_name,
        "bio": profile_data.bio.strip()
    }
