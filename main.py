from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import create_database, get_connection
from schemas import (
    UserRegister,
    UserLogin,
    UserResponse,
    UserUpdate,
    Token
)
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)


# =========================
# CREATE FASTAPI APP
# =========================

app = FastAPI(
    title="RabTech Task 05 - JWT Authentication API",
    description="FastAPI microservice with JWT authentication and secure CRUD operations",
    version="1.0.0"
)


# =========================
# JWT SECURITY
# =========================

security = HTTPBearer()


# =========================
# DATABASE INITIALIZATION
# =========================

create_database()


# =========================
# GET CURRENT USER
# =========================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    connection = get_connection()

    user = connection.execute(
        """
        SELECT id, username, email, password
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user


# =========================
# HOME ROUTE
# =========================

@app.get("/")
def home():
    return {
        "message": "RabTech Task 05 FastAPI JWT Microservice is running"
    }


# =========================
# REGISTER
# =========================

@app.post(
    "/register",
    response_model=UserResponse,
    status_code=201
)
def register(user: UserRegister):

    connection = get_connection()

    existing_user = connection.execute(
        """
        SELECT id
        FROM users
        WHERE username = ? OR email = ?
        """,
        (user.username, user.email)
    ).fetchone()

    if existing_user:
        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Username or email already registered"
        )

    hashed_password = hash_password(user.password)

    cursor = connection.execute(
        """
        INSERT INTO users (username, email, password)
        VALUES (?, ?, ?)
        """,
        (
            user.username,
            user.email,
            hashed_password
        )
    )

    connection.commit()

    user_id = cursor.lastrowid

    connection.close()

    return {
        "id": user_id,
        "username": user.username,
        "email": user.email
    }


# =========================
# LOGIN
# =========================

@app.post(
    "/login",
    response_model=Token
)
def login(user: UserLogin):

    connection = get_connection()

    existing_user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (user.username,)
    ).fetchone()

    connection.close()

    if existing_user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not verify_password(
        user.password,
        existing_user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Create JWT using user ID
    access_token = create_access_token(
        str(existing_user["id"])
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# =========================
# GET CURRENT USER
# =========================

@app.get(
    "/users/me",
    response_model=UserResponse
)
def get_my_profile(
    current_user=Depends(get_current_user)
):

    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"]
    }


# =========================
# UPDATE CURRENT USER
# =========================

@app.put(
    "/users/me",
    response_model=UserResponse
)
def update_my_profile(
    user: UserUpdate,
    current_user=Depends(get_current_user)
):

    connection = get_connection()

    new_username = (
        user.username
        if user.username is not None
        else current_user["username"]
    )

    new_email = (
        user.email
        if user.email is not None
        else current_user["email"]
    )

    # Check whether another user already has
    # the requested username or email
    existing_user = connection.execute(
        """
        SELECT id
        FROM users
        WHERE (username = ? OR email = ?)
        AND id != ?
        """,
        (
            new_username,
            new_email,
            current_user["id"]
        )
    ).fetchone()

    if existing_user:
        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Username or email already in use"
        )

    # Update user
    connection.execute(
        """
        UPDATE users
        SET username = ?, email = ?
        WHERE id = ?
        """,
        (
            new_username,
            new_email,
            current_user["id"]
        )
    )

    connection.commit()

    # Fetch updated user
    updated_user = connection.execute(
        """
        SELECT id, username, email
        FROM users
        WHERE id = ?
        """,
        (current_user["id"],)
    ).fetchone()

    connection.close()

    if updated_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Convert sqlite3.Row to dictionary
    return {
        "id": updated_user["id"],
        "username": updated_user["username"],
        "email": updated_user["email"]
    }


# =========================
# DELETE CURRENT USER
# =========================

@app.delete("/users/me")
def delete_my_account(
    current_user=Depends(get_current_user)
):

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (current_user["id"],)
    )

    connection.commit()
    connection.close()

    return {
        "message": "User account deleted successfully"
    }