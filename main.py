from __future__ import annotations

import re
import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from itsdangerous import BadSignature, Signer
from pydantic import BaseModel, ConfigDict, EmailStr, PositiveInt

app = FastAPI(title="KR2 FastAPI Tasks")

SECRET_KEY = "super-secret-key-for-kr2"
signer = Signer(SECRET_KEY)
SESSION_COOKIE_NAME = "session_token"
SESSION_MAX_AGE_SECONDS = 300
SESSION_REFRESH_THRESHOLD_SECONDS = 180


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: PositiveInt | None = None
    is_subscribed: bool | None = None


class CommonHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    user_agent: str
    accept_language: str


def _is_valid_accept_language(value: str) -> bool:
    pattern = r"^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})?(?:\s*,\s*[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})?(?:;q=(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?))?)*$"
    return bool(re.match(pattern, value))


def get_common_headers(request: Request) -> CommonHeaders:
    user_agent = request.headers.get("User-Agent")
    accept_language = request.headers.get("Accept-Language")

    if not user_agent or not accept_language:
        raise HTTPException(status_code=400, detail="Required headers are missing")

    if not _is_valid_accept_language(accept_language):
        raise HTTPException(status_code=400, detail="Invalid Accept-Language format")

    return CommonHeaders(user_agent=user_agent, accept_language=accept_language)


def _make_signed_session_token(user_id: str, ts: int) -> str:
    payload = f"{user_id}.{ts}"
    return signer.sign(payload.encode("utf-8")).decode("utf-8")


def _make_signed_user_token(user_id: str) -> str:
    return signer.sign(user_id.encode("utf-8")).decode("utf-8")


def _parse_and_verify_user_token(token: str) -> str:
    try:
        user_id = signer.unsign(token.encode("utf-8")).decode("utf-8")
    except BadSignature as exc:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"}) from exc

    try:
        uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"}) from exc

    return user_id


def _parse_and_verify_session_token(token: str) -> tuple[str, int]:
    try:
        raw = signer.unsign(token.encode("utf-8")).decode("utf-8")
    except BadSignature as exc:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"}) from exc

    parts = raw.split(".")
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"})

    user_id, ts_str = parts

    try:
        uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"}) from exc

    try:
        ts = int(ts_str)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"}) from exc

    return user_id, ts


async def _extract_credentials(request: Request) -> tuple[str, str]:
    content_type = (request.headers.get("content-type") or "").lower()

    if "application/json" in content_type:
        payload = await request.json()
        username = payload.get("username") if isinstance(payload, dict) else None
        password = payload.get("password") if isinstance(payload, dict) else None
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
    else:
        try:
            payload = await request.json()
            username = payload.get("username") if isinstance(payload, dict) else None
            password = payload.get("password") if isinstance(payload, dict) else None
        except Exception:
            username = None
            password = None

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    return str(username), str(password)


# --- Задание 3.1 ---
@app.post("/create_user")
async def create_user(user: UserCreate) -> UserCreate:
    return user


# --- Задание 3.2 ---
sample_product_1 = {
    "product_id": 123,
    "name": "Smartphone",
    "category": "Electronics",
    "price": 599.99,
}
sample_product_2 = {
    "product_id": 456,
    "name": "Phone Case",
    "category": "Accessories",
    "price": 19.99,
}
sample_product_3 = {
    "product_id": 789,
    "name": "Iphone",
    "category": "Electronics",
    "price": 1299.99,
}
sample_product_4 = {
    "product_id": 101,
    "name": "Headphones",
    "category": "Accessories",
    "price": 99.99,
}
sample_product_5 = {
    "product_id": 202,
    "name": "Smartwatch",
    "category": "Electronics",
    "price": 299.99,
}

sample_products = [
    sample_product_1,
    sample_product_2,
    sample_product_3,
    sample_product_4,
    sample_product_5,
]


@app.get("/products/search")
async def search_products(keyword: str, category: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit must be positive")

    keyword_normalized = keyword.strip().lower()
    if not keyword_normalized:
        raise HTTPException(status_code=400, detail="keyword is required")

    filtered = [
        product
        for product in sample_products
        if keyword_normalized in product["name"].lower()
        and (category is None or product["category"].lower() == category.lower())
    ]
    return filtered[:limit]


@app.get("/product/{product_id}")
async def get_product(product_id: int) -> dict[str, Any]:
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")


# --- Задание 5.1 + 5.3 (login + user/profile) ---
@app.post("/login")
async def login(request: Request, response: Response) -> dict[str, str]:
    username, password = await _extract_credentials(request)

    if not (username == "user123" and password == "password123"):
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"})

    user_id = str(uuid.uuid4())
    now_ts = int(time.time())
    token = _make_signed_session_token(user_id, now_ts)

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    return {"message": "Login successful"}


@app.get("/user")
async def get_user_profile(
    response: Response, session_token: str | None = Cookie(default=None)
) -> dict[str, Any]:
    if not session_token:
        response.status_code = 401
        return {"message": "Unauthorized"}

    try:
        user_id, _ = _parse_and_verify_session_token(session_token)
    except HTTPException:
        response.status_code = 401
        return {"message": "Unauthorized"}

    return {
        "user_id": user_id,
        "username": "user123",
        "email": "user123@example.com",
        "is_active": True,
    }


# --- Задание 5.2 (строгий формат <user_id>.<signature>) ---
@app.post("/login_v52")
async def login_v52(request: Request, response: Response) -> dict[str, str]:
    username, password = await _extract_credentials(request)

    if not (username == "user123" and password == "password123"):
        response.status_code = 401
        return {"message": "Unauthorized"}

    user_id = str(uuid.uuid4())
    token = _make_signed_user_token(user_id)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    return {"message": "Login successful (v5.2)"}


@app.get("/profile_v52")
async def profile_v52(response: Response, session_token: str | None = Cookie(default=None)) -> dict[str, Any]:
    if not session_token:
        response.status_code = 401
        return {"message": "Unauthorized"}

    try:
        user_id = _parse_and_verify_user_token(session_token)
    except HTTPException:
        response.status_code = 401
        return {"message": "Unauthorized"}

    return {
        "user_id": user_id,
        "username": "user123",
        "email": "user123@example.com",
    }


# --- Задание 5.3 (динамическая сессия 3/5 минут) ---
@app.get("/profile")
async def get_profile(
    response: Response, session_token: str | None = Cookie(default=None)
) -> dict[str, Any]:
    if not session_token:
        response.status_code = 401
        return {"message": "Invalid session"}

    try:
        user_id, last_activity_ts = _parse_and_verify_session_token(session_token)
    except HTTPException:
        response.status_code = 401
        return {"message": "Invalid session"}

    now_ts = int(time.time())
    elapsed = now_ts - last_activity_ts

    if elapsed < 0:
        response.status_code = 401
        return {"message": "Invalid session"}

    if elapsed > SESSION_MAX_AGE_SECONDS:
        response.status_code = 401
        return {"message": "Session expired"}

    if SESSION_REFRESH_THRESHOLD_SECONDS <= elapsed < SESSION_MAX_AGE_SECONDS:
        refreshed_token = _make_signed_session_token(user_id, now_ts)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=refreshed_token,
            httponly=True,
            secure=False,
            max_age=SESSION_MAX_AGE_SECONDS,
        )

    return {
        "user_id": user_id,
        "username": "user123",
        "email": "user123@example.com",
        "message": "Profile data is available",
    }


# --- Задание 5.4 + 5.5 (headers + DRY CommonHeaders) ---
@app.get("/headers")
async def read_headers(headers: CommonHeaders = Depends(get_common_headers)) -> dict[str, str]:
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }


@app.get("/info")
async def info(response: Response, headers: CommonHeaders = Depends(get_common_headers)) -> dict[str, Any]:
    response.headers["X-Server-Time"] = datetime.now().isoformat(timespec="seconds")
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }
