from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.deps import current_user, require_role
from app.services.auth import AuthError, AuthService, Principal

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _service(request: Request) -> AuthService:
    return request.app.state.auth


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: Literal["viewer", "analyst", "admin"] = "analyst"


@router.post("/login")
def login(body: LoginRequest, service: Annotated[AuthService, Depends(_service)]) -> dict:
    try:
        return service.login(body.username, body.password)
    except AuthError as exc:
        raise HTTPException(401, str(exc))


@router.post("/logout")
def logout(user: Annotated[Principal, Depends(current_user)], service: Annotated[AuthService, Depends(_service)]) -> dict:
    service.logout(user)
    return {"logged_out": True}


@router.get("/me")
def me(user: Annotated[Principal, Depends(current_user)]) -> dict:
    return {"username": user.username, "role": user.role, "expires_at": user.expires_at}


@router.post("/register", dependencies=[Depends(require_role("admin"))])
def register(body: RegisterRequest, request: Request, service: Annotated[AuthService, Depends(_service)]) -> dict:
    """Admins create accounts. There is deliberately no public self-registration."""
    try:
        return service.create_user(request.state.user, body.username, body.password, body.role)
    except AuthError as exc:
        raise HTTPException(400, str(exc))


@router.get("/users", dependencies=[Depends(require_role("admin"))])
def users(service: Annotated[AuthService, Depends(_service)]) -> list[dict]:
    return service.list_users()
