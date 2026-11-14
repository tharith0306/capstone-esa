import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import jwt
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.security import ROLES, create_token, decode_token, hash_password, verify_password
from app.database.models import RevokedToken, User, utcnow
from app.services.audit import audit

log = logging.getLogger(__name__)
MIN_PASSWORD_LENGTH = 10


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    jti: str | None = None
    expires_at: datetime | None = None


ANONYMOUS_ADMIN = Principal("anonymous", "admin")  # only when auth is disabled (local experiments)


class AuthService:
    def __init__(self, session_factory: sessionmaker[Session], settings: Settings):
        self.session_factory = session_factory
        self.settings = settings
        self.secret = settings.jwt_secret or secrets.token_urlsafe(48)

    def bootstrap_admin(self) -> None:
        with self.session_factory() as session:
            if session.scalar(select(func.count()).select_from(User)):
                return
            password = self.settings.bootstrap_admin_password
            generated = password is None
            if generated:
                password = secrets.token_urlsafe(12)
            session.add(User(username=self.settings.bootstrap_admin_username, password_hash=hash_password(password),
                             role="admin"))
            audit(session, "system", "bootstrap_admin", "user", self.settings.bootstrap_admin_username)
            session.commit()
        if generated:
            log.warning("Created admin user %r with generated password: %s  (set CLOUDSHIELD_BOOTSTRAP_ADMIN_PASSWORD "
                        "to choose it; change it after first login)", self.settings.bootstrap_admin_username, password)

    def login(self, username: str, password: str) -> dict:
        with self.session_factory() as session:
            user = session.scalar(select(User).where(User.username == username))
            if user is None or not user.active or not verify_password(password, user.password_hash):
                audit(session, username, "login_failed", "user", username)
                session.commit()
                raise AuthError("invalid username or password")
            user.last_login = utcnow()
            token, jti, expires = create_token(self.secret, user.username, user.role, self.settings.token_ttl_minutes)
            audit(session, username, "login", "user", username)
            session.commit()
            return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat(),
                    "user": {"username": user.username, "role": user.role}}

    def authenticate(self, token: str) -> Principal:
        try:
            claims = decode_token(self.secret, token)
        except jwt.PyJWTError as exc:
            raise AuthError("invalid or expired token") from exc
        with self.session_factory() as session:
            if session.get(RevokedToken, claims["jti"]):
                raise AuthError("token has been revoked")
            user = session.scalar(select(User).where(User.username == claims["sub"]))
            if user is None or not user.active:
                raise AuthError("user disabled")
            return Principal(user.username, user.role, claims["jti"],
                             datetime.fromtimestamp(claims["exp"], tz=timezone.utc))

    def logout(self, principal: Principal) -> None:
        if not principal.jti:
            return
        with self.session_factory() as session:
            session.execute(delete(RevokedToken).where(RevokedToken.expires_at < utcnow()))
            session.merge(RevokedToken(jti=principal.jti, expires_at=principal.expires_at or utcnow()))
            audit(session, principal.username, "logout", "user", principal.username)
            session.commit()

    def create_user(self, actor: Principal, username: str, password: str, role: str) -> dict:
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise AuthError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        with self.session_factory() as session:
            if session.scalar(select(User).where(User.username == username)):
                raise AuthError("username already exists")
            session.add(User(username=username, password_hash=hash_password(password), role=role))
            audit(session, actor.username, "create_user", "user", username, role=role)
            session.commit()
        return {"username": username, "role": role}

    def list_users(self) -> list[dict]:
        with self.session_factory() as session:
            return [{"username": u.username, "role": u.role, "active": u.active, "last_login": u.last_login,
                     "created_at": u.created_at} for u in session.scalars(select(User).order_by(User.username))]
