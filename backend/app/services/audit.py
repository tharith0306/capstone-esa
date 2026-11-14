from typing import Any

from sqlalchemy.orm import Session

from app.database.models import AuditLog


def audit(session: Session, actor: str, action: str, object_type: str, object_id: str, **details: Any) -> None:
    session.add(AuditLog(actor=actor, action=action, object_type=object_type, object_id=object_id, details=details))
