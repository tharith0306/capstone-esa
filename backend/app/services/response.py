"""Approval workflow for response actions: proposed -> approved|rejected -> executed|failed -> rolled_back."""

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.models import IncidentRecord, ResponseActionRecord, utcnow
from app.response.executor import ExecutionError, ResponseExecutor
from app.services.audit import audit
from app.services.serialize import row_to_dict


class WorkflowError(ValueError):
    pass


class ResponseService:
    def __init__(self, session_factory: sessionmaker[Session], settings: Settings,
                 executor: ResponseExecutor | None = None):
        self.session_factory = session_factory
        self.executor = executor or ResponseExecutor(settings)

    def _load(self, session: Session, action_id: str) -> ResponseActionRecord:
        action = session.get(ResponseActionRecord, action_id)
        if action is None:
            raise KeyError(action_id)
        return action

    def decide(self, action_id: str, analyst: str, approve: bool, note: str | None = None) -> dict:
        with self.session_factory() as session:
            action = self._load(session, action_id)
            if action.status != "proposed":
                raise WorkflowError(f"action is {action.status}; only proposed actions can be decided")
            action.status = "approved" if approve else "rejected"
            action.decided_by, action.decided_at, action.decision_note = analyst, utcnow(), note
            incident = session.get(IncidentRecord, action.incident_id)
            if incident and incident.status == "open":
                incident.status = "investigating"
            audit(session, analyst, "approve" if approve else "reject", "response_action", action_id,
                  action_type=action.action_type, target=action.target, note=note)
            session.commit()
            return row_to_dict(action)

    def execute(self, action_id: str, analyst: str, rollback: bool = False) -> dict:
        with self.session_factory() as session:
            action = self._load(session, action_id)
            if rollback:
                if action.status != "executed" or not action.reversible:
                    raise WorkflowError("only executed, reversible actions can be rolled back")
            elif action.status != "approved":
                raise WorkflowError(f"action is {action.status}; it must be approved before execution")
            if not action.automatable:
                raise WorkflowError("manual action: perform it outside CloudShield and record it in the notes")
            try:
                result = self.executor.execute(action.action_type, action.target, rollback=rollback)
            except ExecutionError as exc:
                action.status, action.error = "failed", str(exc)
                audit(session, analyst, "execute_failed", "response_action", action_id, error=str(exc))
                session.commit()
                raise WorkflowError(str(exc)) from exc
            action.execution = result
            action.executed_at = utcnow()
            action.error = None
            action.status = "rolled_back" if rollback else "executed"
            incident = session.get(IncidentRecord, action.incident_id)
            if incident and not rollback and incident.status in ("open", "investigating"):
                incident.status = "contained"
            audit(session, analyst, "rollback" if rollback else "execute", "response_action", action_id,
                  mode=result["mode"], operation=f"{result['service']}:{result['operation']}",
                  params=result["params"])
            session.commit()
            return row_to_dict(action)
