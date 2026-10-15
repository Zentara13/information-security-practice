# app/audit/logger.py
import json
import logging

from sqlalchemy.orm import Session
from starlette.requests import Request

from app.models import AuditLog

SENSITIVE_KEYS = {"password", "token", "access_token", "refresh_token", "secret", "key"}

logger = logging.getLogger("security_audit")
if not logger.handlers:  # без дублювання при --reload
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter('{"ts":"%(asctime)s","level":"%(levelname)s","event":%(message)s}'))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def get_client_ip(request: Request) -> str:
    """IP клієнта. За Nginx його підставляє uvicorn --proxy-headers з X-Forwarded-For."""
    return request.client.host if request.client else "unknown"


def _clean(details: dict | None) -> dict | None:
    if not details:
        return None
    return {k: ("***" if k.lower() in SENSITIVE_KEYS else v) for k, v in details.items()}


def log_event(db: Session, action: str, status: str, ip_address: str, *,
              user_id: int | None = None, username: str | None = None,
              http_method: str | None = None, endpoint: str | None = None,
              status_code: int | None = None, resource: str | None = None,
              details: dict | None = None) -> None:
    """Пише подію в audit_log (БД) і в stdout (JSON для docker logs / SIEM)."""
    details = _clean(details)
    try:
        db.add(AuditLog(
            user_id=user_id, username=username, ip_address=ip_address,
            action=action, resource=resource, http_method=http_method,
            endpoint=endpoint, status=status, status_code=status_code,
            details=json.dumps(details, ensure_ascii=False) if details else None,
        ))
        db.commit()
    except Exception:  # збій аудиту не повинен ламати запит
        db.rollback()
        logger.exception(json.dumps({"action": "audit_write_failed"}))

    level = logging.WARNING if status in ("failure", "warning", "error") else logging.INFO
    logger.log(level, json.dumps({
        "action": action, "status": status, "user_id": user_id, "username": username,
        "ip": ip_address, "endpoint": endpoint, "code": status_code, "details": details,
    }, ensure_ascii=False))


def log_login_success(db, user_id, username, ip):
    log_event(db, "login_success", "success", ip, user_id=user_id, username=username,
              http_method="POST", endpoint="/auth/login", status_code=200)


def log_login_failed(db, username, ip, reason="invalid_credentials"):
    log_event(db, "login_failed", "failure", ip, username=username,
              http_method="POST", endpoint="/auth/login", status_code=401,
              details={"reason": reason})


def log_data_change(db, user, ip, resource, old, new, endpoint=None):
    """Зміна оцінки, ролі тощо: зберігаємо старе → нове значення (Repudiation)."""
    log_event(db, "data_change", "success", ip, user_id=user.id, username=user.username,
              endpoint=endpoint, resource=resource, details={"old": old, "new": new})
