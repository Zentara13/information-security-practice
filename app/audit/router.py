# app/audit/router.py
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.audit.detector import get_security_stats
from app.audit.logger import get_client_ip, log_event
from app.auth.dependencies import require_role
from app.database import get_db
from app.models import AuditLog, User

router = APIRouter(prefix="/admin", tags=["Audit"])


@router.get("/audit-log")
def get_audit_log(
    request: Request,
    action: str | None = Query(None, max_length=50),
    username: str | None = Query(None, max_length=50),
    ip: str | None = Query(None, max_length=45),
    status: str | None = Query(None, pattern="^(success|failure|warning|error)$"),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(AuditLog).filter(AuditLog.timestamp >= since)
    if action:
        q = q.filter(AuditLog.action == action)
    if username:
        q = q.filter(AuditLog.username == username)
    if ip:
        q = q.filter(AuditLog.ip_address == ip)
    if status:
        q = q.filter(AuditLog.status == status)

    total = q.count()
    rows = q.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    # «Хто стереже сторожів»: перегляд журналу теж фіксується
    log_event(db, "audit_log_viewed", "success", get_client_ip(request),
              user_id=admin.id, username=admin.username, http_method="GET",
              endpoint="/admin/audit-log", details={"filter_action": action, "hours": hours})

    return {"total": total, "logs": [{
        "id": r.id, "timestamp": r.timestamp.isoformat(), "action": r.action,
        "status": r.status, "user_id": r.user_id, "username": r.username,
        "ip_address": r.ip_address, "method": r.http_method, "endpoint": r.endpoint,
        "status_code": r.status_code, "details": r.details,
    } for r in rows]}


@router.get("/security-stats")
def security_stats(hours: int = Query(24, ge=1, le=720),
                   db: Session = Depends(get_db),
                   admin: User = Depends(require_role("admin"))):
    return get_security_stats(db, hours)
