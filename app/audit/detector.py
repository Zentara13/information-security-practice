# app/audit/detector.py
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.audit.logger import log_event
from app.models import AuditLog

KYIV = ZoneInfo("Europe/Kyiv")


def check_brute_force(db: Session, ip: str, username: str | None = None,
                      threshold: int = 5, window_minutes: int = 5) -> bool:
    """True, якщо з цієї IP АБО на цей логін було >= threshold невдалих входів за вікно."""
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    who = AuditLog.ip_address == ip
    if username:
        who = or_(who, AuditLog.username == username)
    failed = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "login_failed", AuditLog.timestamp >= since, who
    ).scalar()
    if failed >= threshold:
        log_event(db, "brute_force_detected", "warning", ip, username=username,
                  endpoint="/auth/login",
                  details={"failed_attempts": failed, "window_minutes": window_minutes})
        return True
    return False


def check_off_hours_access(db: Session, user_id: int, username: str, ip: str) -> bool:
    hour = datetime.now(KYIV).hour
    if 0 <= hour < 6:
        log_event(db, "off_hours_login", "warning", ip, user_id=user_id,
                  username=username, details={"local_hour": hour})
        return True
    return False


def get_security_stats(db: Session, hours: int = 24) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    counts = dict(db.query(AuditLog.action, func.count(AuditLog.id))
                  .filter(AuditLog.timestamp >= since)
                  .group_by(AuditLog.action).all())
    top_ips = (db.query(AuditLog.ip_address, func.count(AuditLog.id))
               .filter(AuditLog.timestamp >= since, AuditLog.status == "failure")
               .group_by(AuditLog.ip_address).order_by(func.count(AuditLog.id).desc())
               .limit(5).all())
    return {
        "period_hours": hours,
        "total_events": sum(counts.values()),
        "failed_logins": counts.get("login_failed", 0),
        "access_denied": counts.get("access_denied", 0),
        "brute_force_alerts": counts.get("brute_force_detected", 0),
        "off_hours_logins": counts.get("off_hours_login", 0),
        "data_changes": counts.get("data_change", 0),
        "server_errors": counts.get("server_error", 0),
        "top_failure_ips": [{"ip": ip, "failures": n} for ip, n in top_ips],
    }
