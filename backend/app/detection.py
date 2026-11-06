"""
SOC detection rules. Pure functions: logs in -> alerts out, so each rule is
easy to unit-test. Rules implemented:

  BRUTE_FORCE               repeated failed logins by one actor in a short window
  BRUTE_FORCE_SUCCESS       ...followed by a successful login (likely compromise)
  OFF_HOURS_LOGIN           successful login outside business hours (UTC)
  PRIVILEGE_ESCALATION      IAM permission changes (CRITICAL if admin-level)
  AUDIT_LOGGING_DISABLED    CloudTrail/GuardDuty switched off (defense evasion)
  ROOT_ACCOUNT_USAGE        any activity by the root account
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .config import Settings

FAILED_EVENTS = {"failedlogin", "consoleloginfailure", "authfailure", "loginfailed"}
LOGIN_EVENTS = {"consolelogin", "login", "loginsuccess"}
PRIV_ESC_EVENTS = {
    "attachrolepolicy", "attachuserpolicy", "attachgrouppolicy", "putuserpolicy", "putrolepolicy",
    "putgrouppolicy", "createpolicyversion", "setdefaultpolicyversion", "addusertogroup",
    "createaccesskey", "updateassumerolepolicy", "createloginprofile",
}
AUDIT_OFF_EVENTS = {
    "stoplogging", "deletetrail", "updatetrail", "puteventselectors", "deletedetector",
    "disablegaurdduty", "disableguardduty", "deleteflowlogs", "deleteconfigurationrecorder",
}
ADMIN_MARKERS = ("administratoraccess", "iamfullaccess", '"action":"*"', "*:*")


@dataclass
class DetectionConfig:
    brute_force_threshold: int = 3
    brute_force_window_minutes: int = 5
    off_hours_start: int = 22
    off_hours_end: int = 6

    @classmethod
    def from_settings(cls, s: Settings) -> "DetectionConfig":
        return cls(s.brute_force_threshold, s.brute_force_window_minutes, s.off_hours_start, s.off_hours_end)


@dataclass
class Alert:
    rule: str
    severity: str
    message: str
    log_index: int
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "message": self.message,
                "log_index": self.log_index, "details": self.details}


def parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _login_kind(event_type: str, detail: str) -> Optional[str]:
    et = (event_type or "").lower()
    if et in FAILED_EVENTS:
        return "fail"
    if et in LOGIN_EVENTS:
        return "fail" if "fail" in (detail or "").lower() else "success"
    return None


def _is_off_hours(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    return hour >= start or hour < end if start > end else start <= hour < end


def _is_root(actor: str) -> bool:
    a = (actor or "").strip().lower()
    return a == "root" or a.endswith(":root") or a.endswith("/root")


def evaluate(logs: List[dict], cfg: Optional[DetectionConfig] = None) -> List[Alert]:
    cfg = cfg or DetectionConfig()
    alerts: List[Alert] = []
    indexed = []  # (index, log, parsed timestamp or None, login kind)
    for i, log in enumerate(logs):
        indexed.append((i, log, parse_ts(log.get("timestamp")),
                        _login_kind(str(log.get("event_type", "")), str(log.get("detail") or ""))))

    # ---- brute force + success-after-brute-force (grouped by actor) --------
    window = timedelta(minutes=cfg.brute_force_window_minutes)
    failures_by_actor: Dict[str, list] = defaultdict(list)
    for i, log, ts, kind in indexed:
        if kind == "fail" and ts is not None:
            failures_by_actor[str(log.get("actor"))].append((ts, i))

    for actor, fails in failures_by_actor.items():
        fails.sort()
        recent: deque = deque()
        for ts, i in fails:
            recent.append((ts, i))
            while recent and ts - recent[0][0] > window:
                recent.popleft()
            if len(recent) >= cfg.brute_force_threshold:
                alerts.append(Alert(
                    "BRUTE_FORCE", "HIGH",
                    f"{len(recent)} failed logins for '{actor}' within {cfg.brute_force_window_minutes} min",
                    i, {"actor": actor, "failures": len(recent)}))
                for s_i, s_log, s_ts, s_kind in indexed:
                    if (s_kind == "success" and s_ts is not None and str(s_log.get("actor")) == actor
                            and ts <= s_ts <= ts + timedelta(hours=1)):
                        alerts.append(Alert(
                            "BRUTE_FORCE_SUCCESS", "CRITICAL",
                            f"Successful login for '{actor}' right after {len(recent)} failures - "
                            "possible account takeover",
                            s_i, {"actor": actor, "failures_before": len(recent)}))
                        break
                break  # one brute-force alert per actor per batch

    # ---- single-event rules -------------------------------------------------
    for i, log, ts, kind in indexed:
        event = str(log.get("event_type", ""))
        et = event.lower()
        actor = str(log.get("actor", ""))
        detail = str(log.get("detail") or "")

        if kind == "success" and ts is not None and _is_off_hours(ts.hour, cfg.off_hours_start, cfg.off_hours_end):
            alerts.append(Alert("OFF_HOURS_LOGIN", "MEDIUM",
                                f"Login by '{actor}' at {ts.strftime('%H:%M')} UTC (outside business hours)",
                                i, {"actor": actor, "hour_utc": ts.hour}))

        if et in PRIV_ESC_EVENTS:
            is_admin = any(marker in detail.lower() for marker in ADMIN_MARKERS)
            alerts.append(Alert("PRIVILEGE_ESCALATION", "CRITICAL" if is_admin else "HIGH",
                                f"{event} by '{actor}'" + (" granting administrator-level access" if is_admin else ""),
                                i, {"actor": actor, "event": event, "admin_level": is_admin}))

        if et in AUDIT_OFF_EVENTS:
            alerts.append(Alert("AUDIT_LOGGING_DISABLED", "CRITICAL",
                                f"{event} by '{actor}' - audit logging may have been turned off",
                                i, {"actor": actor, "event": event}))

        if _is_root(actor):
            alerts.append(Alert("ROOT_ACCOUNT_USAGE", "HIGH", f"Root account activity: {event}",
                                i, {"actor": actor, "event": event}))

    alerts.sort(key=lambda a: (a.log_index, a.rule))
    return alerts
