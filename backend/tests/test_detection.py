from app.detection import DetectionConfig, evaluate


def ev(ts, event, actor="u", detail=""):
    return {"timestamp": ts, "event_type": event, "actor": actor, "detail": detail}


def rules(alerts):
    return [a.rule for a in alerts]


def test_clean_business_hours_activity_raises_nothing():
    assert evaluate([ev("2026-10-14T10:00:00", "ConsoleLogin", "alice", "success")]) == []


def test_brute_force_needs_threshold_inside_window():
    fails = [ev(f"2026-10-14T10:0{i}:00", "FailedLogin", "bob") for i in range(3)]
    assert "BRUTE_FORCE" in rules(evaluate(fails))
    slow = [ev(f"2026-10-14T1{i}:00:00", "FailedLogin", "bob") for i in range(3)]  # hours apart
    assert "BRUTE_FORCE" not in rules(evaluate(slow))
    two = fails[:2]
    assert "BRUTE_FORCE" not in rules(evaluate(two))


def test_failures_are_counted_per_actor():
    mixed = [ev(f"2026-10-14T10:0{i}:00", "FailedLogin", f"user{i}") for i in range(3)]
    assert "BRUTE_FORCE" not in rules(evaluate(mixed))


def test_success_after_brute_force_is_critical():
    logs = [ev(f"2026-10-14T10:0{i}:00", "FailedLogin", "bob") for i in range(3)]
    logs.append(ev("2026-10-14T10:04:00", "ConsoleLogin", "bob", "success"))
    found = {a.rule: a for a in evaluate(logs)}
    assert found["BRUTE_FORCE_SUCCESS"].severity == "CRITICAL"
    assert found["BRUTE_FORCE_SUCCESS"].log_index == 3


def test_console_login_marked_failure_counts_as_failed():
    logs = [ev(f"2026-10-14T10:0{i}:00", "ConsoleLogin", "bob", "login failed") for i in range(3)]
    assert "BRUTE_FORCE" in rules(evaluate(logs))


def test_off_hours_login_and_custom_window():
    night = ev("2026-10-14T02:30:00", "ConsoleLogin", "alice", "success")
    assert "OFF_HOURS_LOGIN" in rules(evaluate([night]))
    assert "OFF_HOURS_LOGIN" not in rules(evaluate([night], DetectionConfig(off_hours_start=0, off_hours_end=0)))


def test_privilege_escalation_severity():
    admin = evaluate([ev("2026-10-14T10:00:00", "AttachRolePolicy", "bob", "AdministratorAccess")])
    plain = evaluate([ev("2026-10-14T10:00:00", "CreateAccessKey", "bob", "for ci")])
    assert admin[0].rule == "PRIVILEGE_ESCALATION" and admin[0].severity == "CRITICAL"
    assert plain[0].rule == "PRIVILEGE_ESCALATION" and plain[0].severity == "HIGH"


def test_audit_logging_disabled():
    found = evaluate([ev("2026-10-14T10:00:00", "StopLogging", "bob")])
    assert found[0].rule == "AUDIT_LOGGING_DISABLED" and found[0].severity == "CRITICAL"


def test_root_account_usage():
    assert "ROOT_ACCOUNT_USAGE" in rules(evaluate([ev("2026-10-14T10:00:00", "ListBuckets", "root")]))
    assert "ROOT_ACCOUNT_USAGE" in rules(evaluate([ev("2026-10-14T10:00:00", "ListBuckets", "arn:aws:iam::123:root")]))


def test_bad_timestamps_do_not_crash():
    assert evaluate([ev("not-a-time", "FailedLogin", "bob"), {"event_type": "ConsoleLogin"}]) == []


def test_unsorted_logs_are_handled():
    logs = [ev(f"2026-10-14T10:0{i}:00", "FailedLogin", "bob") for i in (2, 0, 1)]
    assert "BRUTE_FORCE" in rules(evaluate(logs))
