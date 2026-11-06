import dataclasses
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from conftest import LOGS, make_settings, seal_sample


# ------------------------------------------------------------ happy path
def test_seal_anchors_and_raises_alerts(client, switch):
    batch = seal_sample(client)
    assert batch["anchored"] is True and batch["tx_hash"]
    assert switch.chain.get_root(batch["batch_id"]) == batch["merkle_root"]
    assert batch["alerts_raised"] >= 1
    summary = client.get("/alerts/summary").json()
    assert "AUDIT_LOGGING_DISABLED" in summary["by_rule"]


def test_untouched_batch_is_intact_and_verifies(client):
    batch = seal_sample(client)
    bid = batch["batch_id"]
    assert client.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "INTACT"
    stored = client.get(f"/logs/batch/{bid}").json()["logs"]
    r = client.post("/logs/verify", json={"batch_id": bid, "log_index": 2, "log_entry": stored[2]}).json()
    assert r["valid"] is True and r["status"] == "valid"


# ------------------------------------------- the flaws found in the review
def test_fail_closed_when_chain_is_down(client, switch):
    batch = seal_sample(client)
    bid = batch["batch_id"]
    client.post(f"/demo/tamper/{bid}/2", params={"new_detail": "x", "rewrite_local_root": "true"})
    switch.up = False
    integrity = client.get(f"/logs/batch/{bid}/integrity").json()
    assert integrity["verdict"] == "UNVERIFIABLE"          # was "INTACT (local check only)"
    stored = client.get(f"/logs/batch/{bid}").json()["logs"]
    verify = client.post("/logs/verify", json={"batch_id": bid, "log_index": 2, "log_entry": stored[2]}).json()
    assert verify["valid"] is False and verify["status"] == "unverifiable"


def test_verify_detects_modified_stored_log(client):
    batch = seal_sample(client)
    bid = batch["batch_id"]
    original = client.get(f"/logs/batch/{bid}").json()["logs"][2]
    client.post(f"/demo/tamper/{bid}/2", params={"new_detail": "edited"})
    r = client.post("/logs/verify", json={"batch_id": bid, "log_index": 2, "log_entry": original}).json()
    assert r["valid"] is False and r["stored_matches_seal"] is False and r["submitted_matches_seal"] is True


def test_verify_detects_an_edited_submission(client):
    bid = seal_sample(client)["batch_id"]
    edited = dict(client.get(f"/logs/batch/{bid}").json()["logs"][1], detail="changed")
    r = client.post("/logs/verify", json={"batch_id": bid, "log_index": 1, "log_entry": edited}).json()
    assert r["valid"] is False and r["submitted_matches_seal"] is False and r["stored_matches_seal"] is True


def test_smart_attacker_is_caught_by_the_chain(client):
    bid = seal_sample(client)["batch_id"]
    client.post(f"/demo/tamper/{bid}/3", params={"new_detail": "nothing happened", "rewrite_local_root": "true"})
    r = client.get(f"/logs/batch/{bid}/integrity").json()
    assert r["matches_local_root"] is True            # the local check is fooled...
    assert r["matches_onchain_root"] is False         # ...the blockchain is not
    assert r["verdict"] == "TAMPERED" and r["local_root_rewritten"] is True
    rules = [a["rule"] for a in client.get("/alerts").json()["alerts"]]
    assert "LOG_TAMPERING" in rules


def test_tamper_alert_is_not_duplicated(client):
    bid = seal_sample(client)["batch_id"]
    client.post(f"/demo/tamper/{bid}/0", params={"new_detail": "x"})
    for _ in range(3):
        client.get(f"/logs/batch/{bid}/integrity")
    rules = [a["rule"] for a in client.get(f"/alerts?batch_id={bid}").json()["alerts"]]
    assert rules.count("LOG_TAMPERING") == 1


# ---------------------------------------------- anchoring problems / retry
def test_unanchored_batch_can_be_anchored_later(client, switch):
    switch.up = False
    batch = seal_sample(client)
    bid = batch["batch_id"]
    assert batch["anchored"] is False and "node down" in batch["anchor_error"]
    assert client.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "UNVERIFIABLE"
    switch.up = True
    assert client.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "UNANCHORED"
    assert client.post(f"/logs/batch/{bid}/anchor").json()["anchored"] is True
    assert client.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "INTACT"


def test_refuses_to_anchor_modified_data(client, switch):
    switch.up = False
    bid = seal_sample(client)["batch_id"]
    client.post(f"/demo/tamper/{bid}/0", params={"new_detail": "edited"})
    switch.up = True
    assert client.post(f"/logs/batch/{bid}/anchor").status_code == 409


def test_new_batches_skip_ids_already_used_on_chain(client, switch):
    switch.chain.roots[7] = "ab" * 32
    assert seal_sample(client)["batch_id"] == 8


# ------------------------------------------------------------ persistence
def test_batches_and_alerts_survive_a_restart(tmp_path, switch):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings, chain_connector=switch)) as first:
        bid = seal_sample(first)["batch_id"]
    with TestClient(create_app(settings, chain_connector=switch)) as second:
        assert second.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "INTACT"
        assert second.get("/alerts/summary").json()["total"] >= 1
        assert len(second.get("/logs/batches").json()) == 1


# --------------------------------------------------------------- security
def test_api_key_protects_write_endpoints(tmp_path, switch):
    app = create_app(make_settings(tmp_path, api_key="s3cret"), chain_connector=switch)
    with TestClient(app) as c:
        assert c.post("/logs/ingest", json=LOGS[0]).status_code == 401
        assert c.post("/logs/ingest", json=LOGS[0], headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.post("/logs/ingest", json=LOGS[0], headers={"X-API-Key": "s3cret"}).status_code == 200
        assert c.post("/logs/seal-batch").status_code == 401
        assert c.get("/health").json()["auth_enabled"] is True


def test_demo_endpoints_are_off_by_default(tmp_path, switch):
    app = create_app(make_settings(tmp_path, demo_mode=False), chain_connector=switch)
    with TestClient(app) as c:
        assert c.post("/demo/tamper/1/0", params={"new_detail": "x"}).status_code == 404


def test_input_limits(tmp_path, switch):
    app = create_app(make_settings(tmp_path, max_pending=2), chain_connector=switch)
    with TestClient(app) as c:
        assert c.post("/logs/ingest", json={**LOGS[0], "source": "s" * 5000}).status_code == 422
        assert c.post("/logs/ingest", json={**LOGS[0], "unexpected": 1}).status_code == 422
        assert c.post("/logs/ingest", json=LOGS[0]).status_code == 200
        assert c.post("/logs/ingest", json=LOGS[1]).status_code == 200
        assert c.post("/logs/ingest", json=LOGS[2]).status_code == 429
        big = {"batch_id": 1, "log_index": 0, "log_entry": {"x": "y" * 20000}}
        assert c.post("/logs/verify", json=big).status_code == 422


def test_errors_for_missing_things(client):
    assert client.post("/logs/seal-batch").status_code == 400
    assert client.get("/logs/batch/99").status_code == 404
    assert client.get("/logs/batch/99/integrity").status_code == 404


def test_dashboard_is_served_with_a_strict_csp(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/static/dashboard.js").status_code == 200


def test_landing_page_is_served_at_root_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and "SOC Chain Monitor" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/static/landing.js").status_code == 200
    assert client.get("/static/landing.css").status_code == 200


def test_console_assets_are_served(client):
    for name in ("dashboard.css", "dashboard.js", "console-fx.js", "merkle-viz.js", "landing.css", "landing.js"):
        assert client.get(f"/static/{name}").status_code == 200, name


def test_simulated_chain_detects_tampering(tmp_path):
    app = create_app(make_settings(tmp_path, chain_mode="simulated"))   # default connector, no fake
    with TestClient(app) as c:
        assert c.get("/health").json()["chain"]["mode"] == "simulated"
        bid = seal_sample(c)["batch_id"]
        assert c.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "INTACT"
        c.post(f"/demo/tamper/{bid}/3", params={"new_detail": "nothing happened", "rewrite_local_root": "true"})
        r = c.get(f"/logs/batch/{bid}/integrity").json()
        assert r["verdict"] == "TAMPERED" and r["local_root_rewritten"] is True
    with TestClient(create_app(make_settings(tmp_path, chain_mode="simulated"))) as again:   # survives restart
        assert again.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "TAMPERED"
