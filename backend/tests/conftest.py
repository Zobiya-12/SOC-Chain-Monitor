import dataclasses
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


class FakeChain:
    """In-memory stand-in for the LogAnchor contract (write-once, like the real one)."""

    mode = "fake"
    address = "0xFAKE"
    chain_id = 31337

    def __init__(self):
        self.roots = {}

    def anchor_root(self, batch_id, root_hex):
        if batch_id in self.roots:
            raise RuntimeError("batch already anchored")
        self.roots[batch_id] = root_hex
        return {"tx_hash": "0x" + "ab" * 32, "block_number": len(self.roots), "chain_id": self.chain_id}

    def get_root(self, batch_id):
        return self.roots.get(batch_id)

    def last_batch_id(self):
        return max(self.roots, default=0)


class Switch:
    """Lets a test turn the fake blockchain on and off."""

    def __init__(self):
        self.chain = FakeChain()
        self.up = True

    def __call__(self, _settings):
        return (self.chain, None) if self.up else (None, "node down (simulated)")


def make_settings(tmp_path: Path, **overrides) -> Settings:
    base = dataclasses.replace(
        Settings.from_env(),
        db_path=str(tmp_path / "test.db"),
        api_key=None, demo_mode=True, max_pending=1000, chain_enabled=True,
    )
    return dataclasses.replace(base, **overrides)


LOGS = [
    {"timestamp": "2026-10-14T09:00:00", "source": "aws-cloudtrail", "event_type": "ConsoleLogin", "actor": "alice", "detail": "success"},
    {"timestamp": "2026-10-14T09:05:00", "source": "aws-cloudtrail", "event_type": "AssumeRole", "actor": "alice", "detail": "role DevOps"},
    {"timestamp": "2026-10-14T09:10:00", "source": "auth-service", "event_type": "FailedLogin", "actor": "bob", "detail": "bad password"},
    {"timestamp": "2026-10-14T09:15:00", "source": "aws-cloudtrail", "event_type": "StopLogging", "actor": "bob", "detail": "trail disabled"},
]


@pytest.fixture
def switch():
    return Switch()


@pytest.fixture
def client(tmp_path, switch):
    app = create_app(make_settings(tmp_path), chain_connector=switch)
    with TestClient(app) as c:
        yield c


def seal_sample(client, logs=LOGS):
    for log in logs:
        assert client.post("/logs/ingest", json=log).status_code == 200
    response = client.post("/logs/seal-batch")
    assert response.status_code == 200, response.text
    return response.json()
