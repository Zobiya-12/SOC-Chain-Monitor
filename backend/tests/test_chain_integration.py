"""
Real-blockchain tests. They SKIP automatically unless a local node is running
with the contract deployed:

    cd contracts && npx hardhat node                                  (terminal 1)
    cd contracts && npx hardhat run scripts/deploy.js --network localhost   (terminal 2)
    cd backend   && python -m pytest tests/test_chain_integration.py -v

To also test SIGNED transactions (the mode used on Sepolia), export one of the
private keys printed by `npx hardhat node` first (local test keys only):
    $env:TEST_CHAIN_PRIVATE_KEY = "0x..."
"""

import dataclasses
import os

import pytest
from fastapi.testclient import TestClient

from app.chain import try_connect
from app.config import Settings
from app.main import create_app
from conftest import LOGS, make_settings, seal_sample

pytestmark = pytest.mark.chain


@pytest.fixture
def real_settings(tmp_path):
    settings = make_settings(tmp_path, chain_private_key=None)
    client, reason = try_connect(settings)
    if client is None:
        pytest.skip(f"no local blockchain available: {reason}")
    return settings


def test_full_flow_on_a_real_chain(real_settings):
    with TestClient(create_app(real_settings)) as c:
        batch = seal_sample(c)
        bid = batch["batch_id"]
        assert batch["anchored"] is True and batch["tx_hash"].startswith("0x")
        assert c.get(f"/logs/batch/{bid}/integrity").json()["verdict"] == "INTACT"

        c.post(f"/demo/tamper/{bid}/3", params={"new_detail": "nothing happened", "rewrite_local_root": "true"})
        result = c.get(f"/logs/batch/{bid}/integrity").json()
        assert result["matches_local_root"] is True and result["matches_onchain_root"] is False
        assert result["verdict"] == "TAMPERED" and result["local_root_rewritten"] is True


def test_the_real_contract_is_write_once(real_settings):
    client, _ = try_connect(real_settings)
    batch_id = client.last_batch_id() + 1
    client.anchor_root(batch_id, "ab" * 32)
    with pytest.raises(Exception) as excinfo:
        client.anchor_root(batch_id, "cd" * 32)
    assert "already anchored" in str(excinfo.value)
    assert client.get_root(batch_id) == "ab" * 32


def test_signed_transaction_mode(real_settings):
    key = os.getenv("TEST_CHAIN_PRIVATE_KEY")
    if not key:
        pytest.skip("set TEST_CHAIN_PRIVATE_KEY to test signed transactions")
    signed_settings = dataclasses.replace(real_settings, chain_private_key=key)
    client, reason = try_connect(signed_settings)
    assert client is not None, reason
    assert client.mode == "signed"
    batch_id = client.last_batch_id() + 1
    result = client.anchor_root(batch_id, "ef" * 32)
    assert result["tx_hash"].startswith("0x") and client.get_root(batch_id) == "ef" * 32


def test_unreachable_node_fails_closed(real_settings):
    dead = dataclasses.replace(real_settings, chain_rpc_url="http://127.0.0.1:9")
    with TestClient(create_app(dead)) as c:
        batch = seal_sample(c)
        assert batch["anchored"] is False
        assert c.get(f"/logs/batch/{batch['batch_id']}/integrity").json()["verdict"] == "UNVERIFIABLE"
