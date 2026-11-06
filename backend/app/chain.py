"""
Talks to the LogAnchor smart contract through web3.py.

Two signing modes:
  * unlocked - local Hardhat node: the node signs for its first account.
  * signed   - testnets (Sepolia): set CHAIN_PRIVATE_KEY and we sign locally.

try_connect() never raises. It returns (client, None) on success or
(None, "human readable reason") on failure. Callers must treat a missing
client as "cannot prove anything" - never as "everything is fine".
"""

import hashlib
import json
import sqlite3
import threading
from typing import Any, Dict, Optional, Tuple

from web3 import Web3

from .config import Settings

ZERO_ROOT = "0" * 64

EXPLORERS = {
    11155111: "https://sepolia.etherscan.io/tx/",
    1: "https://etherscan.io/tx/",
}


def explorer_tx_url(chain_id: Optional[int], tx_hash: Optional[str]) -> Optional[str]:
    if not chain_id or not tx_hash or chain_id not in EXPLORERS:
        return None
    return EXPLORERS[chain_id] + tx_hash


class ChainClient:
    def __init__(self, w3: Web3, address: str, abi: list, private_key: Optional[str] = None):
        self.w3 = w3
        self.address = Web3.to_checksum_address(address)
        self.contract = w3.eth.contract(address=self.address, abi=abi)
        self.chain_id = int(w3.eth.chain_id)
        if private_key:
            from eth_account import Account
            self._account = Account.from_key(private_key)
            self.sender = self._account.address
            self.mode = "signed"
        else:
            self._account = None
            self.sender = w3.eth.accounts[0]
            self.mode = "unlocked"

    def anchor_root(self, batch_id: int, merkle_root_hex: str) -> Dict[str, Any]:
        fn = self.contract.functions.anchorRoot(batch_id, bytes.fromhex(merkle_root_hex))
        if self._account is not None:
            tx = fn.build_transaction({
                "from": self.sender,
                "nonce": self.w3.eth.get_transaction_count(self.sender, "pending"),
                "chainId": self.chain_id,
            })
            signed = self._account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        else:
            tx_hash = fn.transact({"from": self.sender})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        if receipt["status"] != 1:
            raise RuntimeError("anchoring transaction reverted")
        return {"tx_hash": Web3.to_hex(tx_hash), "block_number": int(receipt["blockNumber"]),
                "chain_id": self.chain_id}

    def get_root(self, batch_id: int) -> Optional[str]:
        """On-chain root as 64 hex chars, or None if the batch was never anchored."""
        root, _timestamp = self.contract.functions.getRoot(batch_id).call()
        root_hex = Web3.to_hex(root)[2:]
        return None if root_hex == ZERO_ROOT else root_hex

    def last_batch_id(self) -> int:
        return int(self.contract.functions.lastBatchId().call())


class SimulatedChain:
    """
    DEMO ONLY - a stand-in for the blockchain that keeps roots in a small table of the
    same SQLite file. Like the real contract it is write-once, and the demo-tamper
    endpoint never touches it, so tampering is still detected. It is NOT a real
    blockchain: anyone with access to the database file could edit it.
    """

    mode = "simulated"
    address = "simulated-ledger"
    chain_id = 0

    def __init__(self, db_path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS sim_chain ("
                         "batch_id INTEGER PRIMARY KEY, root TEXT NOT NULL, block INTEGER NOT NULL)")
        self._db.commit()

    def anchor_root(self, batch_id: int, merkle_root_hex: str) -> Dict[str, Any]:
        with self._lock:
            if self._db.execute("SELECT 1 FROM sim_chain WHERE batch_id=?", (batch_id,)).fetchone():
                raise RuntimeError("batch already anchored")
            block = self._db.execute("SELECT COALESCE(MAX(block),0)+1 FROM sim_chain").fetchone()[0]
            self._db.execute("INSERT INTO sim_chain VALUES (?,?,?)", (batch_id, merkle_root_hex, block))
            self._db.commit()
        tx = "0x" + hashlib.sha256(f"{batch_id}:{merkle_root_hex}:{block}".encode()).hexdigest()
        return {"tx_hash": tx, "block_number": block, "chain_id": self.chain_id}

    def get_root(self, batch_id: int) -> Optional[str]:
        with self._lock:
            row = self._db.execute("SELECT root FROM sim_chain WHERE batch_id=?", (batch_id,)).fetchone()
        return row[0] if row else None

    def last_batch_id(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COALESCE(MAX(batch_id),0) FROM sim_chain").fetchone()[0])


_SIMULATED: Dict[str, SimulatedChain] = {}
_SIM_LOCK = threading.Lock()


def get_simulated(db_path: str) -> SimulatedChain:
    with _SIM_LOCK:
        if db_path not in _SIMULATED:
            _SIMULATED[db_path] = SimulatedChain(db_path)
        return _SIMULATED[db_path]


def try_connect(settings: Settings) -> Tuple[Optional[ChainClient], Optional[str]]:
    if not settings.chain_enabled:
        return None, "blockchain disabled by configuration (SOC_CHAIN_ENABLED=false)"
    if settings.chain_mode == "simulated":
        try:
            return get_simulated(settings.db_path), None
        except Exception as exc:
            return None, f"simulated ledger error: {exc}"
    try:
        if not settings.deployment_file.exists():
            return None, "contract not deployed yet (run the deploy script)"
        if not settings.artifact_file.exists():
            return None, "contract not compiled yet (run: npx hardhat compile)"
        w3 = Web3(Web3.HTTPProvider(settings.chain_rpc_url, request_kwargs={"timeout": 5}))
        if not w3.is_connected():
            return None, f"cannot reach the blockchain node at {settings.chain_rpc_url}"
        deployment = json.loads(settings.deployment_file.read_text())
        address = Web3.to_checksum_address(deployment["address"])
        expected_chain = deployment.get("chainId")
        if expected_chain is not None and int(expected_chain) != int(w3.eth.chain_id):
            return None, (f"node is on chain {w3.eth.chain_id} but the contract was deployed on "
                          f"chain {expected_chain}")
        if w3.eth.get_code(address) in (b"", b"\x00"):
            return None, "no contract at the saved address (chain restarted? run the deploy script again)"
        abi = json.loads(settings.artifact_file.read_text())["abi"]
        return ChainClient(w3, address, abi, settings.chain_private_key), None
    except Exception as exc:  # never let a chain problem crash the API
        return None, f"blockchain error: {exc}"
