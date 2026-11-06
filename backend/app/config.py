"""
Central settings. Everything comes from environment variables, so no secret
(API key, private key) ever lives in the source code or in git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_DIR.parent


def _flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    db_path: str
    api_key: Optional[str]            # if set, write endpoints need header X-API-Key
    demo_mode: bool                   # enables the /demo/tamper endpoints
    max_pending: int                  # cap on un-sealed logs (memory/DoS guard)
    chain_enabled: bool
    chain_mode: str                   # "real" (web3 node) or "simulated" (built-in demo ledger)
    chain_rpc_url: str
    chain_private_key: Optional[str]  # set for signed transactions (testnets)
    deployment_file: Path
    artifact_file: Path
    brute_force_threshold: int
    brute_force_window_minutes: int
    off_hours_start: int              # UTC hour; logins from this hour...
    off_hours_end: int                # ...until this hour count as off-hours

    @classmethod
    def from_env(cls) -> "Settings":
        default_artifact = (
            PROJECT_ROOT / "contracts" / "artifacts" / "contracts" / "LogAnchor.sol" / "LogAnchor.json"
        )
        return cls(
            db_path=os.getenv("SOC_DB_PATH", str(BACKEND_DIR / "data" / "soc.db")),
            api_key=os.getenv("SOC_API_KEY") or None,
            demo_mode=_flag("SOC_DEMO_MODE", False),
            max_pending=_int("SOC_MAX_PENDING", 10_000),
            chain_enabled=_flag("SOC_CHAIN_ENABLED", True),
            chain_mode=os.getenv("SOC_CHAIN_MODE", "real").strip().lower(),
            chain_rpc_url=os.getenv("CHAIN_RPC_URL", "http://127.0.0.1:8545"),
            chain_private_key=os.getenv("CHAIN_PRIVATE_KEY") or None,
            deployment_file=Path(
                os.getenv("SOC_DEPLOYMENT_FILE", str(PROJECT_ROOT / "contracts" / "deployment.json"))
            ),
            artifact_file=Path(os.getenv("SOC_ARTIFACT_FILE", str(default_artifact))),
            brute_force_threshold=_int("SOC_BRUTE_FORCE_THRESHOLD", 3),
            brute_force_window_minutes=_int("SOC_BRUTE_FORCE_WINDOW_MIN", 5),
            off_hours_start=_int("SOC_OFF_HOURS_START", 22),
            off_hours_end=_int("SOC_OFF_HOURS_END", 6),
        )
