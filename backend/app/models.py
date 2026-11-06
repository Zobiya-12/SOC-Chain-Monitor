import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_VERIFY_BYTES = 16_384


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LogEntry(BaseModel):
    """One security event. Field sizes are capped so one request cannot exhaust memory."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=_utc_now)
    source: str = Field(min_length=1, max_length=256)       # e.g. "aws-cloudtrail"
    event_type: str = Field(min_length=1, max_length=256)   # e.g. "ConsoleLogin"
    actor: str = Field(min_length=1, max_length=256)        # user / role / IP
    detail: Optional[str] = Field(default=None, max_length=2048)


class BatchSummary(BaseModel):
    batch_id: int
    log_count: int
    merkle_root: str
    created_at: str
    anchored: bool = False
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    anchor_error: Optional[str] = None
    explorer_url: Optional[str] = None
    alerts_raised: int = 0


class VerifyRequest(BaseModel):
    batch_id: int = Field(ge=1)
    log_index: int = Field(ge=0)
    log_entry: Dict[str, Any]

    @field_validator("log_entry")
    @classmethod
    def _limit_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if len(json.dumps(value, default=str)) > MAX_VERIFY_BYTES:
            raise ValueError(f"log_entry larger than {MAX_VERIFY_BYTES} bytes")
        return value


class VerifyResponse(BaseModel):
    valid: bool                                   # True ONLY when status == "valid"
    status: Literal["valid", "invalid", "unverifiable"]
    message: str
    root_source: str = "onchain"
    expected_root: Optional[str] = None
    submitted_leaf_hash: Optional[str] = None
    stored_leaf_hash: Optional[str] = None
    submitted_matches_seal: Optional[bool] = None
    stored_matches_seal: Optional[bool] = None


class AlertOut(BaseModel):
    id: int
    rule: str
    severity: str
    message: str
    batch_id: Optional[int] = None
    log_index: Optional[int] = None
    created_at: str
    details: Dict[str, Any] = {}


class AlertList(BaseModel):
    count: int
    alerts: List[AlertOut]
