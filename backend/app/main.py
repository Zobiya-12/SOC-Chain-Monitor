"""
SOC Chain Monitor API.

create_app() builds the app from a Settings object so tests can inject a
temporary database and a fake blockchain.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import detection
from .chain import explorer_tx_url, try_connect
from .config import Settings
from .merkle import MerkleTree, hash_leaf, verify_proof
from .models import (AlertList, AlertOut, BatchSummary, LogEntry, VerifyRequest, VerifyResponse)
from .security import make_auth_dependency
from .storage import PendingLimitError, Store

STATIC_DIR = Path(__file__).parent / "static"
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

Connector = Callable[[Settings], Tuple[Optional[Any], Optional[str]]]


def create_app(settings: Optional[Settings] = None, chain_connector: Optional[Connector] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    connect = chain_connector or try_connect
    store = Store(settings.db_path, settings.max_pending)
    det_cfg = detection.DetectionConfig.from_settings(settings)
    auth = make_auth_dependency(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        store.close()

    app = FastAPI(
        title="SOC Chain Monitor",
        description="SOC log monitoring with detection rules and blockchain-anchored tamper evidence",
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ------------------------------------------------------------ helpers
    def onchain_root(batch_id: int):
        """Returns (root_or_None, error_or_None, chain_reachable)."""
        client, reason = connect(settings)
        if client is None:
            return None, reason, False
        try:
            return client.get_root(batch_id), None, True
        except Exception as exc:
            return None, f"blockchain call failed: {exc}", False

    def summary(record: Dict[str, Any]) -> BatchSummary:
        return BatchSummary(
            batch_id=record["batch_id"], log_count=record["log_count"],
            merkle_root=record["merkle_root"], created_at=record["created_at"],
            anchored=record["anchored"], tx_hash=record.get("tx_hash"),
            block_number=record.get("block_number"), anchor_error=record.get("anchor_error"),
            explorer_url=explorer_tx_url(record.get("chain_id"), record.get("tx_hash")),
            alerts_raised=store.alert_count(record["batch_id"]),
        )

    def get_batch_or_404(batch_id: int) -> Dict[str, Any]:
        try:
            return store.get_batch(batch_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc.args[0]))

    def run_detection(record: Dict[str, Any]) -> int:
        found = [a.as_dict() for a in detection.evaluate(record["logs"], det_cfg)]
        store.replace_alerts(record["batch_id"], found)
        return len(found)

    def try_anchor(record: Dict[str, Any]) -> None:
        client, reason = connect(settings)
        if client is None:
            store.update_anchor(record["batch_id"], False, error=f"not anchored: {reason}")
            return
        try:
            result = client.anchor_root(record["batch_id"], record["merkle_root"])
            store.update_anchor(record["batch_id"], True, result["tx_hash"], result["block_number"],
                                result["chain_id"], None)
        except Exception as exc:
            store.update_anchor(record["batch_id"], False, error=f"anchoring failed: {exc}")

    # --------------------------------------------------------------- pages
    def page(name: str) -> FileResponse:
        return FileResponse(
            STATIC_DIR / name,
            headers={"Content-Security-Policy": DASHBOARD_CSP, "X-Content-Type-Options": "nosniff",
                     "Referrer-Policy": "no-referrer"},
        )

    @app.get("/", include_in_schema=False)
    def landing():
        return page("landing.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard():
        return page("dashboard.html")

    @app.get("/health")
    def health():
        client, reason = connect(settings)
        chain: Dict[str, Any] = {"connected": client is not None, "reason": reason}
        if client is not None:
            chain.update(address=client.address, chain_id=client.chain_id, mode=client.mode)
        return {"status": "ok", "auth_enabled": bool(settings.api_key), "demo_mode": settings.demo_mode,
                "chain": chain, "stats": store.stats()}

    # ---------------------------------------------------------------- logs
    @app.post("/logs/ingest", dependencies=[Depends(auth)])
    def ingest_log(log: LogEntry):
        try:
            index = store.add_log(log.model_dump(mode="json"))
        except PendingLimitError as exc:
            raise HTTPException(status_code=429, detail=str(exc))
        return {"status": "queued", "pending_index": index, "pending_count": store.pending_count()}

    @app.post("/logs/seal-batch", response_model=BatchSummary, dependencies=[Depends(auth)])
    def seal_batch():
        """Seal pending logs into a batch, run detection rules, and anchor the root on-chain."""
        min_id = 1
        client, _reason = connect(settings)
        if client is not None:
            try:  # never reuse a batch id that is already taken on-chain
                min_id = client.last_batch_id() + 1
            except Exception:
                pass
        try:
            record = store.seal_batch(min_batch_id=min_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        try_anchor(record)
        run_detection(record)
        return summary(store.get_batch(record["batch_id"]))

    @app.get("/logs/batches")
    def list_batches():
        return [summary(r).model_dump() for r in store.list_batches()]

    @app.get("/logs/batch/{batch_id}")
    def get_batch(batch_id: int):
        record = get_batch_or_404(batch_id)
        return {**summary(record).model_dump(), "logs": record["logs"]}

    @app.get("/logs/batch/{batch_id}/proof/{log_index}")
    def get_proof(batch_id: int, log_index: int):
        record = get_batch_or_404(batch_id)
        tree = MerkleTree(record["logs"])
        try:
            proof = tree.get_proof(log_index)
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"batch_id": batch_id, "log_index": log_index, "leaf_hash": tree.leaves[log_index],
                "root_from_current_logs": tree.root, "proof": proof}

    # -------------------------------------------------------- verification
    @app.post("/logs/verify", response_model=VerifyResponse)
    def verify_log(req: VerifyRequest):
        """
        Checks one log against the ON-CHAIN root. It FAILS CLOSED: if the chain
        cannot be reached the answer is 'unverifiable' (valid=false), never 'valid'.
        Both the submitted log AND the stored copy must match the sealed record.
        """
        record = get_batch_or_404(req.batch_id)
        tree = MerkleTree(record["logs"])
        try:
            proof = tree.get_proof(req.log_index)
            submitted_leaf = hash_leaf(req.log_entry)
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=f"log_entry cannot be hashed: {exc}")
        stored_leaf = tree.leaves[req.log_index]

        trusted, error, _reachable = onchain_root(req.batch_id)
        if trusted is None:
            why = error or "the batch was never anchored on-chain"
            return VerifyResponse(valid=False, status="unverifiable",
                                  message=f"Cannot verify: no trusted on-chain root ({why}).",
                                  submitted_leaf_hash=submitted_leaf, stored_leaf_hash=stored_leaf)

        submitted_ok = verify_proof(submitted_leaf, proof, trusted)
        stored_ok = verify_proof(stored_leaf, proof, trusted)
        if submitted_ok and stored_ok:
            status, message = "valid", "Log matches the on-chain record and the stored copy is intact."
        elif submitted_ok and not stored_ok:
            status, message = "invalid", ("The stored copy of this log (or another log in the batch) was "
                                          "modified after sealing; the log you submitted matches the on-chain root.")
        elif stored_ok and not submitted_ok:
            status, message = "invalid", "The log you submitted does not match what was sealed."
        else:
            status, message = "invalid", ("Neither the submitted nor the stored log matches the sealed record "
                                          "(or another log in this batch was modified - run the integrity check).")
        return VerifyResponse(valid=status == "valid", status=status, message=message, expected_root=trusted,
                              submitted_leaf_hash=submitted_leaf, stored_leaf_hash=stored_leaf,
                              submitted_matches_seal=submitted_ok, stored_matches_seal=stored_ok)

    @app.get("/logs/batch/{batch_id}/integrity")
    def check_integrity(batch_id: int):
        """
        Rebuilds the root from the logs as stored right now and compares it with the
        on-chain root. A TAMPERED result also raises a LOG_TAMPERING alert (once per batch).
        Verdicts: INTACT | TAMPERED | UNVERIFIABLE | UNANCHORED
        """
        record = get_batch_or_404(batch_id)
        current = MerkleTree(record["logs"]).root
        sealed_local = record["merkle_root"]
        chain_root, error, reachable = onchain_root(batch_id)

        local_rewritten = bool(chain_root) and sealed_local != chain_root
        if chain_root is not None:
            verdict = "INTACT" if current == chain_root else "TAMPERED"
            explanation = ("Stored logs hash to the root anchored on-chain." if verdict == "INTACT" else
                           "Stored logs no longer match the on-chain root."
                           + (" The locally stored root was ALSO changed to hide the edit." if local_rewritten else ""))
        elif not reachable:
            verdict, explanation = "UNVERIFIABLE", f"No trusted on-chain root available ({error}). Treat as unproven."
        elif record["anchored"]:
            verdict, explanation = "UNVERIFIABLE", ("The chain has no root for a batch recorded as anchored "
                                                    "(chain reset or wrong contract?).")
        else:
            verdict, explanation = "UNANCHORED", ("This batch was never anchored on-chain, so its integrity "
                                                  f"cannot be proven. Try POST /logs/batch/{batch_id}/anchor.")

        if verdict == "TAMPERED":
            store.add_alert_once({"rule": "LOG_TAMPERING", "severity": "CRITICAL", "batch_id": batch_id,
                                  "message": f"Batch {batch_id}: stored logs do not match the on-chain root",
                                  "details": {"local_root_rewritten": local_rewritten}})
        return {
            "batch_id": batch_id, "verdict": verdict, "explanation": explanation,
            "root_recomputed_from_current_logs": current, "root_sealed_locally": sealed_local,
            "root_on_chain": chain_root, "matches_onchain_root": None if chain_root is None else current == chain_root,
            "matches_local_root": current == sealed_local, "local_root_rewritten": local_rewritten,
            "chain_error": error, "anchored_at_seal": record["anchored"],
        }

    @app.post("/logs/batch/{batch_id}/anchor", response_model=BatchSummary, dependencies=[Depends(auth)])
    def anchor_batch(batch_id: int):
        """Retry anchoring a batch whose first attempt failed (e.g. the chain was down)."""
        record = get_batch_or_404(batch_id)
        client, reason = connect(settings)
        if client is None:
            raise HTTPException(status_code=503, detail=f"blockchain unavailable: {reason}")
        existing = client.get_root(batch_id)
        if existing is not None:
            if existing != record["merkle_root"]:
                raise HTTPException(status_code=409, detail="the on-chain root differs from the locally stored root")
            store.update_anchor(batch_id, True, record.get("tx_hash"), record.get("block_number"),
                                record.get("chain_id") or client.chain_id, None)
            return summary(store.get_batch(batch_id))
        if MerkleTree(record["logs"]).root != record["merkle_root"]:
            raise HTTPException(status_code=409, detail="stored logs changed since sealing; refusing to anchor modified data")
        try_anchor(record)
        return summary(store.get_batch(batch_id))

    # ------------------------------------------------------------- alerts
    @app.post("/logs/batch/{batch_id}/detect", dependencies=[Depends(auth)])
    def redetect(batch_id: int):
        record = get_batch_or_404(batch_id)
        return {"batch_id": batch_id, "alerts_found": run_detection(record)}

    @app.get("/alerts", response_model=AlertList)
    def alerts(severity: Optional[str] = None, batch_id: Optional[int] = None, limit: int = 200):
        found = store.list_alerts(severity, batch_id, max(1, min(limit, 1000)))
        return AlertList(count=len(found), alerts=[AlertOut(**a) for a in found])

    @app.get("/alerts/summary")
    def alerts_summary():
        return store.alert_summary()

    # ---------------------------------------------------------- demo mode
    if settings.demo_mode:
        @app.post("/demo/tamper/{batch_id}/{log_index}", dependencies=[Depends(auth)])
        def demo_tamper(batch_id: int, log_index: int, new_detail: str, rewrite_local_root: bool = False):
            """DEMO ONLY (SOC_DEMO_MODE=1): simulate an attacker editing a stored log."""
            try:
                store.tamper(batch_id, log_index, new_detail[:2048], rewrite_local_root)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc.args[0]))
            except IndexError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            return {"status": "tampered", "batch_id": batch_id, "log_index": log_index,
                    "rewrote_local_root": rewrite_local_root}

    return app


app = create_app()
