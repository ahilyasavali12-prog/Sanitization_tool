#!/usr/bin/env python3
"""FastAPI sidecar: models load ONCE, hooks just curl this.

Run:  python3 scripts/sidecar.py   (or ./start_sidecar.sh)
Listens on http://127.0.0.1:8100 — localhost only, never expose it.
"""
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# make core/ importable regardless of where sidecar is launched from
CORE = Path(__file__).resolve().parent.parent / "core"
sys.path.insert(0, str(CORE))

from agentic_firewall import AgenticFirewallPlugin  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

fw = AgenticFirewallPlugin(
    db_path=str(DATA_DIR / "firewall_vectors.db"),
    audit_log=str(DATA_DIR / "firewall_audit.jsonl"),
)

app = FastAPI(title="Agentic Firewall Sidecar")


class ScanIn(BaseModel):
    text: str


@app.post("/scan")
def scan(body: ScanIn):
    """Main endpoint the Claude Code hook calls. ~50-200ms per scan."""
    if not body.text.strip():
        return {"allowed": True, "reason": "empty"}
    try:
        return fw.intercept(body.text)
    except Exception as e:
        # fail open: never break the user's Claude session over a firewall bug
        return {"allowed": True, "reason": f"firewall error (fail-open): {e}"}


@app.get("/health")
def health():
    return {"status": "ok", **fw.stats()}


@app.post("/learn")
def learn(body: ScanIn):
    if not body.text.strip():
        raise HTTPException(400, "empty text")
    fw._add_known_attack(body.text)
    return {"status": "added", "known_attacks": len(fw._ids)}


@app.get("/stats")
def stats():
    return fw.stats()


@app.get("/audit")
def audit(n: int = 20):
    return fw.recent_audit(n)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8100, log_level="warning")