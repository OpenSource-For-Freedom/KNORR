"""Run artifacts: findings CSV + summary JSON (PRD section 14.1, full transparency).

Every image the run touched is exported with its status and evidence, so a
reviewer can audit confirmations and recognized rejections alike.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from . import config


def write_findings_csv(db, run_id: str) -> Path:
    config.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    path = config.ARTIFACTS_DIR / f"{run_id}_findings.csv"
    rows = db.all_findings()
    cols = ["image", "reference", "digest", "detection_method", "status", "score",
            "tier", "publisher", "pull_count", "pool", "wallet", "miner", "likely_tool",
            "attribution", "signals", "reasoning"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(cols)
        for r in rows:
            signals = ", ".join(json.loads(r["signals"] or "[]"))
            evidence = json.loads(r["evidence"] or "{}")
            iocs = evidence.get("iocs") or {}
            writer.writerow([
                r["image"], r["reference"], (r["digest"] or "")[:19], r["detection_method"],
                r["status"], r["score"], r["tier"] or "", r["publisher"] or "",
                r["pull_count"] or "", "; ".join(iocs.get("pools") or []),
                "; ".join(iocs.get("wallets") or []), "; ".join(iocs.get("miners") or []),
                "yes" if evidence.get("likely_tool") else "", r["attribution"] or "",
                signals, (r["reasoning"] or "")[:300],
            ])
    return path


def write_summary(run_id: str, summary: dict) -> Path:
    config.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    path = config.ARTIFACTS_DIR / f"{run_id}_summary.json"
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return path
