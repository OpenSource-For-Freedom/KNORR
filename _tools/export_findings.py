import sys
sys.path.insert(0, r'F:\dev\knorr\src')
from knorr.db import Database
from knorr import config
import json
from pathlib import Path

db = Database.open(config.DB_PATH)
rows = db.conn.execute("""
    SELECT image, status, tier, score, pull_count, attribution,
           detection_method, digest, signals, reasoning
    FROM image_findings
    ORDER BY
        CASE status
            WHEN 'confirmed' THEN 0
            WHEN 'screened'  THEN 1
            WHEN 'candidate' THEN 2
            WHEN 'rejected'  THEN 3
            ELSE 4
        END,
        score DESC, image
""").fetchall()

out = Path(r'F:\dev\knorr\artifacts\discovered_images.txt')
out.parent.mkdir(parents=True, exist_ok=True)

lines = []
lines.append("KNORR — Discovered Container Image Registry")
lines.append(f"Generated: 2026-07-07  |  Total records: {len(rows)}")
lines.append("=" * 100)

current_status = None
for r in rows:
    if r['status'] != current_status:
        current_status = r['status']
        count = sum(1 for x in rows if x['status'] == current_status)
        lines.append("")
        lines.append(f"{'─' * 100}")
        lines.append(f"  {current_status.upper()} ({count})")
        lines.append(f"{'─' * 100}")

    pulls  = f"{r['pull_count']:,}" if r['pull_count'] else "unknown"
    tier   = r['tier'] or "—"
    attr   = f"  [{r['attribution']}]" if r['attribution'] else ""
    digest = (r['digest'] or "")[:19]
    sigs   = ", ".join(json.loads(r['signals'] or "[]"))
    reason = (r['reasoning'] or "")[:120]

    lines.append("")
    lines.append(f"  IMAGE   : {r['image']}{attr}")
    lines.append(f"  status  : {r['status']}  |  tier: {tier}  |  score: {r['score']}  |  pulls: {pulls}")
    lines.append(f"  method  : {r['detection_method']}  |  digest: {digest or '—'}")
    if sigs:
        lines.append(f"  signals : {sigs}")
    if reason:
        lines.append(f"  reason  : {reason}")

lines.append("")
lines.append("=" * 100)
lines.append(f"  SUMMARY")
lines.append("=" * 100)
for status in ('confirmed', 'screened', 'candidate', 'rejected', 'removed'):
    n = sum(1 for r in rows if r['status'] == status)
    if n:
        lines.append(f"  {status:<12} {n}")
lines.append("")

text = "\n".join(lines)
out.write_text(text, encoding="utf-8")
print(f"Written {len(rows)} records -> {out}")
db.close()
