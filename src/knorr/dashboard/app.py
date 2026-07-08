"""Live threat-telemetry dashboard for the container registry.

Read-only over the SQLite store, served by the standard library's
``http.server`` so Knörr keeps its tiny dependency footprint (no FastAPI /
uvicorn). Each request opens a short-lived DB so the page always reflects the
latest committed hunt. The HTML/CSS/JS is a single self-contained page styled as
an enterprise security console (sharp edges, restrained palette, dense tables).

    knorr serve            # http://127.0.0.1:8789
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from ..config import DB_PATH, PROJECT_ROOT
from ..db import Database

log = logging.getLogger(__name__)

# The README hero image, reused here as a subtle fixed background (a heavy
# overlay keeps it from competing with the dense data panels sitting on top).
_BRAND_IMAGE = PROJECT_ROOT / "docs" / "knorr.png"


# Registries/sources this dashboard knows how to link out to. A bare "ns/repo"
# image (no host prefix) is Docker Hub; anything else is keyed by its host
# prefix. "github.com" findings are Dockerfile-in-git scans, not pullable
# images (see cli.py's _finding_from_dockerfile_hit); their precise link is the
# GitHub blob URL stashed in evidence, checked before this generic fallback.
_REGISTRY_LINKS = {
    "ghcr.io": lambda image: f"https://github.com/{image.split('/', 2)[1]}",
    "github.com": lambda image: f"https://{image.split(':', 1)[0]}",
}


def _registry_of(image: str) -> str:
    for host in _REGISTRY_LINKS:
        if image.startswith(host + "/"):
            return host
    return "docker.io"


def _link_for(image: str, evidence: dict) -> str:
    if evidence.get("dockerfile_url"):
        return evidence["dockerfile_url"]
    for host, make in _REGISTRY_LINKS.items():
        if image.startswith(host + "/"):
            return make(image)
    return f"https://hub.docker.com/r/{image}"


def _rows(db: Database, status: str | None = None) -> list[dict]:
    if status:
        cur = db.conn.execute(
            "SELECT * FROM image_findings WHERE status = ? ORDER BY score DESC, image", (status,))
    else:
        cur = db.conn.execute("SELECT * FROM image_findings ORDER BY score DESC, image")
    out = []
    for r in cur:
        evidence = json.loads(r["evidence"] or "{}")
        out.append({
            "image": r["image"], "reference": r["reference"], "digest": r["digest"],
            "detection_method": r["detection_method"], "status": r["status"],
            "score": r["score"], "tier": r["tier"], "publisher": r["publisher"],
            "pull_count": r["pull_count"], "attribution": r["attribution"],
            "signals": json.loads(r["signals"] or "[]"),
            "confirming": json.loads(r["confirming"] or "[]"),
            "reasoning": r["reasoning"], "osm_severity": r["osm_severity"],
            "registry": _registry_of(r["image"]), "link": _link_for(r["image"], evidence),
            "likely_tool": bool(evidence.get("likely_tool")),
        })
    return out


def _summary(db: Database) -> dict:
    rows = _rows(db)
    confirmed = [r for r in rows if r["status"] == "confirmed"]
    removed = [r for r in rows if r["status"] == "removed"]
    screened = [r for r in rows if r["status"] == "screened"]
    cat_counter: Counter = Counter()
    method_counter: Counter = Counter()
    registry_counter: Counter = Counter()
    for r in confirmed:
        method_counter[r["detection_method"]] += 1
        registry_counter[r["registry"]] += 1
        for sig in r["signals"]:
            cat_counter[sig.split("/", 1)[0]] += 1
    novel = [r for r in confirmed
             if r["detection_method"] in ("hub_search", "typosquat", "publisher_pivot",
                                          "dockerfile_scan")]
    tools = [r for r in confirmed if r["likely_tool"]]
    runs = list(db.conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1"))
    return {
        "totals": {"confirmed": len(confirmed), "removed": len(removed),
                   "screened": len(screened), "candidates": len(rows), "novel": len(novel),
                   "tools": len(tools)},
        "by_category": cat_counter.most_common(),
        "by_method": method_counter.most_common(),
        "by_registry": registry_counter.most_common(),
        "run": runs[0]["run_id"] if runs else "",
        "counts": json.loads(runs[0]["counts"]) if runs and runs[0]["counts"] else {},
    }


class _Handler(BaseHTTPRequestHandler):
    db_path = DB_PATH

    def log_message(self, *args):
        return

    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj) -> None:
        self._send(json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._send(_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/knorr.png":
            if _BRAND_IMAGE.is_file():
                self._send(_BRAND_IMAGE.read_bytes(), "image/png")
            else:
                self._send(b"", "image/png", 404)
            return
        if path.startswith("/api/"):
            db = Database.open(self.db_path)
            try:
                if path == "/api/summary":
                    self._json(_summary(db))
                elif path == "/api/confirmed":
                    self._json(_rows(db, "confirmed"))
                elif path == "/api/removed":
                    self._json(_rows(db, "removed"))
                elif path == "/api/all":
                    self._json(_rows(db))
                else:
                    self._json({"error": "unknown endpoint"})
            finally:
                db.close()
            return
        self._send(b"not found", "text/plain", 404)


def serve(db_path=DB_PATH, host: str = "127.0.0.1", port: int = 8789) -> None:
    _Handler.db_path = db_path
    httpd = ThreadingHTTPServer((host, port), _Handler)
    log.info("dashboard serving on http://%s:%s", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Knorr - Container Threat Registry</title>
<style>
:root{
  --canvas:#f3f5f8;--canvas-rgb:243,245,248;--surface:#ffffff;--surface-2:#f8fafc;--zebra:#fbfcfe;
  --border:#e2e7ee;--border-2:#ced6e0;--hair:#eef1f5;
  --text:#182430;--text-2:#57667a;--text-3:#8592a4;
  --brand:#1c548f;--brand-2:#e8f0f8;
  --crit:#b3283a;--crit-bg:#fbe9eb;--high:#9a6712;--high-bg:#f7eede;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code",Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root{
  --canvas:#0d1219;--canvas-rgb:13,18,25;--surface:#131a23;--surface-2:#0f161e;--zebra:#141c26;
  --border:#232d3a;--border-2:#303c4b;--hair:#1b232e;
  --text:#d7dee7;--text-2:#94a1b0;--text-3:#66717f;
  --brand:#4f9bd8;--brand-2:#16222f;
  --crit:#e05669;--crit-bg:#2a1519;--high:#d29a44;--high-bg:#241c10;
}}
*{box-sizing:border-box}
body{margin:0;font-family:var(--sans);color:var(--text);
  background-color:var(--canvas);
  background-image:linear-gradient(rgba(var(--canvas-rgb),.94),rgba(var(--canvas-rgb),.94)),
    url('/knorr.png');
  background-size:auto,cover;background-position:center,center top;
  background-attachment:fixed,fixed;background-repeat:no-repeat,no-repeat;
  font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
a:focus-visible{outline:2px solid var(--brand);outline-offset:1px}
.bar{display:flex;align-items:center;gap:14px;height:56px;padding:0 24px;
  background:var(--surface);border-bottom:1px solid var(--border-2)}
.logo{width:26px;height:26px;background:var(--brand);display:flex;align-items:center;justify-content:center}
.brand{font-weight:700;font-size:15px}.divider{width:1px;height:22px;background:var(--border-2)}
.desc{color:var(--text-2);font-size:12px}
.env{margin-left:auto;display:flex;align-items:center;gap:14px;color:var(--text-3);font-size:11px}
.env .badge{border:1px solid var(--border-2);padding:3px 9px;color:var(--text-2);font-family:var(--mono)}
.env .run{text-align:right;line-height:1.35}.env .run b{color:var(--text-2);font-family:var(--mono)}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);background:var(--surface);border-bottom:1px solid var(--border-2)}
@media(max-width:820px){.kpis{grid-template-columns:repeat(3,1fr)}}
.kpi{padding:16px 24px;border-right:1px solid var(--hair)}
.kpi .n{font-size:27px;font-weight:700;color:var(--text)}
.kpi.crit .n{color:var(--crit)}.kpi.brand .n{color:var(--brand)}
.kpi .l{color:var(--text-3);font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;margin-top:4px}
.main{padding:24px;max-width:1320px;margin:0 auto}
.rowg{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:820px){.rowg{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);margin-bottom:16px}
.phead{display:flex;align-items:baseline;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border)}
.phead h2{margin:0;font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-2)}
.phead .meta{color:var(--text-3);font-size:11px;margin-left:auto}
.pbody{padding:14px 16px}
.bar-row{display:flex;align-items:center;gap:12px;margin:7px 0}
.bar-row .nm{width:140px;font-size:12px;text-transform:capitalize;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-row .tr{flex:1;height:8px;background:var(--surface-2);border:1px solid var(--hair)}
.bar-row .fl{height:100%}.bar-row .v{width:28px;text-align:right;font-size:12px;color:var(--text-2);font-family:var(--mono)}
.note{color:var(--text-2);font-size:12px;line-height:1.6}.note b{color:var(--text)}
.tblwrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12.5px;min-width:760px}
thead th{text-align:left;color:var(--text-3);font-weight:600;font-size:10.5px;letter-spacing:.05em;
  text-transform:uppercase;padding:9px 12px;border-bottom:1px solid var(--border-2);background:var(--surface-2);white-space:nowrap}
th.num,td.num{text-align:right}
tbody td{padding:10px 12px;border-bottom:1px solid var(--hair);vertical-align:top}
tbody tr:nth-child(even){background:var(--zebra)}tbody tr:hover{background:var(--brand-2)}
.sev{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;font-weight:700;padding:2px 7px;border:1px solid transparent;white-space:nowrap}
.sev .dot{width:7px;height:7px}
.sev.crit{color:var(--crit);background:var(--crit-bg);border-color:var(--crit)}.sev.crit .dot{background:var(--crit)}
.sev.high{color:var(--high);background:var(--high-bg);border-color:var(--high)}.sev.high .dot{background:var(--high)}
.img a{color:var(--text);font-family:var(--mono);font-size:12px}.img a:hover{color:var(--brand)}
.tag{display:inline-block;font-size:9.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
  color:var(--brand);border:1px solid var(--brand);padding:0 5px;margin-left:6px}
.attr{display:block;color:var(--text-3);font-size:10.5px;margin-top:3px}
.tierlbl{font-family:var(--mono);font-size:11px;color:var(--text-2)}
.threat{text-transform:capitalize}.src{color:var(--text-3);font-family:var(--mono);font-size:11px}
.score{font-family:var(--mono);font-weight:700}
.chip{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 5px;margin:1px 3px 1px 0;
  border:1px solid var(--border);color:var(--text-2);background:var(--surface-2);white-space:nowrap}
.more{color:var(--text-3);font-size:10.5px}
.removed{padding:12px 16px;color:var(--text-2);font-size:12px;line-height:2;font-family:var(--mono)}
.removed span.r{text-decoration:line-through;text-decoration-color:var(--crit);color:var(--text-3)}
.foot{max-width:1320px;margin:0 auto;padding:16px 24px;color:var(--text-3);font-size:11px;border-top:1px solid var(--border)}
.foot b{color:var(--text-2)}
</style></head>
<body>
<div class="bar">
  <span class="logo"><svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
    <rect x="1" y="3" width="14" height="3" fill="#fff" opacity=".9"/>
    <rect x="1" y="6.5" width="14" height="3" fill="#fff" opacity=".65"/>
    <rect x="1" y="10" width="14" height="3" fill="#fff" opacity=".4"/></svg></span>
  <span class="brand">Kn&ouml;rr</span><span class="divider"></span>
  <span class="desc">Container Threat Registry</span>
  <div class="env"><span class="badge" id="registries">registries: Docker Hub</span>
    <span class="run" id="run"></span></div>
</div>
<div class="kpis" id="kpis"></div>
<div class="main">
  <div class="rowg">
    <div class="panel" style="margin:0"><div class="phead"><h2>Threat facets detected</h2>
      <span class="meta">signals across confirmed images</span></div><div class="pbody" id="cats"></div></div>
    <div class="panel" style="margin:0"><div class="phead"><h2>Discovery source</h2>
      <span class="meta">how each finding surfaced</span></div><div class="pbody" id="meths"></div></div>
  </div>
  <div class="panel"><div class="phead"><h2>Confirmed detections</h2>
    <span class="meta" id="cmeta"></span></div>
    <div class="tblwrap"><table><thead><tr><th>Severity</th><th>Image</th><th>Registry</th>
      <th>Rule tier</th><th class="num">Score</th><th>Threat</th><th>Source</th>
      <th>Signals</th></tr></thead>
      <tbody id="rows"></tbody></table></div></div>
  <div class="panel"><div class="phead"><h2>Removed / taken down</h2>
    <span class="meta" id="rmeta"></span></div><div class="removed" id="removed"></div></div>
</div>
<div class="foot">Kn&ouml;rr &middot; container sibling to <b>git_warden</b> (repositories) and
  <b>git_paca</b> (packages) &middot; confirmed findings submit to OpenSourceMalware as
  <b>report_type: container</b>.</div>
<script>
const COL={cryptomining:"#b5731a",reverse_shell:"#b3283a",c2:"#a02947",exfiltration:"#a85a3c",
  credential_access:"#9a6712",obfuscation:"#5a5296",persistence:"#2a6386",rootkit:"#a23a63",
  defense_evasion:"#6b7683",container_escape:"#9a5a2a",malware_family:"#8f1f34",download_exec:"#8a7d1f",
  recon:"#6b7683",lateral_movement:"#3c6f8c"};
const NOVEL=new Set(["hub_search","typosquat","publisher_pivot","dockerfile_scan"]);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function bar(nm,v,mx,c){const p=mx?Math.max(3,Math.round(v/mx*100)):0;
  return `<div class="bar-row"><div class="nm">${esc(nm.replace(/_/g," "))}</div>
   <div class="tr"><div class="fl" style="width:${p}%;background:${c}"></div></div><div class="v">${v}</div></div>`}
const REGISTRY_LABEL={"docker.io":"Docker Hub","ghcr.io":"GHCR","github.com":"GitHub (Dockerfile)"};
async function load(){
  const s=await (await fetch('/api/summary')).json(); const t=s.totals;
  document.getElementById('run').innerHTML=`run <b>${esc(s.run||'-')}</b><br>static analysis &middot; images never executed`;
  document.getElementById('registries').textContent='registries: '+
    (s.by_registry.length?s.by_registry.map(([r,n])=>`${REGISTRY_LABEL[r]||r} (${n})`).join(', ')
      :'Docker Hub');
  document.getElementById('kpis').innerHTML=[["crit","Confirmed",t.confirmed],["brand","Novel / beyond OSM",t.novel],
    ["","Promoted to Tier 2",t.screened],["","Removed / delisted",t.removed],
    ["","Candidates screened",t.candidates],["","Tools flagged",t.tools]]
    .map(([c,l,n])=>`<div class="kpi ${c}"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`).join("");
  const cmx=Math.max(1,...s.by_category.map(x=>x[1]));
  document.getElementById('cats').innerHTML=s.by_category.map(([c,n])=>bar(c,n,cmx,COL[c]||"var(--brand)")).join("")||'<span class="note">no data</span>';
  const mmx=Math.max(1,...s.by_method.map(x=>x[1]));
  document.getElementById('meths').innerHTML=(s.by_method.map(([m,n])=>bar(m,n,mmx,"var(--brand)")).join(""))+
    `<p class="note" style="margin:14px 0 0">Tier 1 reads the image config only (no layer pull); Tier 2 pulls and unpacks layers. A miner is confirmed only when a payout wallet or pool is hardcoded, so a legitimate miner tool is <b>not</b> flagged.</p>`;
  const rows=await (await fetch('/api/confirmed')).json();
  document.getElementById('cmeta').textContent=`${rows.length} images · confirmed by static evidence`;
  document.getElementById('rows').innerHTML=rows.map(x=>{
    const A=(x.tier||"").startsWith("A");
    const sev=A?`<span class="sev crit"><span class="dot"></span>CRITICAL</span>`:`<span class="sev high"><span class="dot"></span>HIGH</span>`;
    const nv=NOVEL.has(x.detection_method)?`<span class="tag">novel</span>`:"";
    const tool=x.likely_tool?`<span class="tag" style="color:var(--text-2);border-color:var(--border-2)">tool</span>`:"";
    const sig=(x.signals||[]).slice(0,6).map(g=>`<span class="chip">${esc(g)}</span>`).join("")+((x.signals||[]).length>6?` <span class="more">+${x.signals.length-6}</span>`:"");
    return `<tr><td>${sev}</td>
      <td class="img"><a href="${esc(x.link)}" target="_blank" rel="noopener">${esc(x.image)}</a>${nv}${tool}
      ${x.attribution?`<span class="attr">campaign: ${esc(x.attribution)}</span>`:""}</td>
      <td class="src">${esc(REGISTRY_LABEL[x.registry]||x.registry)}</td>
      <td class="tierlbl">${esc(x.tier||"")}</td><td class="num score">${x.score}</td>
      <td class="threat">${esc((x.tier||"").split(":")[1]||"")}</td>
      <td class="src">${esc(x.detection_method)}</td><td>${sig}</td></tr>`}).join("")
    ||'<tr><td colspan="8" class="note">no confirmed findings yet - run a hunt</td></tr>';
  const rem=await (await fetch('/api/removed')).json();
  document.getElementById('rmeta').textContent=`${rem.length} OSM-flagged images returned 401/404 at pull`;
  document.getElementById('removed').innerHTML=rem.length?rem.map(x=>`<span class="r">${esc(x.image)}</span>`).join("   "):"none";
}
load(); setInterval(load,15000);
</script>
</body></html>"""
