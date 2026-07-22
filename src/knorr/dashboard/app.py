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
# images (see scanning/dockerfile.py's finding_from_hit); their precise link
# is the GitHub blob URL stashed in evidence, checked before this fallback.
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


def _telemetry(db: Database, limit: int = 60) -> list[dict]:
    """Chronological run history for the telemetry graphs: one point per
    completed hunt round, its search yield (candidates screened), and the
    registry's confirmed count at that point in time. Confirmed count is NOT
    purely monotonic: it dips when a precision fix lands and false positives
    get rejected, not just grows as new images are found -- that trajectory
    is exactly what the graph is for."""
    rows = list(db.conn.execute(
        "SELECT run_id, started_at, counts FROM runs "
        "WHERE status='completed' AND counts IS NOT NULL "
        "ORDER BY started_at DESC LIMIT ?", (limit,)))
    out = []
    for r in reversed(rows):  # chronological, oldest first
        counts = json.loads(r["counts"] or "{}")
        out.append({
            "run_id": r["run_id"], "started_at": r["started_at"],
            "candidates": counts.get("candidates", 0),
            "confirmed_total": counts.get("confirmed_total", 0),
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
    publisher_counter: Counter = Counter()
    severity_counter: Counter = Counter()
    for r in confirmed:
        method_counter[r["detection_method"]] += 1
        registry_counter[r["registry"]] += 1
        if r["publisher"]:
            publisher_counter[r["publisher"]] += 1
        severity_counter["critical" if (r["tier"] or "").startswith("A") else "high"] += 1
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
        "by_publisher": publisher_counter.most_common(10),
        "by_severity": severity_counter.most_common(),
        "run": runs[0]["run_id"] if runs else "",
        "counts": json.loads(runs[0]["counts"]) if runs and runs[0]["counts"] else {},
    }


def _packages(db: Database) -> list[dict]:
    """Malicious-dependency intel aggregated across every finding's Trivy SBOM
    match: which OSM-listed malicious package (ecosystem/name/version) was
    found actually installed in which image(s). The searchable
    Dependency/Package Report -- the container-level view of what git_paca
    tracks at the package-registry level. Empty until a hunt runs with SBOM
    matching enabled (`knorr watch` always enables it; `knorr hunt` needs
    `--sources ...,osm_package`) and Trivy is installed.
    """
    agg: dict[tuple, dict] = {}
    for r in db.conn.execute("SELECT image, status, evidence FROM image_findings"):
        evidence = json.loads(r["evidence"] or "{}")
        for hit in evidence.get("sbom_hits") or []:
            key = (hit.get("ecosystem"), hit.get("name"), hit.get("version"))
            entry = agg.setdefault(key, {
                "ecosystem": hit.get("ecosystem"), "name": hit.get("name"),
                "version": hit.get("version"), "images": []})
            entry["images"].append({
                "image": r["image"], "status": r["status"],
                "link": _link_for(r["image"], evidence)})
    out = list(agg.values())
    out.sort(key=lambda d: -len(d["images"]))
    return out


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
                elif path == "/api/telemetry":
                    self._json(_telemetry(db))
                elif path == "/api/packages":
                    self._json(_packages(db))
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
  --brand:#1c548f;--brand-2:#e8f0f8;--series-2:#eb6834;
  --crit:#b3283a;--crit-bg:#fbe9eb;--high:#9a6712;--high-bg:#f7eede;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code",Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root{
  --canvas:#0d1219;--canvas-rgb:13,18,25;--surface:#131a23;--surface-2:#0f161e;--zebra:#141c26;
  --border:#232d3a;--border-2:#303c4b;--hair:#1b232e;
  --text:#d7dee7;--text-2:#94a1b0;--text-3:#66717f;
  --brand:#4f9bd8;--brand-2:#16222f;--series-2:#d95926;
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
.chart-box{position:relative;height:150px}
.chart-box svg{display:block;overflow:visible}
.chart-box circle.mark{fill:var(--surface);stroke-width:2;cursor:crosshair}
.chart-box rect.mark{cursor:crosshair}
.chart-box .xhair{stroke:var(--border-2);stroke-width:1;pointer-events:none;display:none}
.chart-tip{position:absolute;pointer-events:none;background:var(--text);color:var(--surface);
  font-size:11px;font-family:var(--mono);padding:5px 8px;white-space:nowrap;display:none;
  transform:translate(-50%,-100%);margin-top:-8px;z-index:5;line-height:1.5}
.chart-tip b{font-family:var(--sans);font-weight:600}
.chart-foot{display:flex;justify-content:space-between;color:var(--text-3);font-size:10px;
  font-family:var(--mono);margin-top:4px}
.note{color:var(--text-2);font-size:12px;line-height:1.6}.note b{color:var(--text)}
.subhead{margin:0 0 6px;color:var(--text-3);font-size:10.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.subhead:not(:first-child){margin-top:16px}
.search{width:100%;box-sizing:border-box;background:var(--surface-2);border:1px solid var(--border-2);
  color:var(--text);font-family:var(--sans);font-size:12.5px;padding:8px 12px;margin-bottom:12px}
.search:focus{outline:2px solid var(--brand);outline-offset:-1px}
.search::placeholder{color:var(--text-3)}
.pkgimgs{display:flex;flex-direction:column;gap:2px}
.pkgimgs a{font-family:var(--mono);font-size:11px}
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
  <div class="rowg">
    <div class="panel" style="margin:0"><div class="phead"><h2>Confirmed images over time</h2>
      <span class="meta">registry size per run</span></div>
      <div class="pbody"><div class="chart-box" id="chart-confirmed"></div>
      <div class="chart-foot" id="chart-confirmed-foot"></div></div></div>
    <div class="panel" style="margin:0"><div class="phead"><h2>Search yield per run</h2>
      <span class="meta">candidates screened, by round</span></div>
      <div class="pbody"><div class="chart-box" id="chart-candidates"></div>
      <div class="chart-foot" id="chart-candidates-foot"></div></div></div>
  </div>
  <div class="rowg">
    <div class="panel" style="margin:0"><div class="phead"><h2>Registry &amp; severity</h2>
      <span class="meta">confirmed images, by surface</span></div>
      <div class="pbody">
        <p class="subhead">Registry</p><div id="regs"></div>
        <p class="subhead">Severity</p><div id="sevs"></div>
      </div></div>
    <div class="panel" style="margin:0"><div class="phead"><h2>Top confirmed publishers</h2>
      <span class="meta">compounding pivot targets</span></div><div class="pbody" id="pubs"></div></div>
  </div>
  <div class="panel"><div class="phead"><h2>Package intelligence</h2>
    <span class="meta" id="pkgmeta"></span></div>
    <div class="pbody" style="padding-bottom:0">
      <input type="search" id="pkgsearch" class="search" placeholder="Search by package, ecosystem, or image&hellip;">
    </div>
    <div class="tblwrap"><table><thead><tr><th>Ecosystem</th><th>Package</th><th>Version</th>
      <th class="num">Images</th><th>Found in</th></tr></thead>
      <tbody id="pkgrows"></tbody></table></div></div>
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
const fmtTime=iso=>{try{return new Date(iso).toLocaleString(undefined,
  {month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}catch(e){return iso||""}};
// A small, dependency-free time-series chart (line or bar), single series,
// with a hover crosshair + tooltip. mode:"line" connects points; mode:"bar"
// draws thin sharp-cornered bars (matching this console's own flat, sharp-
// edged aesthetic rather than the general rounded-bar default).
function seriesChart(boxEl, footEl, data, key, color, mode){
  if(!data.length){boxEl.innerHTML='<span class="note">no completed runs yet</span>';footEl.textContent="";return}
  const w=Math.max(280, boxEl.clientWidth||560), h=150, pad={t:10,r:8,b:8,l:30};
  const vals=data.map(d=>d[key]);
  const maxV=Math.max(1,...vals), minV=Math.min(0,...vals);
  const iw=w-pad.l-pad.r, ih=h-pad.t-pad.b;
  const x=i=>pad.l+(data.length>1?iw*i/(data.length-1):iw/2);
  const y=v=>pad.t+ih-(ih*(v-minV)/((maxV-minV)||1));
  let grid="";
  for(let i=0;i<=3;i++){const gy=pad.t+ih*i/3, gv=Math.round(maxV-(maxV-minV)*i/3);
    grid+=`<line x1="${pad.l}" x2="${w-pad.r}" y1="${gy.toFixed(1)}" y2="${gy.toFixed(1)}" stroke="var(--hair)" stroke-width="1"/>`+
      `<text x="2" y="${(gy+3).toFixed(1)}" font-size="9" fill="var(--text-3)" font-family="var(--mono)">${gv}</text>`;}
  let marks="";
  if(mode==="line"){
    const path=data.map((d,i)=>(i?"L":"M")+x(i).toFixed(1)+","+y(d[key]).toFixed(1)).join(" ");
    marks=`<path d="${path}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`+
      data.map((d,i)=>`<circle class="mark" cx="${x(i).toFixed(1)}" cy="${y(d[key]).toFixed(1)}" r="2.5" stroke="${color}" data-i="${i}"/>`).join("");
  } else {
    const bw=Math.max(2, Math.min(18, iw/data.length-2));
    marks=data.map((d,i)=>`<rect class="mark" x="${(x(i)-bw/2).toFixed(1)}" y="${y(d[key]).toFixed(1)}"
      width="${bw.toFixed(1)}" height="${(pad.t+ih-y(d[key])).toFixed(1)}" fill="${color}" stroke="none" data-i="${i}"/>`).join("");
  }
  boxEl.innerHTML=`<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}">${grid}${marks}
    <line class="xhair" x1="0" x2="0" y1="${pad.t}" y2="${pad.t+ih}"/></svg><div class="chart-tip"></div>`;
  footEl.innerHTML=`<span>${esc(fmtTime(data[0].started_at))}</span><span>${esc(fmtTime(data[data.length-1].started_at))}</span>`;
  const svg=boxEl.querySelector("svg"), xhair=boxEl.querySelector(".xhair"), tip=boxEl.querySelector(".chart-tip");
  const nearest=px=>{let best=0,bd=Infinity;data.forEach((d,i)=>{const dd=Math.abs(x(i)-px);if(dd<bd){bd=dd;best=i}});return best};
  svg.addEventListener("mousemove",e=>{
    const r=svg.getBoundingClientRect(), px=(e.clientX-r.left)*(w/r.width), i=nearest(px);
    const d=data[i];
    xhair.style.display="block"; xhair.setAttribute("x1",x(i)); xhair.setAttribute("x2",x(i));
    tip.style.display="block";
    tip.style.left=((x(i)/w)*r.width)+"px"; tip.style.top=((y(d[key])/h)*r.height)+"px";
    tip.innerHTML=`<b>${d[key]}</b> &middot; ${esc(fmtTime(d.started_at))}`;
  });
  svg.addEventListener("mouseleave",()=>{xhair.style.display="none";tip.style.display="none"});
}
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
  const rgmx=Math.max(1,...s.by_registry.map(x=>x[1]));
  document.getElementById('regs').innerHTML=s.by_registry.map(([r,n])=>bar(REGISTRY_LABEL[r]||r,n,rgmx,"var(--brand)")).join("")||'<span class="note">no data</span>';
  const sevmx=Math.max(1,...s.by_severity.map(x=>x[1]));
  document.getElementById('sevs').innerHTML=s.by_severity.map(([sv,n])=>bar(sv,n,sevmx,sv==="critical"?"var(--crit)":"var(--high)")).join("")||'<span class="note">no data</span>';
  const pubmx=Math.max(1,...s.by_publisher.map(x=>x[1]));
  document.getElementById('pubs').innerHTML=s.by_publisher.map(([p,n])=>bar(p,n,pubmx,"var(--series-2)")).join("")||'<span class="note">no data</span>';
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
  const tel=await (await fetch('/api/telemetry')).json();
  seriesChart(document.getElementById('chart-confirmed'), document.getElementById('chart-confirmed-foot'),
    tel, 'confirmed_total', 'var(--brand)', 'line');
  seriesChart(document.getElementById('chart-candidates'), document.getElementById('chart-candidates-foot'),
    tel, 'candidates', 'var(--series-2)', 'bar');
  ALL_PACKAGES=await (await fetch('/api/packages')).json();
  applyPackageFilter();
}
let ALL_PACKAGES=[];
function renderPackages(pkgs){
  document.getElementById('pkgmeta').textContent=
    `${pkgs.length} known-malicious dependenc${pkgs.length===1?'y':'ies'} found installed, Trivy SBOM match against OSM`;
  document.getElementById('pkgrows').innerHTML=pkgs.map(p=>{
    const imgs=p.images.slice(0,4).map(im=>`<a href="${esc(im.link)}" target="_blank" rel="noopener">${esc(im.image)}</a>`).join("")+
      (p.images.length>4?`<span class="more">+${p.images.length-4} more</span>`:"");
    return `<tr><td class="src">${esc(p.ecosystem)}</td><td class="img">${esc(p.name)}</td>
      <td class="tierlbl">${esc(p.version)}</td><td class="num score">${p.images.length}</td>
      <td><div class="pkgimgs">${imgs}</div></td></tr>`;
  }).join("")||`<tr><td colspan="5" class="note">no malicious dependencies found yet, SBOM matching runs during Tier-2 (needs Trivy installed; <code>knorr watch</code> enables it by default)</td></tr>`;
}
function applyPackageFilter(){
  const q=document.getElementById('pkgsearch').value.trim().toLowerCase();
  renderPackages(q?ALL_PACKAGES.filter(p=>
    p.name.toLowerCase().includes(q) || p.ecosystem.toLowerCase().includes(q) ||
    p.images.some(im=>im.image.toLowerCase().includes(q))):ALL_PACKAGES);
}
document.getElementById('pkgsearch').addEventListener('input',applyPackageFilter);
load(); setInterval(load,15000);
</script>
</body></html>"""
