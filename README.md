<div align="center">

<img src="docs/knorr.png" alt="KNÖRR" width="100%"/>

# KNÖRR

*The warden of poisoned waters. The eye that does not sleep.*

[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## The Saga

In the age before memory, when the world-tree Yggdrasil stretched its roots into nine realms, the seas between them teemed with serpents wearing the faces of merchants. They sailed in vessels that looked like grain ships, but carried venom in the hold. Cryptojacking daemons. Reverse shells stitched into Alpine images. Typosquatted names so close to the true names that only a völva with clear-sight could tell them apart.

The gods grew weary of watching registries fill with rot.

So they sent **Knörr**. Not a warrior, not a skald. A *knörr*. The merchant vessel that had sailed every route, learned every trick of the poisoned current, and now rode the dark registries with an eye like a hawk and a hull that drew no attention.

The captain asks no favors. He sails alone.

---

<div align="center">

<img src="docs/knorr_fight.png" alt="The Fight" width="100%"/>

</div>

---

## The Hunt

The waters Knörr patrols are vast.

**Docker Hub** churns with ten thousand images. Most are honest cargo. But threaded through them: **XMRig** dressed as `python:slim`, **kinsing** hiding in a Redis impersonation, **TeamTNT** campaign images with wallets baked into the manifest like runes carved in bone.

Knörr moves in three passes. None of them loud.

**The First Crossing: Discovery**
Knörr sweeps the surface with known words of power: miner families, coin names, campaign sigils. He circles proven-bad harbors and enumerates every vessel docked there. He checks the names of Official images against the names of their imitators, the typosquats, and marks those that are one rune off from truth.

**The Second Crossing: Tier-1 Screening**
No layer is pulled. No cargo opened. Knörr reads the manifest, reads the config. He scores the signals: baked-in pool addresses, stratum connections, environment variables carrying wallet strings, entrypoints that spawn shells in the dark. Confirmed malice needs no deeper look. It is logged, written to the wall, and the captain moves on.

**The Third Crossing: Tier-2 Reckoning**
For the leads that whisper but do not shout, the ones the manifest alone cannot condemn, Knörr pulls layers. He runs Trivy across the SBOM. He reads the strings. He finds what hides in the deep.

Nothing is ever executed. Nothing is assumed. The captain reads the runes and records what is true.

**The Reach Beyond the Sea**
Knörr sails not only the registry waters. He crosses into **GitHub**, hunting malicious Dockerfiles before they ever publish. The pre-publish surface, the build files, the poisoned source: he sees these too. A pipeline-only scanner never would.

**The Wall of Bad Owners**
When one vessel in an account is confirmed poison, the whole harbor is suspect. Knörr pivots on the owner, enumerates the fleet, and surfaces every image the bad actor ever docked. One confirmed miner becomes a full account audit.

---

<div align="center">

<img src="docs/knorr_lok.png" alt="Loki's Reach" width="100%"/>

</div>

---

## What Knörr Carries

```
knorr probe <image>     # Tier-1 read of one image: manifest, config, signal score
knorr hunt              # Full sail: discover -> screen -> confirm -> registry
knorr dockerfiles        # Hunt malicious Dockerfile CODE on GitHub (pre-publish)
knorr serve              # Read-only threat-telemetry dashboard (default :8789)
knorr watch              # Long-running hunt loop with Discord alerts
```

| Command | What it does |
|---|---|
| `knorr probe --image <ref>` | Tier-1 read of one image (manifest + config, no layer pull); prints the signal score. The cheap sanity check before trusting the pipeline. |
| `knorr hunt --registry {docker,ghcr}` | Full pipeline: discover → Tier-1 screen → Tier-2 confirm → registry. `--scan` runs Tier-2; `--sources` picks discovery methods; `--limit`/`--tier1-limit` bound the pull budget. |
| `knorr dockerfiles` | Mines GitHub code search for malicious Dockerfile CODE (reverse shells, C2, droppers) *before* an image is ever published. Persists hits into the same registry the dashboard reads. |
| `knorr serve --port 8789` | Serves the live dashboard: confirmed detections, threat-facet breakdown, registry/source split, novelty vs. OSM. Read-only over the SQLite store. |
| `knorr watch --duration <s> --registries docker,ghcr` | Runs repeated hunts for a set duration, posting a Discord alert for every new **HIGH-confidence** finding only, the identical bar OSM submission uses (see below). |
| `python -m knorr.osm_submit` | **Local-only, gitignored.** The write path to OpenSourceMalware: dry-run by default, `--confirm` to POST. Not shipped in the public repo, see [OSM submission](#reporting-to-osm). |

The hold is light by design. The runtime needs only `requests`. Trivy is shelled out, never reimplemented. No pydantic. Runs clean on Python 3.14.

What comes out of the hold: **findings CSV**, **summary**, **SQLite ledger**, a **live dashboard**. The captain records everything. Nothing goes to OSM without a human hand on the wheel.

---

## How the Ship Is Built

Discovery feeds two registries (Docker Hub, GHCR) and one pre-publish source (GitHub
Dockerfiles) into the same Tier-1 → Tier-2 → confirmation-gate pipeline, all landing in
one SQLite registry. Everything downstream, the dashboard, the long-running watch
loop's Discord alerts, and OSM submission, reads from that one store and is gated by
the *same* confidence tiering, so what gets alerted and what gets submitted can never
quietly drift apart.

```mermaid
flowchart TD
    classDef store fill:#1c548f,color:#fff,stroke:#0d2c4a
    classDef gate fill:#b5731a,color:#fff,stroke:#7a4d10
    classDef drop fill:#5a6472,color:#fff,stroke:#333a42
    classDef live fill:#22aa66,color:#fff,stroke:#0f5c34

    A1["Docker Hub: search / publisher pivot / typosquat"]
    A2["GHCR: account pivot"]
    A3["GitHub code search: ghcr.io/&lt;owner&gt;/&lt;image&gt; refs"]
    A4["GitHub code search: malicious Dockerfile code"]
    A5["OSM container feed: seed targets + novelty check"]

    A1 --> B
    A2 --> B
    A3 --> B
    A5 --> B

    subgraph B["Tier-1 screen (no layer pull)"]
        direction TB
        B1["Manifest + config only"]
        B2["Score signals: pool/wallet strings, ENV vars, entrypoint shape"]
    end

    B -- "score clears threshold" --> C
    B -. "clean" .-> X1["discarded"]:::drop

    subgraph C["Tier-2 confirm (bounded layer pull)"]
        direction TB
        C1["Extract + unpack layers"]
        C2["Trivy SBOM match + content scan"]
    end

    A4 --> D

    subgraph D["Precision-first confirmation gate"]
        direction TB
        D1["Tier-A signature confirms alone / Tier-B needs corroboration"]
        D2["Known-good-publisher allowlist -&gt; held for review, never auto-confirmed"]
        D3["Shared-wallet auto-promotion across a proven-bad publisher's fleet"]
    end

    C --> D

    D -- confirmed --> E[("SQLite registry<br/>image_findings + runs")]:::store
    D -- "screened / rejected" --> E

    E --> F1["knorr serve<br/>read-only dashboard"]
    E --> F2["knorr watch<br/>long-running hunt loop"]
    E --> F3["osm_submit.py<br/>local-only, gitignored"]

    F2 --> G{{"scanning/confidence.py<br/>shared confidence tiering"}}:::gate
    F3 --> G

    G -- high --> H1["Discord alert"]:::live
    G -- high --> H2["Liveness recheck:<br/>image / Dockerfile still live?"]
    G -- "review / byo" --> H3["held for manual review, never alerted or submitted"]

    H2 -- live --> H4["POST submit-threat-report"]:::live
    H2 -. gone .-> H5["skipped, never sent"]:::drop
```

**The precision-first philosophy**, inherited from `git_warden`: a Tier-A signature
(a reverse shell, a hardcoded miner wallet) confirms an image on its own; a Tier-B
signal needs a second, independent corroborating signal; an OSM label or a name match
alone never confirms anything. The confidence gate then splits confirmed findings into
`high` (submission-eligible), `review` (an ENV-default wallet, a very high pull count:
gray area, held for a human), and `byo` (a parameterized tool, someone's own miner
config: never submitted). That same three-way split governs Discord alerts, the
dashboard, and OSM submission identically.

### Reporting to OSM

The write path (`osm_submit.py`) is **local-only and gitignored**, the public repo
ships detection, not the submission credentials or logic. It checks OSM's full
history before ever sending anything, re-verifies each payload is still live right
before POSTing, and never auto-submits anything below the `high` confidence tier.
It also mirrors `git_warden`'s reviewer tooling: `--queue` (what's ready, read-only),
`--reconcile`/`--audit` (what OSM currently says about our submissions), and
`--wizard` (an interactive walkthrough for a non-technical operator).

---

## Project Layout

```
src/knorr/
  cli.py                CLI entry point (probe / hunt / dockerfiles / serve / watch)
  hunt.py                Discovery -> Tier-1 -> Tier-2 -> registry orchestration
  db.py                  SQLite registry (image_findings, runs)
  watch.py               Long-running hunt loop + Discord alerting
  config.py              Env/credential loading, known-good-publisher allowlist
  registry/              Daemonless OCI clients (Docker Hub + GHCR, shared code)
  scanning/               Signature library, Tier-1/Tier-2 scanners, confidence.py
                         (the shared confirm/alert/submit gate), the Dockerfile scanner
  feeds/                 GitHub + OSM API clients
  dashboard/              Self-contained read-only web dashboard (stdlib http.server)
tests/                   pytest suite (346 tests; osm_submit.py's own tests travel
                         with it, out-of-band, since the module itself is gitignored)
docs/plans/01 PRD.md     The original product requirements document
```

Testing: [![CI](https://github.com/OpenSource-For-Freedom/KNORR/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenSource-For-Freedom/KNORR/actions/workflows/ci.yml)
`ruff check` + `pytest` on every push/PR to `main`, Python 3.12 and 3.13.

---

*Knörr sailed before the gods named him. He will sail after.*

---

<p align="center">
  <a href="https://opensourcemalware.com/my-submissions">
    <img src="docs/osm-reports.png" alt="OSM Submissions" width="100%">
  </a>
</p>

<div align="center">
<sub>OpenSource-For-Freedom · MIT License</sub>
</div>
