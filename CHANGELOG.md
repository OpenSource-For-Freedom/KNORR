# Changelog

## 0.1.0

First capability-complete release: multi-registry hunting, a hardened
discovery pipeline, and a public long-running watch mode.

### Added

- **GitHub Container Registry (GHCR)** as a second hunted registry
  (`--registry ghcr`): daemonless OCI client profile, account-pivot discovery,
  and a GitHub-code-search image-reference discovery source (GHCR has no
  public keyword-search API, so this mines Dockerfiles/compose/k8s manifests
  for `ghcr.io/<owner>/<image>` references naming a malicious term).
- **`knorr watch`** — a public, first-class long-running hunt loop with
  Discord/webhook alerts on new confirmed findings. Budget-aware, rotates
  across registries, and is resilient to a single bad round.
- **Known-good-publisher allowlist** — legitimate vendors (the upstream
  `xmrig` project, `aquasec`, and others) can no longer auto-confirm; a match
  is held for manual review instead.
- **Shared-wallet auto-promotion** — a review/BYO-bucketed image whose payout
  wallet matches an already-confirmed image is promoted to high-confidence
  regardless of its own command shape (proven on the `isukim`/`donafro`
  cryptojacking fleets).
- **OSM submission ledger** (`osm_submit.py --ledger`) — a methodology +
  precision-stats Markdown report for review/audit.
- Retry/backoff for transient registry errors (5xx, network), so a single
  flaky response no longer drops an image from a long-running hunt.
- CI (`ruff` + `pytest` on push/PR to `main`).
- Malicious Dockerfile findings now persist into the same shared registry the
  dashboard reads, instead of only ever being printed to a console and
  forgotten; `knorr dockerfiles` upserts every hit, keyed
  `github.com/<owner>/<repo>:<path>`.
- Dashboard: a registry column and per-finding outbound link (Docker Hub,
  GHCR, or the GitHub blob URL for a Dockerfile finding), a "tools flagged"
  KPI, a project hero-image background, and a registries-seen summary badge.

### Changed

- Dashboard default port moved from 8788 to 8789 to stop colliding with
  git_warden's dashboard when both run locally at once.

### Fixed

- **Docker Hub discovery starvation**: the publisher pivot (the highest-yield
  discovery source) sat past position 686 in a ~1,100-item candidate list and
  was never reached by a budget-constrained Tier-1 screen. Fixed by excluding
  already-known images from rediscovery and reordering the publisher pivot
  ahead of the much larger, lower-precision search set.
- **Search pagination**: `hub_search` sampled only page 1 (~25 results) of
  what is often 500-1000+ matches for a common term; now paginates.
- Several false-positive classes caught and fixed: OpenSSL's generated
  `fipskey.h` misread as a shellcode blob, a security vendor's own AppSec
  ruleset misread as a named malware family, an AWS devops image's empty
  credential-env declaration misread as a set secret, and the upstream
  `xmrig`/`xmrig-proxy` projects misread as cryptojacking distributions.
- Removed Quay.io support (searched, but its public miner surface was
  consistently legitimate BYO tooling; zero confirmations across a full run).
- **Discord alert / OSM submission mismatch**: `knorr watch` alerted on any
  confirmed finding, regardless of confidence bucket, so a review-bucket or
  BYO-tool finding (an ENV-default wallet, a parameterized miner) displayed
  identically to a genuinely submission-ready one. The confidence tiering used
  to gate OSM submission is now extracted into a public module
  (`scanning/confidence.py`) shared by both the private submission path and
  `knorr watch`'s alerting, so the two can never drift apart again; alerts now
  only fire on the same `high`-confidence bar OSM submission uses, and show
  the actual severity, confidence tier, and confirming proof line instead of a
  fixed crypto-shaped template.

### Known issues

- The `mirai-gafgyt` malware-family signature (and, in one case,
  `linux-cryptobot`/`c2-framework`/`preload-rootkit` alongside it) has matched
  generic FSF/GNU copyright boilerplate and bundled open-source JS libraries
  (MathJax, zxcvbn, GNU autotools' `config.guess`/`config.sub`) rather than
  actual malware code on at least three images. Those specific findings were
  caught and rejected before submission; the underlying rule still needs
  tightening so it stops confirming on generic license/copyright text.

## 0.0.1

Initial MVP: Docker Hub hunting (Tier-1 config screen, Tier-2 layer pull +
scan), the full-spectrum static signature library, the precision-first
confirmation gate, the Dockerfile-in-git scanner, the dashboard, and the local
OSM submission path.
