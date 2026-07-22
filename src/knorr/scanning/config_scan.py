"""Full-spectrum static container threat-signature library.

Reads image config (Entrypoint/Cmd/Env/Labels/history) at Tier-1 and unpacked
layer file contents at Tier-2, and scores EVERY threat facet, not just mining:

    cryptomining · reverse-shell/C2 · exfiltration · credential & cloud theft ·
    obfuscation/encoding · persistence · rootkit/defense-evasion ·
    container-escape · known malware & botnet families · recon/lateral movement ·
    suspicious download infrastructure

Everything here is DETECTED and SCORED (retained in artifacts). Which signals
may *confirm* a finding is decided by the precision-first gate (``gate.py``);
dual-use idioms (nmap, curl, a project's own webhook, --privileged) are scored
for ranking but never confirm alone.

The same rule set runs over the image config (Tier-1) and over baked-in layer
files (Tier-2, e.g. an xmrig ``config.json`` carrying the pool + wallet), so an
attacker cannot hide a payload by moving it from the entrypoint into a file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigSignal:
    category: str
    rule: str
    evidence: str  # the (truncated) string that matched


def _r(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I)


# (category, rule, weight, pattern). Weight feeds ranking; the gate decides
# confirmation. Weights: 5 = direct RCE/theft, 4 = loader/exfil, 3 = access/
# persistence, 2 = escape/recon dual-use, 1 = weak.
_RULES: tuple[tuple[str, str, int, re.Pattern[str]], ...] = (
    # ===================== CRYPTOMINING =====================
    ("cryptomining", "miner-binary", 5, _r(
        r"\b(xmrig|xmr-stak|xmr-node|ccminer|cpuminer(?:-multi)?|cgminer|bfgminer|"
        r"t-rex|trex|nbminer|phoenixminer|lolminer|nanominer|teamredminer|srbminer|"
        r"ethminer|gminer|bzminer|miniz|wildrig|verusminer|ariominer|kawpowminer|"
        r"cpu_miner|minerd|kdevtmpfsi)\b")),
    ("cryptomining", "miner-executable", 4, _r(r"(?:\./|/)[\w.\-]*miner\b")),
    ("cryptomining", "miner-wallet-flag", 5, _r(
        r"(?:--wallet|--user|-u)[=\s]+[A-Za-z0-9]{20,}")),  # hardcoded payout addr
    ("cryptomining", "miner-flags", 4, _r(
        r"--(?:cpu-intensity|donate-level|randomx|coin[=\s]|algo[=\s]|nicehash|"
        r"pool[=\s]|rig-id|max-cpu-usage)\b")),
    ("cryptomining", "mining-pool", 4, _r(
        r"(stratum\+(?:tcp|ssl)://|\bpool\.(?:supportxmr|hashvault|minexmr)\b|"
        r"\b(?:supportxmr|minexmr|nanopool|minergate|moneroocean|c3pool|xmrpool|"
        r"2miners|dxpool|hashvault|aropool|unmineable|herominers|zergpool|monerohash|"
        r"miningpoolhub|f2pool|nanopool|nicehash)\.(?:com|org|pro|net|eu|io)\b)")),
    ("cryptomining", "monero-wallet", 4, _r(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")),
    ("cryptomining", "kill-competitors", 5, _r(
        r"\b(?:pkill|killall|kill\s+-9)\b[^\n]{0,60}"
        r"(xmrig|minerd|kinsing|kdevtmpfsi|\bkthread|cnrig|\.mining)")),

    # ===================== REVERSE SHELL / C2 =====================
    # Real reverse shell only: an interactive shell wired to the socket, a
    # stdin/stdout redirect (0>&1 / <&), or exec NN<>/dev/tcp -- NOT a bare
    # wait-for-port healthcheck like `echo > /dev/tcp/db/5432` (which has no
    # shell/redirect and must not confirm).
    # Real reverse shell only: an interactive shell wired to the socket, or a
    # /dev/tcp connection followed by a shell redirect (0>&1 / ;sh). The bare
    # `exec N<>/dev/tcp/...` idiom is NOT here: it is the wait-for-service /
    # healthcheck pattern (exec 3<>/dev/tcp/127.0.0.1/3000, wait-for-MySQL) and
    # would confirm legitimate startup probes.
    ("reverse_shell", "bash-tcp", 5, _r(
        r"(?:bash|sh)\s+-i\b[^\n]{0,80}/dev/(?:tcp|udp)/"
        r"|/dev/(?:tcp|udp)/[\w.\-]+/\d+[^\n]{0,25}(?:0>&1|0<&1|0<&\d|;\s*(?:sh|bash)\b)")),
    ("reverse_shell", "nc-exec", 5, _r(r"\bnc(?:at)?\b[^\n]*\s-\w*e\w*\b[^\n]*(sh|bash)")),
    ("reverse_shell", "mkfifo-shell", 5, _r(r"mkfifo\b[^\n]*\|\s*(?:/bin/)?(?:sh|bash)\b")),
    ("reverse_shell", "python-revshell", 5, _r(
        r"pty\.spawn\(\s*[\"']/(?:bin/)?(?:ba)?sh|"
        r"socket\.socket\([^\n]{0,40}\)[^\n]{0,80}connect\([^\n]{0,60}\)[^\n]{0,80}"
        r"(?:subprocess|/bin/sh|dup2)")),
    ("reverse_shell", "perl-revshell", 5, _r(
        r"perl\b[^\n]{0,80}(?:socket|IO::Socket)[^\n]{0,140}(?:exec|/bin/sh)")),
    ("reverse_shell", "php-revshell", 5, _r(r"fsockopen\s*\([^\n]{0,80}(?:exec|proc_open|/bin/sh|shell_exec)")),
    ("reverse_shell", "ruby-revshell", 5, _r(r"TCPSocket\.(?:new|open)\b[^\n]{0,120}(?:exec|/bin/sh)")),
    ("reverse_shell", "powershell-revshell", 5, _r(
        r"New-Object\s+System\.Net\.Sockets\.TCPClient|IEX\s*\(\s*New-Object")),
    ("reverse_shell", "socat-shell", 5, _r(r"socat\b[^\n]*(?:EXEC:|exec:)[^\n]*(?:sh|bash|pty)")),
    # Near-exclusively-malicious red-team C2 frameworks (negligible legitimate
    # base rate as a bare string match) confirm alone. "metasploit"/"msfvenom"
    # are deliberately NOT here: Metasploit is the world's most mainstream,
    # legal pentesting framework, ships by default in Kali Linux, and a bare
    # "apt-get install metasploit-framework" build line is exactly as
    # consistent with a security researcher's own toolbox image as with
    # malice (the d0whc3r/kali-ssh false positive, already submitted to OSM
    # before this was caught: a "C2 host" of gitlab.com/www.kali.org was the
    # tell). See "pentest-toolkit" below for the dual-use, scored-not-confirmed
    # treatment "meterpreter" was kept here: unlike a package name, actually
    # finding the literal payload name in content is a stronger signal of use.
    ("c2", "c2-framework", 5, _r(
        r"\b(meterpreter|cobalt\s?strike|cobaltstrike|beacon\.(?:dll|bin)|"
        r"sliver|havoc|mythic|powershell[-_]?empire|covenant|merlin|brute\s?ratel|bruteratel|"
        r"posh[-_]c2|sillenttrinity|silenttrinity)\b")),
    # Dual-use pentesting tools: legitimate on a security researcher's own
    # image, so scored for ranking (like nmap/--privileged) but never confirms
    # alone (see gate.py's _CONFIRM_ALONE, which deliberately omits this rule).
    ("c2", "pentest-toolkit", 2, _r(r"\b(metasploit(?:-framework)?|msfvenom|msfconsole)\b")),
    ("c2", "dyndns-c2", 3, _r(
        r"\b[\w.\-]+\.(?:duckdns\.org|ngrok\.io|serveo\.net|hopto\.org|no-ip\.\w+|"
        r"myftp\.\w+|dynu\.\w+|zapto\.org|portmap\.io)\b")),

    # ===================== EXFILTRATION =====================
    ("exfiltration", "discord-webhook", 4, _r(
        r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[\w.\-]+")),
    ("exfiltration", "telegram-bot", 4, _r(r"https?://api\.telegram\.org/bot\d+:[\w.\-]+")),
    ("exfiltration", "slack-webhook", 3, _r(r"https://hooks\.slack\.com/services/[\w/]+")),
    ("exfiltration", "generic-webhook", 3, _r(r"https?://(?:webhook\.site|hookb\.in|pipedream\.net)/[\w-]+")),
    ("exfiltration", "curl-post-data", 4, _r(
        r"\b(?:curl|wget)\b[^\n]*(?:-d|--data(?:-binary|-raw)?|-F|--form|-T|--upload-file)\b"
        r"[^\n]*(?:\$\(|whoami|hostname|`|/etc/|env\b|\.ssh)")),
    ("exfiltration", "paste-exfil", 4, _r(
        r"\b(?:curl|wget)\b[^\n]*(?:pastebin\.com|transfer\.sh|0x0\.st|file\.io|ix\.io|"
        r"termbin\.com|anonfiles|controlc\.com|oshi\.at)")),
    ("exfiltration", "dns-exfil", 3, _r(
        r"\b(?:dig|nslookup|host)\b[^\n]{0,40}\$\(|\$\([^\n]{0,40}\)[^\n]{0,20}\.\w+\.\w+\b[^\n]{0,10}(?:dig|nslookup)")),

    # ===================== CREDENTIAL / CLOUD THEFT =====================
    ("credential_access", "cloud-metadata", 4, _r(
        r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
        r"/latest/meta-data/iam|/computeMetadata/v1/)")),
    # A bare `AWS_SECRET_ACCESS_KEY=` env DECLARATION (empty) is normal for an AWS
    # tooling image; only a real access-key id, a set secret value, or the creds
    # file is a credential-access signal (the eks-kubectl-helm false positive).
    ("credential_access", "aws-creds", 4, _r(
        r"(\.aws/credentials|AKIA[0-9A-Z]{16}|"
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*\S{8,})")),
    ("credential_access", "gcp-creds", 3, _r(
        r"(GOOGLE_APPLICATION_CREDENTIALS|\.config/gcloud|gcp[-_]?service[-_]?account.*\.json)")),
    ("credential_access", "azure-creds", 3, _r(r"(AZURE_CLIENT_SECRET|\.azure/(?:accessTokens|credentials))")),
    ("credential_access", "ssh-keys", 4, _r(
        r"(\.ssh/id_(?:rsa|ed25519|ecdsa)|BEGIN\s+(?:RSA|OPENSSH|EC|DSA)\s+PRIVATE\s+KEY)")),
    ("credential_access", "k8s-token", 4, _r(r"/var/run/secrets/kubernetes\.io/serviceaccount")),
    ("credential_access", "docker-socket", 3, _r(r"/var/run/docker\.sock")),
    ("credential_access", "env-dump", 4, _r(
        r"(cat\s+/proc/(?:self|\d+|\*)/environ|printenv\b[^\n]*\|\s*(?:curl|nc|wget)|"
        r"\benv\b[^\n]*\|\s*(?:curl|nc|wget|base64)|JSON\.stringify\(process\.env)")),
    ("credential_access", "shadow-read", 4, _r(r"\b(?:cat|cp|less|tail|head)\s+/etc/shadow\b")),
    ("credential_access", "git-creds", 3, _r(r"(\.git-credentials|/\.netrc\b|\.npmrc\b[^\n]*_authToken)")),

    # ===================== OBFUSCATION / ENCODING =====================
    # Network-fetched, decoded, and executed = an obfuscated dropper. Unambiguous
    # (confirm-alone). Kept separate from the plain decode-exec below, which a
    # legitimate embedded-blob idiom (e.g. the FreeSurfer license written via
    # `echo <b64> | base64 -d | sh`) trips at scale across scientific images.
    ("obfuscation", "fetch-decode-exec", 5, _r(
        r"(?:curl|wget|fetch)\b[^\n]{0,140}\|\s*base64\s+(?:-d|--decode|-D)\s*\|\s*"
        r"(?:/bin/)?(?:sh|bash|python\d?|perl|node)\b")),
    ("obfuscation", "base64-decode-exec", 4, _r(
        r"base64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:/bin/)?(?:sh|bash|python\d?|perl|node)\b")),
    ("obfuscation", "echo-base64-pipe", 4, _r(r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+(?:-d|--decode)")),
    ("obfuscation", "gzip-base64", 5, _r(r"base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:gunzip|zcat|gzip\s+-d)")),
    ("obfuscation", "python-exec-decode", 5, _r(
        r"(?:exec|eval)\s*\(\s*(?:base64\.b64decode|__import__\(['\"]base64['\"]\)|"
        r"codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)")),
    ("obfuscation", "eval-atob", 5, _r(r"eval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\s*\(")),
    ("obfuscation", "hex-escape-exec", 4, _r(r"(?:echo\s+-e|printf)\s+['\"]?(?:\\x[0-9a-fA-F]{2}){6,}")),
    ("obfuscation", "xxd-revert", 4, _r(r"\|\s*xxd\s+-r\b|xxd\s+-r\b[^\n]*\|\s*(?:sh|bash)")),
    ("obfuscation", "charcode-blob", 3, _r(r"String\.fromCharCode\((?:\s*\d+\s*,){12,}")),
    ("obfuscation", "shellcode-blob", 4, _r(r"(?:\\x[0-9a-fA-F]{2}){20,}|(?:0x[0-9a-fA-F]{2}\s*,\s*){20,}")),
    ("obfuscation", "ifs-obfuscation", 3, _r(r"\$\{IFS\}|\$IFS\$")),  # Mirai/botnet space-evasion

    # ===================== PERSISTENCE =====================
    ("persistence", "cron-inject", 4, _r(
        r"(>>?\s*/etc/cron|/var/spool/cron/|crontab\s+-|echo[^\n]*\|\s*crontab)")),
    ("persistence", "systemd-drop", 3, _r(r">>?\s*/etc/systemd/system/[\w@.\-]+\.service|systemctl\s+enable")),
    ("persistence", "rc-local", 3, _r(r">>?\s*/etc/rc\.local\b")),
    ("persistence", "profile-inject", 3, _r(
        r">>?\s*(?:~|/root|/home/[\w.\-]+)/\.(?:bashrc|profile|bash_profile|zshrc)")),
    ("persistence", "ssh-authkeys", 4, _r(r">>?\s*[^\n]*\.ssh/authorized_keys")),
    ("persistence", "ldso-preload", 5, _r(r"/etc/ld\.so\.preload")),
    ("persistence", "tunnel-tool", 3, _r(r"\b(?:ngrok|autossh|frpc|frps|chisel|gost|iodine|dnscat|reverse[-_]?ssh)\b")),

    # ===================== ROOTKIT / DEFENSE EVASION =====================
    ("rootkit", "preload-rootkit", 5, _r(
        r"\b(libprocesshider|processhider|diamorphine|reptile|azazel|jynx2?|beurk|bedevil|"
        r"vlany|rootkit)\b")),
    ("defense_evasion", "ld-preload-env", 3, _r(r"\bLD_PRELOAD\s*=")),
    ("defense_evasion", "history-clear", 3, _r(
        r"(history\s+-c|unset\s+HISTFILE|>\s*~?/?\.bash_history|HISTSIZE=0|export\s+HISTFILE=/dev/null)")),
    ("defense_evasion", "timestomp", 2, _r(r"touch\s+-[amcr]{1,3}\b[^\n]*(?:-d|-r|-t)\b")),
    ("defense_evasion", "disable-security", 3, _r(
        r"(setenforce\s+0|systemctl\s+stop\s+(?:firewalld|apparmor|selinux)|ufw\s+disable|"
        r"iptables\s+-F|chattr\s+[+-]i)")),
    ("defense_evasion", "hidden-tmp", 2, _r(r"/(?:tmp|dev/shm|var/tmp)/\.[A-Za-z0-9._\-]{2,}")),

    # ===================== CONTAINER ESCAPE =====================
    ("container_escape", "host-mount", 3, _r(r"(?:-v|--volume|--mount[^\n]*source=)\s*/?:?/(?:host|:/)")),
    ("container_escape", "nsenter-host", 4, _r(r"nsenter\b[^\n]*(?:--target\s+1|-t\s*1)\b[^\n]*(?:-m|-p|-n)")),
    ("container_escape", "proc-root", 3, _r(r"/proc/1/root\b")),
    ("container_escape", "cgroup-release-agent", 5, _r(r"release_agent|notify_on_release")),
    ("container_escape", "privileged", 2, _r(r"--privileged\b")),
    ("container_escape", "cap-add-admin", 3, _r(r"--cap-add[=\s]*(?:SYS_ADMIN|SYS_PTRACE|ALL)\b")),
    ("container_escape", "chroot-host", 3, _r(r"chroot\s+/host\b")),

    # ===================== MALWARE / BOTNET FAMILIES =====================
    ("malware_family", "mirai-gafgyt", 5, _r(
        r"\b(mirai|gafgyt|bashlite|tsunami|kaiten|qbot|mozi|hajime|dark[-_]?nexus)\b|"
        r"/bin/busybox\s+[A-Z]{4,}")),
    ("malware_family", "linux-cryptobot", 5, _r(
        # "deromoner" (mandatory suffix), not bare "dero": Dero is a real,
        # popular privacy coin that legitimate miners (xmrig, etc.) genuinely
        # support and reference throughout their own source code, so a bare
        # "dero" collides with that legitimate coin name (the pmietlicki/
        # xmrig-nvidia false positive, matching xmrig's own AstroBWT/Dero
        # mining-algorithm support code).
        # "8220gang"/"8220 gang" (the actual threat-actor name), not a bare
        # "8220": that numeral is also the Unicode codepoint for a curly
        # quote (U+2018-201D), so it appears in essentially every JS
        # character-encoding table (html-entities, entities, and any bundled
        # bundle embedding one) as ordinary data, not a threat-actor
        # reference (the refactr/runner-pool false positive; the SAME numeral
        # false-confirmed via html-entities/entities in node_modules too).
        r"\b(kinsing|kdevtmpfsi|sysrv|sysrvv|deromoner|z0miner|8220[\s-]?gang|watchdogs|xanthe|"
        r"prometei|outlaw|rocke|teamtnt|tntcnc|hildegard|abcbot)\b")),
    ("malware_family", "worm-scanner", 3, _r(r"\b(masscan|zmap|zgrab|pnscan|unicornscan)\b")),
    ("malware_family", "redis-unauth", 3, _r(r"redis-cli\b[^\n]*(?:config\s+set|flushall|-h\s+\d)")),

    # ===================== RECON / LATERAL MOVEMENT =====================
    ("recon", "portscan", 2, _r(r"\b(?:nmap|masscan|zmap|pnscan|unicornscan|hping3)\b")),
    ("lateral_movement", "ssh-brute", 3, _r(r"\b(?:hydra|medusa|ncrack)\b|sshpass\s+-p\b")),

    # ===================== SUSPICIOUS DOWNLOAD INFRASTRUCTURE =====================
    ("download_exec", "curl-pipe-shell", 4, _r(
        r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:sh|bash)\b")),
    ("download_exec", "raw-ip-fetch", 3, _r(r"\b(?:curl|wget)\b[^\n]*https?://\d{1,3}(?:\.\d{1,3}){3}")),
    ("download_exec", "tor-onion-fetch", 4, _r(r"\b(?:curl|wget)\b[^\n]*[a-z2-7]{16,56}\.onion")),
    ("download_exec", "raw-paste-fetch", 3, _r(
        r"\b(?:curl|wget)\b[^\n]*(?:pastebin\.com/raw|raw\.githubusercontent\.com|transfer\.sh|"
        r"0x0\.st|termbin\.com)")),
)


def strings_from_config(config_json: dict) -> list[str]:
    """Flatten the interesting text out of an image config blob.

    Pulls Entrypoint, Cmd, every Env entry, every Label, and every build-history
    ``created_by`` line (which records the RUN/ADD steps that assembled the image).
    """
    cfg = config_json.get("config") or config_json.get("container_config") or {}
    out: list[str] = []
    for key in ("Entrypoint", "Cmd"):
        value = cfg.get(key)
        if isinstance(value, list):
            out.append(" ".join(str(x) for x in value))
        elif value:
            out.append(str(value))
    out.extend(str(e) for e in (cfg.get("Env") or []))
    out.extend(f"{k}={v}" for k, v in (cfg.get("Labels") or {}).items())
    for step in config_json.get("history") or []:
        created_by = step.get("created_by")
        if created_by:
            out.append(str(created_by))
    return [s for s in out if s.strip()]


def scan_texts(texts: list[str]) -> list[ConfigSignal]:
    """Run every rule over a list of text strings; return deduped signals.

    Shared by Tier-1 (image config strings) and Tier-2 (unpacked layer file
    contents), so a config string and a baked-in file are scored identically.
    """
    signals: list[ConfigSignal] = []
    seen: set[tuple[str, str, str]] = set()
    for text in texts:
        for category, rule, _weight, pattern in _RULES:
            if not pattern.search(text):
                continue
            evidence = " ".join(text.split())[:200]
            key = (category, rule, evidence)
            if key in seen:
                continue
            seen.add(key)
            signals.append(ConfigSignal(category=category, rule=rule, evidence=evidence))
    return signals


def scan_config(config_json: dict) -> list[ConfigSignal]:
    """Run every Tier-1 rule over the image config strings; return deduped signals."""
    return scan_texts(strings_from_config(config_json))


def score_signals(signals: list[ConfigSignal]) -> int:
    """Weighted score over distinct (category, rule) pairs (spam-resistant)."""
    weights = {(c, r): w for c, r, w, _ in _RULES}
    distinct = {(s.category, s.rule) for s in signals}
    return sum(weights.get(pair, 1) for pair in distinct)
