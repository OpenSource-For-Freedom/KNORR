"""Regression tests for Tier-2 layer path ignore rules.

Each test below corresponds to a false-positive that was observed in production
and fixed by adding the relevant path to _IGNORE_LAYER_PATH.
"""

from __future__ import annotations

import pytest

from knorr.scanning.tier2 import _IGNORE_LAYER_PATH

# ---------------------------------------------------------------------------
# Paths that MUST be ignored (vendor / SDK / prose / test files)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    # Go standard library — contains binary test vectors that fire shellcode-blob
    "usr/local/go/src/compress/zlib/reader_test.go",
    "usr/local/go/src/encoding/base64/base64_test.go",
    "usr/local/go/src/net/http/http_test.go",
    # Generic Go test files anywhere (suffix _test.go)
    "app/internal/crypto/aes_test.go",
    "home/user/project/cmd/server_test.go",
    # Standard OS vendor paths
    "usr/share/locale/en/LC_MESSAGES/libc.mo",
    "usr/lib/x86_64-linux-gnu/libssl.so.3",
    "usr/lib64/libz.so.1",
    "usr/include/openssl/evp.h",
    "usr/src/linux-headers-6.1/include/linux/types.h",
    "usr/local/lib/python3.12/dist-packages/pip/__init__.py",
    "lib/x86_64-linux-gnu/libc.so.6",
    "lib64/ld-linux-x86-64.so.2",
    "var/lib/dpkg/info/base-files.list",
    # Node module docs / tests
    "node_modules/express/docs/api.md",
    "node_modules/lodash/test/test.js",
    # Perl unicode tables
    "usr/lib/perl5/unicore/lib/Jt/C.pl",
    "perl5/site_perl/unicore/UnicodeData.txt",
    # Man pages and docs
    "usr/share/man/man1/gcc.1",
    "usr/share/doc/libssl-dev/changelog.gz",
    # Copyright / changelog / license
    "usr/share/doc/openssl/copyright",
    "usr/share/doc/curl/changelog.Debian.gz",
])
def test_ignored_vendor_paths(path):
    assert _IGNORE_LAYER_PATH.search(path) is not None, (
        f"Expected {path!r} to be ignored but it wasn't")


# ---------------------------------------------------------------------------
# Paths that must NOT be ignored (actual payload locations)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    # User-space scripts in /app, /opt, /srv, /root, /tmp, /home
    "app/scripts/start.sh",
    "opt/miner/xmrig",
    "opt/miner/config.json",
    "srv/api/entrypoint.sh",
    "root/.bashrc",
    "tmp/payload.py",
    "home/user/miner.sh",
    # Baked-in config files
    "etc/cron.d/mining",
    "etc/profile.d/miner.sh",
    "etc/ld.so.preload",
    # Named executables in /usr/local/bin (not under go/ or lib/)
    "usr/local/bin/xmrig",
    "usr/local/bin/start.sh",
    # Python scripts (not in site-packages)
    "usr/local/scripts/run.py",
    # Docker entrypoint wrapper
    "docker-entrypoint.sh",
    "entrypoint.sh",
])
def test_payload_paths_not_ignored(path):
    assert _IGNORE_LAYER_PATH.search(path) is None, (
        f"Expected {path!r} NOT to be ignored but it was")


# ---------------------------------------------------------------------------
# Specific regression: Go SDK zlib test file that caused the isukim FP
# ---------------------------------------------------------------------------

def test_go_sdk_zlib_test_ignored():
    """usr/local/go/src/compress/zlib/reader_test.go must be ignored.

    This file contains compressed binary test vectors that triggered
    shellcode-blob on the isukim/kargos-agent cluster (score 75 FP).
    """
    path = "usr/local/go/src/compress/zlib/reader_test.go"
    assert _IGNORE_LAYER_PATH.search(path) is not None


def test_go_test_suffix_ignored():
    """Any _test.go file must be ignored regardless of location."""
    assert _IGNORE_LAYER_PATH.search("app/crypto/cipher_test.go") is not None
    assert _IGNORE_LAYER_PATH.search("some/deep/path/util_test.go") is not None


def test_go_non_test_source_not_ignored():
    """A real Go source file (not a test file) outside usr/local/go must be scannable."""
    # Source checked into the image (not the SDK) is payload territory
    assert _IGNORE_LAYER_PATH.search("app/main.go") is None
    assert _IGNORE_LAYER_PATH.search("srv/worker/handler.go") is None
