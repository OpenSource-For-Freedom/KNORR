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
    # Project's own README/INSTALL/NEWS/AUTHORS (prose, not payload)
    "src/README.txt",
    "home/miner/xmrig/README.md",
    "src/INSTALL",
    "project/NEWS",
    "project/AUTHORS",
    # GNU autotools generated boilerplate
    "src/config.sub",
    "src/config.guess",
    # CMake's own build-system bookkeeping
    "home/miner/xmrig/build/xmrig-cuda/build/CMakeCache.txt",
    "home/miner/xmrig/build/xmrig-cuda/build/CMakeFiles/xmrig-cu.dir/link.txt",
    # Stock package/OS files whose default content coincidentally matches
    "etc/ssh/ssh_config",
    "etc/ssh/sshd_config",
    "etc/protocols",
    "etc/services",
    "usr/bin/catchsegv",
    "usr/bin/fakeroot-sysv",
    "usr/bin/fakeroot-tcp",
    # Protobuf-compiler-generated code (mechanical enum/data dumps)
    "usr/local/app/pogo/POGOProtos/Enums/PokemonClass_pb2.py",
    "src/api_pb2_grpc.py",
    # XMRig's own shipped example/template scripts (placeholder syntax) and
    # its own donation-mechanism source
    "home/miner/xmrig/scripts/pool_mine_example.cmd",
    "home/miner/xmrig/scripts/solo_mine_example.cmd",
    "home/miner/xmrig/src/donate.h",
    "home/miner/xmrig/src/donate.cpp",
    # Vendored third-party code directories
    "sqlmap/thirdparty/chardet/big5freq.py",
    "sqlmap/thirdparty/fcrypt/fcrypt.py",
    "app/3rdparty/lib.js",
    # sqlmap's own wordlist and default config template
    "sqlmap/data/txt/smalldict.txt",
    "sqlmap/sqlmap.conf",
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
    # A real payload config, not GNU config.sub/guess or CMake bookkeeping
    "opt/miner/config.json",
    "home/user/config.sh",
    # An actual SSH private key / non-stock sshd path, not the stock templates
    "root/.ssh/id_rsa",
    "home/user/.ssh/authorized_keys",
    "opt/app/sshd_config",  # not under etc/ssh/
    # A dropped script that merely borrows a stock-sounding name/dir, not the
    # exact stock binary path
    "usr/bin/fakeroot-evil.sh",
    "usr/local/bin/catchsegv",
    # A filename that merely contains "example"/"donate" as a substring, not
    # the exact stock XMRig template/donation-source pattern
    "opt/miner/example_config.json",
    "opt/miner/donate.sh",
    # A filename that merely contains "thirdparty" as a substring, not an
    # actual thirdparty/ directory component
    "opt/miner/thirdparty_backdoor.sh",
    # A data/txt/ path NOT under sqlmap's own tree
    "opt/data/txt/malicious.txt",
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
