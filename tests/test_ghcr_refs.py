"""Tests for GHCR image-reference discovery (GitHub code search, all mocked).

GHCR has no keyword-search API, so this mines GitHub code for
``ghcr.io/<owner>/<image>`` references naming a malicious term -- the GHCR
analog of ``hub_search``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from knorr.scanning.ghcr_refs import search_ghcr_image_refs


def _make_client(search_results: list[dict], contents: dict[str, str]) -> MagicMock:
    """A fake GitHubClient: search_code returns `search_results` for every
    query; get_content looks up by "repo:path" key in `contents`."""
    client = MagicMock()
    client.search_code.return_value = search_results
    client.get_content.side_effect = (
        lambda repo, path, ref=None: contents.get(f"{repo}:{path}"))
    return client


def test_finds_ghcr_ref_naming_the_search_term():
    hits = [{"repository": {"full_name": "evil/compose"}, "path": "docker-compose.yml"}]
    contents = {"evil/compose:docker-compose.yml": 'image: "ghcr.io/evilorg/xmrig:latest"'}
    client = _make_client(hits, contents)
    out = search_ghcr_image_refs(client, terms=("xmrig",), pace=0)
    assert len(out) == 1
    assert out[0]["image"] == "ghcr.io/evilorg/xmrig"
    assert out[0]["publisher"] == "evilorg"


def test_precision_filter_drops_ref_not_naming_the_term():
    """A file matched the search query (mentions "xmrig" AND "ghcr.io"
    somewhere), but the extracted ghcr.io reference itself is unrelated
    (e.g. a comment mentions xmrig while the image is a webapp) -- must be
    dropped, mirroring hub_search's name-based precision."""
    hits = [{"repository": {"full_name": "org/repo"}, "path": "k8s.yaml"}]
    contents = {"org/repo:k8s.yaml":
                "# uses xmrig for benchmarking\nimage: ghcr.io/myorg/webapp:1.0"}
    client = _make_client(hits, contents)
    out = search_ghcr_image_refs(client, terms=("xmrig",), pace=0)
    assert out == []


def test_dedupes_same_ref_across_files():
    hits = [
        {"repository": {"full_name": "a/repo"}, "path": "Dockerfile"},
        {"repository": {"full_name": "b/repo"}, "path": "compose.yml"},
    ]
    contents = {
        "a/repo:Dockerfile": "FROM ghcr.io/evilorg/xmrig:latest",
        "b/repo:compose.yml": "image: ghcr.io/evilorg/xmrig",
    }
    client = _make_client(hits, contents)
    out = search_ghcr_image_refs(client, terms=("xmrig",), pace=0)
    assert len(out) == 1


def test_skips_files_already_known_at_image_level():
    hits = [{"repository": {"full_name": "evil/compose"}, "path": "docker-compose.yml"}]
    contents = {"evil/compose:docker-compose.yml": "image: ghcr.io/evilorg/xmrig:latest"}
    client = _make_client(hits, contents)
    out = search_ghcr_image_refs(client, terms=("xmrig",), pace=0,
                                 known={"ghcr.io/evilorg/xmrig"})
    assert out == []


def test_no_content_is_skipped_gracefully():
    hits = [{"repository": {"full_name": "org/repo"}, "path": "Dockerfile"}]
    client = _make_client(hits, {})  # get_content returns None (file unreadable)
    out = search_ghcr_image_refs(client, terms=("xmrig",), pace=0)
    assert out == []


def test_multiple_terms_each_query_the_search_api():
    client = _make_client([], {})
    search_ghcr_image_refs(client, terms=("xmrig", "cpuminer"), pace=0)
    assert client.search_code.call_count == 2
    queries = [c.args[0] for c in client.search_code.call_args_list]
    assert '"ghcr.io" "xmrig"' in queries
    assert '"ghcr.io" "cpuminer"' in queries


def test_case_insensitive_term_match_in_ref():
    hits = [{"repository": {"full_name": "org/repo"}, "path": "Dockerfile"}]
    contents = {"org/repo:Dockerfile": "FROM ghcr.io/EvilOrg/XMRig:latest"}
    client = _make_client(hits, contents)
    out = search_ghcr_image_refs(client, terms=("xmrig",), pace=0)
    assert len(out) == 1
    assert out[0]["image"] == "ghcr.io/evilorg/xmrig"
