"""Tests for data models (ImageFinding, DetectionMethod, FindingStatus)."""


from knorr.models import DetectionMethod, FindingStatus, ImageFinding


def test_image_finding_defaults():
    f = ImageFinding(image="ns/repo")
    assert f.image == "ns/repo"
    assert f.reference == "latest"
    assert f.status == FindingStatus.CANDIDATE
    assert f.score == 0
    assert f.signals == []
    assert f.osm_tags == []
    assert f.confirming == []
    assert f.evidence == {}


def test_namespace_property():
    assert ImageFinding(image="teamtnt/foo").namespace == "teamtnt"
    assert ImageFinding(image="library/alpine").namespace == "library"


def test_add_signals_deduplication():
    f = ImageFinding(image="ns/img")
    f.add_signals([("cryptomining", "miner-binary"), ("c2", "bash-tcp")])
    assert "cryptomining/miner-binary" in f.signals
    assert "c2/bash-tcp" in f.signals
    # duplicates are ignored
    before = list(f.signals)
    f.add_signals([("cryptomining", "miner-binary")])
    assert f.signals == before


def test_add_signals_sorted():
    f = ImageFinding(image="ns/img")
    f.add_signals([("z-cat", "z-rule"), ("a-cat", "a-rule")])
    assert f.signals == sorted(f.signals)


def test_detection_method_values():
    assert DetectionMethod.OSM_CONTAINER == "osm_container"


def test_finding_status_values():
    assert FindingStatus.CANDIDATE == "candidate"
    assert FindingStatus.CONFIRMED == "confirmed"
    assert FindingStatus.REMOVED == "removed"
    assert FindingStatus.REJECTED == "rejected"
    assert FindingStatus.SCREENED == "screened"


def test_image_finding_with_all_fields():
    f = ImageFinding(
        image="evil/miner",
        reference="sha256:abc123",
        digest="sha256:abc123",
        detection_method=DetectionMethod.PUBLISHER_PIVOT,
        status=FindingStatus.CONFIRMED,
        score=15,
        signals=["cryptomining/miner-binary"],
        reasoning="Confirmed cryptojacker",
        publisher="evil",
        pull_count=99000,
        osm_severity="high",
        osm_tags=["cryptojacking", "teamtnt"],
        attribution="teamtnt",
        tier="A:cryptojacking",
        confirming=[{"category": "cryptomining", "rule": "miner-binary", "evidence": "xmrig"}],
        evidence={"iocs": {"pools": ["pool.supportxmr.com"]}},
    )
    assert f.namespace == "evil"
    assert "cryptomining/miner-binary" in f.signals
    assert f.tier == "A:cryptojacking"
