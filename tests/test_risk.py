from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario
from cloudpath.risk import score_attack_path


def test_critical_secret_path_is_high_risk():
    nodes, edges = load_scenario("data/scenario_01.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:manager"],
        targets=["secret:flag"],
    )

    finding = score_attack_path(
        paths[0],
        target_sensitivity="critical",
    )

    assert finding.source == "user:manager"
    assert finding.target == "secret:flag"
    assert finding.path_length == 3
    assert finding.score == 100
    assert finding.severity == "critical"


def test_standard_resource_gets_lower_score():
    nodes, edges = load_scenario("data/scenario_01.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:manager"],
        targets=["secret:flag"],
    )

    finding = score_attack_path(
        paths[0],
        target_sensitivity="standard",
    )

    assert finding.score == 60
    assert finding.severity == "high"
