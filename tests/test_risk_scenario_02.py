from cloudpath.loader import load_scenario
from cloudpath.analyzer import find_attack_paths
from cloudpath.risk import score_attack_path


def test_scenario_02_critical_secret_path():
    nodes, edges = load_scenario("data/scenario_02.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    path = paths[0]

    target = next(
        node for node in nodes
        if node.node_id == "secret:flag"
    )

    finding = score_attack_path(
        path,
        target.sensitivity,
    )

    assert finding.source == "user:low-priv-user"
    assert finding.target == "secret:flag"
    assert finding.severity == "critical"
    assert finding.score >= 80
    assert finding.path_length == 5


def test_scenario_02_risk_reasons_include_credential_pivots():
    nodes, edges = load_scenario("data/scenario_02.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    path = paths[0]

    target = next(
        node for node in nodes
        if node.node_id == "secret:flag"
    )

    finding = score_attack_path(
        path,
        target.sensitivity,
    )

    reasons = " ".join(finding.reasons)

    assert "critical resource" in reasons
    assert "credential control" in reasons
    assert "Secrets Manager" in reasons
