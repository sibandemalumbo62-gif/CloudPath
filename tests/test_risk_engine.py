import pytest

from cloudpath.analyzer import AttackPath, find_attack_paths
from cloudpath.loader import load_scenario
from cloudpath.risk import (
    _classify_severity,
    score_attack_path,
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (29, "low"),
        (30, "medium"),
        (59, "medium"),
        (60, "high"),
        (79, "high"),
        (80, "critical"),
        (125, "critical"),
    ],
)
def test_severity_threshold_boundaries(score, expected):
    assert _classify_severity(score) == expected


def test_scenario_03_receives_expected_risk_score():
    nodes, edges = load_scenario("data/scenario_03.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    target = next(
        node for node in nodes
        if node.node_id == "secret:flag"
    )

    finding = score_attack_path(paths[0], target.sensitivity)

    assert finding.score == 125
    assert finding.severity == "critical"
    assert finding.path_length == 11


def test_multiple_credential_indicators_are_counted_once():
    path = AttackPath(
        source="user:developer",
        target="resource:target",
        nodes=("user:developer", "resource:target"),
        edges=(
            (
                "user:developer",
                "resource:target",
                "credential_control",
                "iam:CreateAccessKey",
            ),
        ),
    )

    finding = score_attack_path(path, "standard")

    assert finding.score == 30
    assert finding.severity == "medium"
    assert len(finding.reasons) == 2


def test_credential_control_reason_has_correct_wording():
    path = AttackPath(
        source="user:developer",
        target="resource:target",
        nodes=("user:developer", "resource:target"),
        edges=(
            (
                "user:developer",
                "resource:target",
                "credential_control",
                "custom:DiscoverCredential",
            ),
        ),
    )

    finding = score_attack_path(path, "standard")

    assert (
        "Path includes credential control or credential discovery."
        in finding.reasons
    )
