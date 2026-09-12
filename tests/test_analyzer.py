from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario


def test_manager_can_reach_secret():
    nodes, edges = load_scenario("data/scenario_01.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:manager"],
        targets=["secret:flag"],
    )

    assert len(paths) == 1

    path = paths[0]

    assert path.nodes == (
        "user:manager",
        "user:admin",
        "role:secretsmanager",
        "secret:flag",
    )

    assert path.edges[0][2] == "credential_control"
    assert path.edges[0][3] == "iam:CreateAccessKey"

    assert path.edges[1][2] == "assume_role"
    assert path.edges[1][3] == "sts:AssumeRole"

    assert path.edges[2][2] == "read"
    assert path.edges[2][3] == "secretsmanager:GetSecretValue"


def test_unconnected_identity_has_no_path():
    nodes, edges = load_scenario("data/scenario_01.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:unknown"],
        targets=["secret:flag"],
    )

    assert paths == []
