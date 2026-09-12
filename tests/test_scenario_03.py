from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario


def test_scenario_03_finds_full_attack_path():
    nodes, edges = load_scenario("data/scenario_03.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    assert len(paths) == 1

    path = paths[0]

    assert path.nodes == (
        "user:low-priv-user",
        "resource:s3",
        "resource:web-app",
        "function:lambda",
        "credential:api-key",
        "credential:vault-token",
        "credential:ssh-key",
        "resource:ec2",
        "role:ec2-instance",
        "resource:dynamodb",
        "credential:iam-user",
        "secret:flag",
    )

    assert len(path.edges) == 11


def test_scenario_03_unknown_source_has_no_path():
    nodes, edges = load_scenario("data/scenario_03.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:does-not-exist"],
        targets=["secret:flag"],
    )

    assert paths == []
