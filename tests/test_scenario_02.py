from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario


def test_scenario_02_finds_full_attack_path():
    nodes, edges = load_scenario("data/scenario_02.json")

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
        "resource:ec2",
        "role:ec2-instance",
        "function:lambda",
        "credential:lambda-key",
        "secret:flag",
    )

    assert path.edges == (
        (
            "user:low-priv-user",
            "resource:ec2",
            "read",
            "ec2:Describe*",
        ),
        (
            "resource:ec2",
            "role:ec2-instance",
            "credential_control",
            "ec2:InstanceMetadata",
        ),
        (
            "role:ec2-instance",
            "function:lambda",
            "read",
            "lambda:ListFunctions",
        ),
        (
            "function:lambda",
            "credential:lambda-key",
            "credential_control",
            "lambda:GetFunctionConfiguration",
        ),
        (
            "credential:lambda-key",
            "secret:flag",
            "read",
            "secretsmanager:GetSecretValue",
        ),
    )


def test_scenario_02_unknown_source_has_no_path():
    nodes, edges = load_scenario("data/scenario_02.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:does-not-exist"],
        targets=["secret:flag"],
    )

    assert paths == []
