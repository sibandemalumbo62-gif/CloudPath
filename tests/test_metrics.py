from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario
from cloudpath.metrics import measure_path


def test_scenario_01_path_metrics():
    nodes, edges = load_scenario("data/scenario_01.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:manager"],
        targets=["secret:flag"],
    )

    metrics = measure_path(paths[0])

    assert metrics.path_length == 3
    assert metrics.credential_transitions == 1
    assert metrics.unique_edge_types == 3
    assert metrics.unique_permissions == 3


def test_scenario_02_path_metrics():
    nodes, edges = load_scenario("data/scenario_02.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    metrics = measure_path(paths[0])

    assert metrics.path_length == 5
    assert metrics.credential_transitions == 2
    assert metrics.unique_edge_types == 2
    assert metrics.unique_permissions == 5


def test_scenario_03_path_metrics():
    nodes, edges = load_scenario("data/scenario_03.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    metrics = measure_path(paths[0])

    assert metrics.path_length == 11
    assert metrics.credential_transitions == 5
    assert metrics.unique_edge_types == 2
    assert metrics.unique_permissions == 11
