from pathlib import Path

from cloudpath.loader import load_scenario
from cloudpath.models import EdgeType, NodeType


SCENARIO_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "scenario_01.json"
)


def test_scenario_loads():
    nodes, edges = load_scenario(SCENARIO_PATH)

    assert len(nodes) == 4
    assert len(edges) == 3


def test_scenario_contains_manager_and_admin():
    nodes, _ = load_scenario(SCENARIO_PATH)

    node_ids = {node.node_id for node in nodes}

    assert "user:manager" in node_ids
    assert "user:admin" in node_ids


def test_scenario_contains_privilege_transition():
    _, edges = load_scenario(SCENARIO_PATH)

    edge_types = {edge.edge_type for edge in edges}

    assert EdgeType.CREDENTIAL_CONTROL in edge_types
    assert EdgeType.ASSUME_ROLE in edge_types
    assert EdgeType.READ in edge_types
