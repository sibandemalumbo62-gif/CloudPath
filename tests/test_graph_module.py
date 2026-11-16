import pytest

from cloudpath.graph import build_graph
from cloudpath.models import Edge, EdgeType, Node, NodeType


def test_build_graph_creates_directed_nodes_and_edges():
    nodes = [
        Node("user-1", NodeType.USER, "Developer"),
        Node("role-1", NodeType.ROLE, "Admin"),
    ]

    edges = [
        Edge(
            "user-1",
            "role-1",
            EdgeType.ASSUME_ROLE,
            "sts:AssumeRole",
        )
    ]

    graph = build_graph(nodes, edges)

    assert graph.is_directed()
    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1
    assert graph.nodes["user-1"]["node_type"] == "user"
    assert graph["user-1"]["role-1"]["permission"] == "sts:AssumeRole"


def test_build_graph_rejects_duplicate_node_identifiers():
    nodes = [
        Node("user-1", NodeType.USER, "Developer"),
        Node("user-1", NodeType.USER, "Another user"),
    ]

    with pytest.raises(ValueError, match="Duplicate node identifiers"):
        build_graph(nodes, [])


def test_build_graph_rejects_unknown_edge_source():
    nodes = [
        Node("user-1", NodeType.USER, "Developer"),
    ]

    edges = [
        Edge(
            "missing-user",
            "user-1",
            EdgeType.ASSUME_ROLE,
            "sts:AssumeRole",
        )
    ]

    with pytest.raises(ValueError, match="unknown source node"):
        build_graph(nodes, edges)


def test_build_graph_rejects_unknown_edge_target():
    nodes = [
        Node("user-1", NodeType.USER, "Developer"),
    ]

    edges = [
        Edge(
            "user-1",
            "missing-role",
            EdgeType.ASSUME_ROLE,
            "sts:AssumeRole",
        )
    ]

    with pytest.raises(ValueError, match="unknown target node"):
        build_graph(nodes, edges)

def test_build_graph_rejects_empty_node_identifier():
    nodes = [
        Node("", NodeType.USER, "Unnamed user"),
    ]

    with pytest.raises(ValueError, match="cannot be empty"):
        build_graph(nodes, [])
