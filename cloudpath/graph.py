import networkx as nx

from cloudpath.models import Edge, Node


def build_graph(nodes: list[Node], edges: list[Edge]) -> nx.DiGraph:
    """
    Build a directed cloud-resource graph.

    Each node represents an identity, role, function, or resource.
    Each directed edge represents a permission or relationship.

    Raises:
        ValueError: If node identifiers are duplicated or an edge
                    references a node that does not exist.
    """
    graph = nx.DiGraph()

    node_ids = [node.node_id for node in nodes]

    if len(node_ids) != len(set(node_ids)):
        raise ValueError("Duplicate node identifiers detected.")

    known_nodes = set(node_ids)

    for node in nodes:
        if not node.node_id.strip():
            raise ValueError("Node identifiers cannot be empty.")

        graph.add_node(
            node.node_id,
            node_type=node.node_type.value,
            name=node.name,
            sensitivity=node.sensitivity,
        )

    for edge in edges:
        if edge.source not in known_nodes:
            raise ValueError(
                f"Edge references unknown source node: {edge.source}"
            )

        if edge.target not in known_nodes:
            raise ValueError(
                f"Edge references unknown target node: {edge.target}"
            )

        graph.add_edge(
            edge.source,
            edge.target,
            edge_type=edge.edge_type.value,
            permission=edge.permission,
        )

    return graph
