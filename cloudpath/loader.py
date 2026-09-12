import json
from pathlib import Path

from cloudpath.models import Edge, EdgeType, Node, NodeType


def load_scenario(path: str | Path) -> tuple[list[Node], list[Edge]]:
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    nodes = [
        Node(
            node_id=item["node_id"],
            node_type=NodeType(item["node_type"]),
            name=item["name"],
            sensitivity=item.get("sensitivity", "unknown"),
        )
        for item in data["nodes"]
    ]

    edges = [
        Edge(
            source=item["source"],
            target=item["target"],
            edge_type=EdgeType(item["edge_type"]),
            permission=item["permission"],
        )
        for item in data["edges"]
    ]

    return nodes, edges
