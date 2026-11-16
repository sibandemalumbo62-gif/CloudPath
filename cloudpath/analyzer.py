from dataclasses import dataclass

import networkx as nx

from cloudpath.graph import build_graph
from cloudpath.models import Edge, Node


@dataclass(frozen=True)
class AttackPath:
    source: str
    target: str
    nodes: tuple[str, ...]
    edges: tuple[tuple[str, str, str, str], ...]


def find_attack_paths(
    nodes: list[Node],
    edges: list[Edge],
    sources: list[str],
    targets: list[str],
) -> list[AttackPath]:
    graph = build_graph(nodes, edges)

    paths: list[AttackPath] = []

    for source in sources:
        if source not in graph:
            continue

        for target in targets:
            if target not in graph:
                continue

            if not nx.has_path(graph, source, target):
                continue

            for node_path in nx.all_simple_paths(
                graph,
                source=source,
                target=target,
            ):
                path_edges = []

                for left, right in zip(node_path, node_path[1:]):
                    data = graph[left][right]

                    path_edges.append(
                        (
                            left,
                            right,
                            data["edge_type"],
                            data["permission"],
                        )
                    )

                paths.append(
                    AttackPath(
                        source=source,
                        target=target,
                        nodes=tuple(node_path),
                        edges=tuple(path_edges),
                    )
                )

    return paths
