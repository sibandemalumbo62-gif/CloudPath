from dataclasses import dataclass

from cloudpath.analyzer import AttackPath


@dataclass(frozen=True)
class PathMetrics:
    path_length: int
    credential_transitions: int
    unique_edge_types: int
    unique_permissions: int


def measure_path(path: AttackPath) -> PathMetrics:
    permissions = {edge[3] for edge in path.edges}
    edge_types = {edge[2] for edge in path.edges}

    credential_transitions = sum(
        1
        for edge in path.edges
        if edge[2] == "credential_control"
    )

    return PathMetrics(
        path_length=len(path.edges),
        credential_transitions=credential_transitions,
        unique_edge_types=len(edge_types),
        unique_permissions=len(permissions),
    )
