from dataclasses import dataclass
from enum import Enum


class NodeType(str, Enum):
    USER = "user"
    ROLE = "role"
    FUNCTION = "function"
    RESOURCE = "resource"


class EdgeType(str, Enum):
    ASSUME_ROLE = "assume_role"
    CREDENTIAL_CONTROL = "credential_control"
    INVOKE = "invoke"
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Node:
    node_id: str
    node_type: NodeType
    name: str
    sensitivity: str = "unknown"


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    edge_type: EdgeType
    permission: str
