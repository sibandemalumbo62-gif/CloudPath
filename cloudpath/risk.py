from dataclasses import dataclass

from cloudpath.models import Edge
from cloudpath.analyzer import AttackPath


@dataclass(frozen=True)
class RiskFinding:
    source: str
    target: str
    severity: str
    score: int
    path_length: int
    reasons: tuple[str, ...]


def score_attack_path(path: AttackPath, target_sensitivity: str) -> RiskFinding:
    score = 0
    reasons = []

    # Target sensitivity
    if target_sensitivity == "critical":
        score += 50
        reasons.append("Path reaches a critical resource.")
    elif target_sensitivity == "sensitive":
        score += 30
        reasons.append("Path reaches a sensitive resource.")
    else:
        score += 10
        reasons.append("Path reaches a standard resource.")

    # Permission and relationship signals
    permissions = {edge[3] for edge in path.edges}
    edge_types = {edge[2] for edge in path.edges}

    # IAM credential-control capability
    if "iam:CreateAccessKey" in permissions:
        score += 20
        reasons.append("Path includes credential control over another identity.")

    # Generic credential-control relationship
    if "credential_control" in edge_types:
        if "Path includes credential control over another identity." not in reasons:
            score += 20
            reasons.append("Path includes credential control or credential discovery.")

    # Role assumption
    if "sts:AssumeRole" in permissions:
        score += 15
        reasons.append("Path includes role assumption.")

    # EC2 metadata credential pivot
    if "ec2:InstanceMetadata" in permissions:
        score += 20
        reasons.append("Path includes an EC2 metadata credential pivot.")

    # Lambda credential discovery
    if "lambda:GetFunctionConfiguration" in permissions:
        score += 20
        reasons.append("Path includes Lambda configuration credential discovery.")

    # Secrets Manager access
    if any(permission.startswith("secretsmanager:") for permission in permissions):
        score += 15
        reasons.append("Path includes access to Secrets Manager.")

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return RiskFinding(
        source=path.source,
        target=path.target,
        severity=severity,
        score=score,
        path_length=len(path.edges),
        reasons=tuple(reasons),
    )
