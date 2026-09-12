from dataclasses import dataclass

from cloudpath.models import Edge


@dataclass(frozen=True)
class BaselineFinding:
    source: str
    target: str
    permission: str
    severity: str
    score: int


def analyze_individual_permissions(
    edges: list[Edge],
) -> list[BaselineFinding]:
    findings: list[BaselineFinding] = []

    for edge in edges:
        score = 0

        if edge.permission == "iam:CreateAccessKey":
            score = 40
        elif edge.permission == "sts:AssumeRole":
            score = 30
        elif edge.permission == "secretsmanager:GetSecretValue":
            score = 50
        else:
            score = 10

        if score >= 50:
            severity = "high"
        elif score >= 30:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            BaselineFinding(
                source=edge.source,
                target=edge.target,
                permission=edge.permission,
                severity=severity,
                score=score,
            )
        )

    return findings
