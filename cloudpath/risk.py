from dataclasses import dataclass

from cloudpath.analyzer import AttackPath


# Risk scoring weights
CRITICAL_TARGET_SCORE = 50
SENSITIVE_TARGET_SCORE = 30
STANDARD_TARGET_SCORE = 10

CREDENTIAL_CONTROL_SCORE = 20
ROLE_ASSUMPTION_SCORE = 15
EC2_METADATA_SCORE = 20
LAMBDA_CONFIGURATION_SCORE = 20
SECRETS_MANAGER_SCORE = 15


# Severity classification thresholds
CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30


@dataclass(frozen=True)
class RiskFinding:
    source: str
    target: str
    severity: str
    score: int
    path_length: int
    reasons: tuple[str, ...]


def _score_target_sensitivity(sensitivity: str) -> tuple[int, str]:
    """Return the risk score and explanation for target sensitivity."""

    if sensitivity == "critical":
        return (
            CRITICAL_TARGET_SCORE,
            "Path reaches a critical resource.",
        )

    if sensitivity == "sensitive":
        return (
            SENSITIVE_TARGET_SCORE,
            "Path reaches a sensitive resource.",
        )

    return (
        STANDARD_TARGET_SCORE,
        "Path reaches a standard resource.",
    )


def _score_permission_signals(
    permissions: set[str],
    edge_types: set[str],
) -> tuple[int, list[str]]:
    """Calculate additional risk from permissions and relationships."""

    score = 0
    reasons = []

    # Count credential control once, even if multiple indicators exist.
    has_iam_key_creation = "iam:CreateAccessKey" in permissions
    has_credential_control = "credential_control" in edge_types

    if has_iam_key_creation or has_credential_control:
        score += CREDENTIAL_CONTROL_SCORE

        if has_iam_key_creation:
            reasons.append(
                "Path includes credential control over another identity."
            )
        else:
            reasons.append(
                "Path includes credential control or credential discovery."
            )

    if "sts:AssumeRole" in permissions:
        score += ROLE_ASSUMPTION_SCORE
        reasons.append("Path includes role assumption.")

    if "ec2:InstanceMetadata" in permissions:
        score += EC2_METADATA_SCORE
        reasons.append("Path includes an EC2 metadata credential pivot.")

    if "lambda:GetFunctionConfiguration" in permissions:
        score += LAMBDA_CONFIGURATION_SCORE
        reasons.append(
            "Path includes Lambda configuration credential discovery."
        )

    if any(
        permission.startswith("secretsmanager:")
        for permission in permissions
    ):
        score += SECRETS_MANAGER_SCORE
        reasons.append("Path includes access to Secrets Manager.")

    return score, reasons


def _classify_severity(score: int) -> str:
    """Map a numeric risk score to its severity classification."""

    if score >= CRITICAL_THRESHOLD:
        return "critical"

    if score >= HIGH_THRESHOLD:
        return "high"

    if score >= MEDIUM_THRESHOLD:
        return "medium"

    return "low"


def score_attack_path(
    path: AttackPath,
    target_sensitivity: str,
) -> RiskFinding:
    """Calculate an explainable risk finding for an attack path."""

    score, target_reason = _score_target_sensitivity(
        target_sensitivity
    )

    reasons = [target_reason]

    permissions = {edge[3] for edge in path.edges}
    edge_types = {edge[2] for edge in path.edges}

    permission_score, permission_reasons = _score_permission_signals(
        permissions,
        edge_types,
    )

    score += permission_score
    reasons.extend(permission_reasons)

    return RiskFinding(
        source=path.source,
        target=path.target,
        severity=_classify_severity(score),
        score=score,
        path_length=len(path.edges),
        reasons=tuple(reasons),
    )
