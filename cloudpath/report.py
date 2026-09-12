from cloudpath.analyzer import AttackPath
from cloudpath.risk import RiskFinding


def format_attack_path(path: AttackPath) -> str:
    lines = [path.source]

    for source, target, edge_type, permission in path.edges:
        lines.append(
            f"  +- {permission} [{edge_type}] ? {target}"
        )

    return "\n".join(lines)


def format_finding(
    finding: RiskFinding,
    path: AttackPath,
) -> str:
    lines = [
        "CLOUDPATH SECURITY FINDING",
        "=" * 28,
        "",
        f"Source: {finding.source}",
        f"Target: {finding.target}",
        f"Severity: {finding.severity.upper()}",
        f"Risk score: {finding.score}",
        f"Path length: {finding.path_length} actions",
        "",
        "Attack path:",
        format_attack_path(path),
        "",
        "Reasons:",
    ]

    for reason in finding.reasons:
        lines.append(f"- {reason}")

    return "\n".join(lines)
