from cloudpath.analyzer import find_attack_paths
from cloudpath.baseline import analyze_individual_permissions
from cloudpath.loader import load_scenario
from cloudpath.report import format_finding
from cloudpath.risk import score_attack_path


def main():
    nodes, edges = load_scenario("data/scenario_02.json")

    print("=" * 60)
    print("CLOUDPATH EXPERIMENT 02")
    print("=" * 60)

    print("\nBASELINE: INDIVIDUAL PERMISSION ANALYSIS")
    print("-" * 60)

    baseline_findings = analyze_individual_permissions(edges)

    for finding in baseline_findings:
        print(
            f"{finding.permission}: "
            f"{finding.severity.upper()} "
            f"(score={finding.score})"
        )

    print("\nPATH-AWARE: CLOUDPATH")
    print("-" * 60)

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:low-priv-user"],
        targets=["secret:flag"],
    )

    target = next(
        node for node in nodes
        if node.node_id == "secret:flag"
    )

    for path in paths:
        finding = score_attack_path(
            path,
            target.sensitivity,
        )

        print(format_finding(finding, path))


if __name__ == "__main__":
    main()
