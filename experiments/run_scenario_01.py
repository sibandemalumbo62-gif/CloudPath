from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario
from cloudpath.report import format_finding
from cloudpath.risk import score_attack_path


def main() -> None:
    nodes, edges = load_scenario("data/scenario_01.json")

    paths = find_attack_paths(
        nodes,
        edges,
        sources=["user:manager"],
        targets=["secret:flag"],
    )

    if not paths:
        print("No attack paths found.")
        return

    target = next(
        node
        for node in nodes
        if node.node_id == "secret:flag"
    )

    finding = score_attack_path(
        paths[0],
        target_sensitivity=target.sensitivity,
    )

    print(format_finding(finding, paths[0]))


if __name__ == "__main__":
    main()
