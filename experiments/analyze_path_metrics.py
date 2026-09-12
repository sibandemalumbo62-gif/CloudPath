from pathlib import Path

from cloudpath.analyzer import find_attack_paths
from cloudpath.loader import load_scenario
from cloudpath.metrics import measure_path


SCENARIOS = [
    (
        "Experiment 01",
        "data/scenario_01.json",
        "user:manager",
        "secret:flag",
    ),
    (
        "Experiment 02",
        "data/scenario_02.json",
        "user:low-priv-user",
        "secret:flag",
    ),
    (
        "Experiment 03",
        "data/scenario_03.json",
        "user:low-priv-user",
        "secret:flag",
    ),
]


def main():
    lines = []

    lines.append("=" * 70)
    lines.append("CLOUDPATH CROSS-EXPERIMENT PATH METRICS")
    lines.append("=" * 70)
    lines.append("")

    for name, scenario_file, source, target in SCENARIOS:
        nodes, edges = load_scenario(scenario_file)

        paths = find_attack_paths(
            nodes,
            edges,
            sources=[source],
            targets=[target],
        )

        if not paths:
            raise ValueError(f"No path found for {name}")

        metrics = measure_path(paths[0])

        lines.append(name)
        lines.append("-" * 70)
        lines.append(f"Path length: {metrics.path_length}")
        lines.append(
            f"Credential transitions: "
            f"{metrics.credential_transitions}"
        )
        lines.append(
            f"Unique edge types: "
            f"{metrics.unique_edge_types}"
        )
        lines.append(
            f"Unique permissions: "
            f"{metrics.unique_permissions}"
        )
        lines.append("")

    output = "\n".join(lines)

    print(output)

    Path(
        "experiments/cross_experiment/path_metrics.txt"
    ).write_text(
        output,
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
