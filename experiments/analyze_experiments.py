from pathlib import Path
import re


EXPERIMENTS = [
    Path("experiments/experiment_01/results.txt"),
    Path("experiments/experiment_02/results.txt"),
    Path("experiments/experiment_03/results.txt"),
]

OUTPUT_FILE = Path("experiments/cross_experiment/results.txt")


def read_result_file(path: Path) -> str:
    raw = path.read_bytes()

    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")

    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-16")


def extract_results(path: Path) -> dict:
    text = read_result_file(path)
    baseline_section = text.split("PATH-AWARE: CLOUDPATH")[0]

    baseline_scores = [
        int(value)
        for value in re.findall(r"\(score=(\d+)\)", baseline_section)
    ]

    if not baseline_scores:
        raise ValueError(f"Could not find baseline scores in {path}")

    match = re.search(
        r"Severity:\s+(\w+).*?"
        r"Risk score:\s+(\d+).*?"
        r"Path length:\s+(\d+)",
        text,
        re.DOTALL,
    )

    if match is None:
        raise ValueError(f"Could not parse CloudPath result from {path}")

    return {
        "file": str(path),
        "baseline_scores": baseline_scores,
        "baseline_max": max(baseline_scores),
        "cloudpath_score": int(match.group(2)),
        "severity": match.group(1),
        "path_length": int(match.group(3)),
    }


def main() -> None:
    results = [extract_results(path) for path in EXPERIMENTS]
    lines = [
        "=" * 70,
        "CLOUDPATH CROSS-EXPERIMENT ANALYSIS",
        "=" * 70,
        "",
    ]

    for index, result in enumerate(results, start=1):
        lines.extend([
            f"EXPERIMENT {index:02d}",
            "-" * 70,
            f"Source file: {result['file']}",
            f"Baseline scores: {result['baseline_scores']}",
            f"Baseline maximum: {result['baseline_max']}",
            f"CloudPath score: {result['cloudpath_score']}",
            f"CloudPath severity: {result['severity'].upper()}",
            f"Path length: {result['path_length']}",
            "",
        ])

    lines.extend([
        "CROSS-EXPERIMENT COMPARISON",
        "-" * 70,
    ])

    for index, result in enumerate(results, start=1):
        difference = result["cloudpath_score"] - result["baseline_max"]

        lines.append(
            f"Experiment {index:02d}: "
            f"CloudPath {result['cloudpath_score']} "
            f"- baseline max {result['baseline_max']} "
            f"= difference {difference}"
        )

    all_higher = all(
        result["cloudpath_score"] > result["baseline_max"]
        for result in results
    )

    lines.append("")

    if all_higher:
        lines.append(
            f"Observed pattern: CloudPath produced a higher risk score "
            f"than the highest individual baseline finding in all "
            f"{len(results)} modeled experiments."
        )
    else:
        lines.append(
            "Observed pattern: CloudPath did not produce a higher "
            "risk score than the individual baseline in every experiment."
        )

    lines.extend([
        "",
        "EVIDENCE LIMITATION",
        "-" * 70,
        "The baseline is hand-authored and is not a commercial cloud-security product.",
        "Results are limited to the locally modeled scenarios and current scoring rules.",
        "Higher scores do not establish superior detection or real-world security effectiveness.",
    ])

    output = "\n".join(lines) + "\n"

    print(output)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(output, encoding="utf-8")

    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
