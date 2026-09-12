from pathlib import Path
import re


EXPERIMENTS = [
    Path("experiments/experiment_01/results.txt"),
    Path("experiments/experiment_02/results.txt"),
]


def read_result_file(path):
    raw = path.read_bytes()

    # Handle common Windows/PowerShell encodings.
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-16")


def extract_results(path):
    text = read_result_file(path)

    baseline_section = text.split("PATH-AWARE: CLOUDPATH")[0]

    baseline_scores = [
        int(value)
        for value in re.findall(
            r"\(score=(\d+)\)",
            baseline_section,
        )
    ]

    if not baseline_scores:
        raise ValueError(
            f"Could not find baseline scores in {path}"
        )

    cloudpath_match = re.search(
        r"Severity:\s+(\w+).*?"
        r"Risk score:\s+(\d+).*?"
        r"Path length:\s+(\d+)",
        text,
        re.DOTALL,
    )

    if cloudpath_match is None:
        raise ValueError(
            f"Could not parse CloudPath result from {path}"
        )

    severity = cloudpath_match.group(1)
    cloudpath_score = int(cloudpath_match.group(2))
    path_length = int(cloudpath_match.group(3))

    return {
        "file": str(path),
        "baseline_scores": baseline_scores,
        "baseline_max": max(baseline_scores),
        "cloudpath_score": cloudpath_score,
        "severity": severity,
        "path_length": path_length,
    }


def main():
    results = [
        extract_results(path)
        for path in EXPERIMENTS
    ]

    print("=" * 70)
    print("CLOUDPATH CROSS-EXPERIMENT ANALYSIS")
    print("=" * 70)
    print()

    for index, result in enumerate(results, start=1):
        print(f"EXPERIMENT {index}")
        print("-" * 70)
        print(f"Source file: {result['file']}")
        print(f"Baseline scores: {result['baseline_scores']}")
        print(f"Baseline maximum: {result['baseline_max']}")
        print(f"CloudPath score: {result['cloudpath_score']}")
        print(f"CloudPath severity: {result['severity']}")
        print(f"Path length: {result['path_length']}")
        print()

    print("CROSS-EXPERIMENT COMPARISON")
    print("-" * 70)

    for index, result in enumerate(results, start=1):
        difference = (
            result["cloudpath_score"]
            - result["baseline_max"]
        )

        print(
            f"Experiment {index}: "
            f"CloudPath {result['cloudpath_score']} "
            f"- baseline max {result['baseline_max']} "
            f"= difference {difference}"
        )

    cloudpath_higher = all(
        result["cloudpath_score"] > result["baseline_max"]
        for result in results
    )

    print()

    if cloudpath_higher:
        print(
            "Observed pattern: CloudPath produced a higher "
            "risk score than the highest individual baseline "
            "finding in both experiments."
        )
    else:
        print(
            "Observed pattern: The same higher-score relationship "
            "was not observed in every experiment."
        )


if __name__ == "__main__":
    main()
