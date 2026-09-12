from cloudpath.baseline import analyze_individual_permissions
from cloudpath.loader import load_scenario


def test_baseline_analyzes_each_permission_individually():
    nodes, edges = load_scenario("data/scenario_01.json")

    findings = analyze_individual_permissions(edges)

    assert len(findings) == 3

    permissions = {
        finding.permission
        for finding in findings
    }

    assert permissions == {
        "iam:CreateAccessKey",
        "sts:AssumeRole",
        "secretsmanager:GetSecretValue",
    }
