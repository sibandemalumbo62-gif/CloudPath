# Experiment 01 — Individual Findings vs Attack-Path Analysis

## Research question

When cloud security permissions are evaluated individually, does adding relationship and attack-path context change the resulting risk assessment?

## Scenario

CloudGoat `iam_privesc_by_key_rotation`.

The scenario was modeled locally from the publicly documented scenario relationships.

## Approaches

### Baseline

Each permission relationship is evaluated independently.

The baseline does not consider whether multiple permissions form a connected path.

### CloudPath

CloudPath represents identities, roles, and resources as a directed graph and searches for connected paths from the starting identity to the target resource.

The path is then evaluated as a whole.

## Evidence boundary

This experiment uses the locally modeled scenario data in:

`data/scenario_01.json`

It does not claim that the experiment reproduces AWS IAM Access Analyzer, AWS Security Hub, or another commercial security product.

## Results

The exact output produced by the experiment is stored in:

`experiments/experiment_01/results.txt`

No results are manually entered into this document.

## Interpretation

Interpretation will be based on the recorded output rather than assumed before running the experiment.

## Reproduction

From the project root:

```powershell
python .\experiments\compare_01.py

To save the output:

python .\experiments\compare_01.py | Tee-Object .\experiments\experiment_01\results.txt

