# Experiment 02 — Multi-Service Credential Pivot

## Research question

When cloud security relationships span multiple services and credential pivots, does evaluating the connected attack path produce a different risk assessment than evaluating each relationship independently?

## Scenario

CloudGoat `data_secrets`.

The scenario was modeled locally from the publicly documented attack route.

The documented route crosses EC2, an EC2 instance role, Lambda, discovered credentials, and Secrets Manager.

## Approaches

### Baseline

Each modeled permission relationship is evaluated independently.

The baseline does not consider whether the relationships form one connected path from the starting identity to the final resource.

### CloudPath

CloudPath represents identities, cloud resources, roles, functions, credentials, and secrets as a directed graph.

It searches for connected paths from the starting identity to the target resource and evaluates the path as a whole.

## Evidence boundary

This experiment uses the locally modeled scenario data in:

`data/scenario_02.json`

The scenario was based on the publicly documented CloudGoat `data_secrets` route.

No CloudGoat infrastructure was deployed by this experiment.

No AWS credentials were used.

The graph represents the documented attack route at a conceptual level. Permission strings such as `ec2:Describe*`, `ec2:InstanceMetadata`, and `lambda:GetFunctionConfiguration` are modeling labels for the documented capabilities and pivots; they are not claims that these strings alone reproduce every implementation detail of the live scenario.

The baseline is a hand-authored comparison model. It is not an implementation of AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or another commercial security product.

## Results

The exact output produced by the experiment is stored in:

`experiments/experiment_02/results.txt`

Observed baseline results:

- `ec2:Describe*`: LOW, score 10
- `ec2:InstanceMetadata`: LOW, score 10
- `lambda:ListFunctions`: LOW, score 10
- `lambda:GetFunctionConfiguration`: LOW, score 10
- `secretsmanager:GetSecretValue`: HIGH, score 50

Observed CloudPath result:

- Severity: CRITICAL
- Risk score: 125
- Path length: 5 actions

Observed path:

`user:low-priv-user`

? `resource:ec2`

? `role:ec2-instance`

? `function:lambda`

? `credential:lambda-key`

? `secret:flag`

## Interpretation

In this modeled scenario, evaluating the relationships as a connected path produced a higher risk assessment than evaluating the same relationships independently.

The result demonstrates that the current CloudPath model can represent a multi-service credential-pivot path and combine several relationship signals into one path-level finding.

This is evidence from one modeled scenario and should not be generalized to all cloud environments or all security-analysis systems.

## Reproduction

From the project root:

```powershell
python .\experiments\compare_02.py
@'
# Experiment 02 — Multi-Service Credential Pivot

## Research question

When cloud security relationships span multiple services and credential pivots, does evaluating the connected attack path produce a different risk assessment than evaluating each relationship independently?

## Scenario

CloudGoat `data_secrets`.

The scenario was modeled locally from the publicly documented attack route.

The documented route crosses EC2, an EC2 instance role, Lambda, discovered credentials, and Secrets Manager.

## Approaches

### Baseline

Each modeled permission relationship is evaluated independently.

The baseline does not consider whether the relationships form one connected path from the starting identity to the final resource.

### CloudPath

CloudPath represents identities, cloud resources, roles, functions, credentials, and secrets as a directed graph.

It searches for connected paths from the starting identity to the target resource and evaluates the path as a whole.

## Evidence boundary

This experiment uses the locally modeled scenario data in:

`data/scenario_02.json`

The scenario was based on the publicly documented CloudGoat `data_secrets` route.

No CloudGoat infrastructure was deployed by this experiment.

No AWS credentials were used.

The graph represents the documented attack route at a conceptual level. Permission strings such as `ec2:Describe*`, `ec2:InstanceMetadata`, and `lambda:GetFunctionConfiguration` are modeling labels for the documented capabilities and pivots; they are not claims that these strings alone reproduce every implementation detail of the live scenario.

The baseline is a hand-authored comparison model. It is not an implementation of AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or another commercial security product.

## Results

The exact output produced by the experiment is stored in:

`experiments/experiment_02/results.txt`

Observed baseline results:

- `ec2:Describe*`: LOW, score 10
- `ec2:InstanceMetadata`: LOW, score 10
- `lambda:ListFunctions`: LOW, score 10
- `lambda:GetFunctionConfiguration`: LOW, score 10
- `secretsmanager:GetSecretValue`: HIGH, score 50

Observed CloudPath result:

- Severity: CRITICAL
- Risk score: 125
- Path length: 5 actions

Observed path:

`user:low-priv-user`

? `resource:ec2`

? `role:ec2-instance`

? `function:lambda`

? `credential:lambda-key`

? `secret:flag`

## Interpretation

In this modeled scenario, evaluating the relationships as a connected path produced a higher risk assessment than evaluating the same relationships independently.

The result demonstrates that the current CloudPath model can represent a multi-service credential-pivot path and combine several relationship signals into one path-level finding.

This is evidence from one modeled scenario and should not be generalized to all cloud environments or all security-analysis systems.

## Reproduction

From the project root:

```powershell
python .\experiments\compare_02.py

To save the output:

python .\experiments\compare_02.py | Tee-Object .\experiments\experiment_02\results.txt

