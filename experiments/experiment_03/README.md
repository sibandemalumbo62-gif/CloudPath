# Experiment 03 — Long Multi-Service Attack Path

## Research question

When a cloud attack path spans many services and credential transitions, does representing the connected path provide a different risk assessment than evaluating the individual relationships independently?

## Scenario

CloudGoat `secrets_in_the_cloud`.

The scenario was modeled locally from the publicly documented attack route.

The documented route crosses S3, an EC2-hosted web application, Lambda, application credentials, HashiCorp Vault, SSH access, EC2 metadata, DynamoDB, IAM credentials, and Secrets Manager.

## Approaches

### Baseline

Each modeled permission relationship is evaluated independently.

The baseline does not consider whether the relationships form one connected path from the starting identity to the final resource.

### CloudPath

CloudPath represents identities, resources, functions, roles, and credentials as a directed graph.

It searches for connected paths from the starting identity to the target resource and evaluates the path as a whole.

## Evidence boundary

This experiment uses the locally modeled scenario data in:

`data/scenario_03.json`

The scenario was based on the publicly documented CloudGoat `secrets_in_the_cloud` route.

No CloudGoat infrastructure was deployed by this experiment.

No AWS credentials were used.

The graph represents the documented attack route at a conceptual level.

Modeling labels such as `vault:Authenticate`, `vault:ReadSecret`, and `ssh:Login` represent capabilities or transitions in the modeled attack path. They are not claims that these strings are AWS IAM permissions.

The baseline is a hand-authored comparison model. It is not an implementation of AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or another commercial security product.

## Results

The exact output produced by the experiment is stored in:

`experiments/experiment_03/results.txt`

Observed baseline results:

- Most modeled relationships: LOW, score 10
- `secretsmanager:GetSecretValue`: HIGH, score 50

Observed CloudPath result:

- Severity: CRITICAL
- Risk score: 125
- Path length: 11 actions

Observed path:

`user:low-priv-user` ? `resource:s3` ? `resource:web-app` ? `function:lambda` ? `credential:api-key` ? `credential:vault-token` ? `credential:ssh-key` ? `resource:ec2` ? `role:ec2-instance` ? `resource:dynamodb` ? `credential:iam-user` ? `secret:flag`

## Interpretation

In this modeled scenario, evaluating the connected path produced a higher risk assessment than evaluating the individual relationships independently.

The experiment also exposes a limitation of the current scoring model: the 11-action path received the same score as the shorter five-action path in Experiment 02.

This indicates that the current model captures several important risk categories but does not yet explicitly model additional path complexity.

This limitation is recorded rather than hidden.

The result should not be interpreted as proof that CloudPath is superior to existing cloud security products.

## Reproduction

From the project root:

```powershell
python .\experiments\compare_03.py
@'
# Experiment 03 — Long Multi-Service Attack Path

## Research question

When a cloud attack path spans many services and credential transitions, does representing the connected path provide a different risk assessment than evaluating the individual relationships independently?

## Scenario

CloudGoat `secrets_in_the_cloud`.

The scenario was modeled locally from the publicly documented attack route.

The documented route crosses S3, an EC2-hosted web application, Lambda, application credentials, HashiCorp Vault, SSH access, EC2 metadata, DynamoDB, IAM credentials, and Secrets Manager.

## Approaches

### Baseline

Each modeled permission relationship is evaluated independently.

The baseline does not consider whether the relationships form one connected path from the starting identity to the final resource.

### CloudPath

CloudPath represents identities, resources, functions, roles, and credentials as a directed graph.

It searches for connected paths from the starting identity to the target resource and evaluates the path as a whole.

## Evidence boundary

This experiment uses the locally modeled scenario data in:

`data/scenario_03.json`

The scenario was based on the publicly documented CloudGoat `secrets_in_the_cloud` route.

No CloudGoat infrastructure was deployed by this experiment.

No AWS credentials were used.

The graph represents the documented attack route at a conceptual level.

Modeling labels such as `vault:Authenticate`, `vault:ReadSecret`, and `ssh:Login` represent capabilities or transitions in the modeled attack path. They are not claims that these strings are AWS IAM permissions.

The baseline is a hand-authored comparison model. It is not an implementation of AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or another commercial security product.

## Results

The exact output produced by the experiment is stored in:

`experiments/experiment_03/results.txt`

Observed baseline results:

- Most modeled relationships: LOW, score 10
- `secretsmanager:GetSecretValue`: HIGH, score 50

Observed CloudPath result:

- Severity: CRITICAL
- Risk score: 125
- Path length: 11 actions

Observed path:

`user:low-priv-user` ? `resource:s3` ? `resource:web-app` ? `function:lambda` ? `credential:api-key` ? `credential:vault-token` ? `credential:ssh-key` ? `resource:ec2` ? `role:ec2-instance` ? `resource:dynamodb` ? `credential:iam-user` ? `secret:flag`

## Interpretation

In this modeled scenario, evaluating the connected path produced a higher risk assessment than evaluating the individual relationships independently.

The experiment also exposes a limitation of the current scoring model: the 11-action path received the same score as the shorter five-action path in Experiment 02.

This indicates that the current model captures several important risk categories but does not yet explicitly model additional path complexity.

This limitation is recorded rather than hidden.

The result should not be interpreted as proof that CloudPath is superior to existing cloud security products.

## Reproduction

From the project root:

```powershell
python .\experiments\compare_03.py

To save the output:

python .\experiments\compare_03.py | Tee-Object .\experiments\experiment_03\results.txt

