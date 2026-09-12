# CloudPath Evaluation

## Purpose

CloudPath is a local prototype for context-aware cloud attack-path risk analysis.

The project evaluates whether representing cloud identities, resources, credentials, and relationships as a connected graph can expose risk that is less apparent when modeled relationships are evaluated independently.

## Research question

When cloud security relationships are evaluated individually, can important multi-step attack paths become harder to prioritize than when permissions and resource relationships are represented as a graph?

## Evidence boundary

This evaluation uses locally modeled scenarios derived from publicly documented CloudGoat attack routes.

No CloudGoat infrastructure was deployed.

No AWS credentials were used.

The baseline is a hand-authored comparison model. It is not an implementation of AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or another commercial security product.

CloudPath results therefore demonstrate behavior of this prototype rather than superiority over commercial security products.

## Scenarios

### Experiment 01 — IAM privilege escalation

Source scenario:

CloudGoat `iam_privesc_by_key_rotation`.

The documented scenario starts with the `manager` IAM user and reaches a Secrets Manager secret through manipulation of another IAM user's credentials and role assumption.

CloudPath modeled the route as a three-action graph.

Observed path length:

3 actions

Observed credential transitions:

1

Observed CloudPath result:

- Risk score: 100
- Severity: CRITICAL

Highest baseline finding:

- Score: 50
- Severity: HIGH

### Experiment 02 — Multi-service credential pivot

Source scenario:

CloudGoat `data_secrets`.

The documented route begins with a limited IAM user and crosses EC2, an instance role, Lambda, discovered credentials, and Secrets Manager.

CloudPath modeled the route as a five-action graph.

Observed path length:

5 actions

Observed credential transitions:

2

Observed CloudPath result:

- Risk score: 125
- Severity: CRITICAL

Highest baseline finding:

- Score: 50
- Severity: HIGH

### Experiment 03 — Long multi-service credential chain

Source scenario:

CloudGoat `secrets_in_the_cloud`.

The documented route crosses S3, an EC2-hosted web application, Lambda, application credentials, HashiCorp Vault, SSH, EC2 metadata, DynamoDB, IAM credentials, and Secrets Manager.

CloudPath modeled the route as an eleven-action graph.

Observed path length:

11 actions

Observed credential transitions:

5

Observed CloudPath result:

- Risk score: 125
- Severity: CRITICAL

Highest baseline finding:

- Score: 50
- Severity: HIGH

## Cross-experiment observations

| Experiment | Path length | Credential transitions | Highest baseline score | CloudPath score | CloudPath severity |
|---|---:|---:|---:|---:|---|
| 01 | 3 | 1 | 50 | 100 | Critical |
| 02 | 5 | 2 | 50 | 125 | Critical |
| 03 | 11 | 5 | 50 | 125 | Critical |

Across all three modeled scenarios, the path-aware analysis produced a higher risk score than the highest individual baseline finding.

The difference between the path-aware result and the strongest individual baseline finding was:

- Experiment 01: +50
- Experiment 02: +75
- Experiment 03: +75

## Important limitation

Experiment 03 revealed an important limitation in the current scoring model.

Although Experiment 03 contains an eleven-action path and five credential transitions, its score is the same as Experiment 02:

- Experiment 02: 125
- Experiment 03: 125

Therefore, the current scoring model does not explicitly increase risk based on additional path complexity.

The project records this as a limitation rather than artificially increasing the score.

## Path metrics

CloudPath now records structural path metrics independently from the risk score:

- path length
- number of credential transitions
- number of unique edge types
- number of unique permissions

These metrics provide additional evidence about attack-path complexity without assuming that longer paths are automatically more dangerous.

## Preliminary conclusion

Across three locally modeled scenarios, CloudPath successfully represented and discovered connected attack paths from starting identities to sensitive or critical resources.

In each experiment, the connected-path analysis produced a higher risk assessment than the strongest individual baseline finding.

The experiments also identified a limitation: the current risk model recognizes several important risk categories but does not yet explicitly account for additional path complexity.

These results are preliminary and limited to three modeled scenarios and a hand-authored baseline.

They do not establish that CloudPath is superior to existing cloud security products.

## Next evaluation step

The next development step is to determine whether path-complexity signals can be incorporated into the risk model in a principled way.

Any scoring change should be tested against all three existing scenarios and should not be introduced merely to make longer paths receive higher scores.

