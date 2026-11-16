# CloudPath

## Context-Aware Cloud Attack-Path Risk Analysis

CloudPath is a Python prototype for analyzing multi-step cloud attack paths by representing identities, resources, credentials, and permissions as a directed graph.

The project explores a practical cloud-security question:

> When security findings are evaluated individually, can important multi-step attack paths become harder to prioritize than when permissions and resource relationships are represented as a graph?

This is an engineering prototype and evaluation project. It does **not** claim to replace AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or other commercial cloud-security platforms.

## What CloudPath Does

CloudPath takes a modeled cloud environment and:

1. Loads identities, resources, credentials, and relationships from JSON.
2. Builds a directed attack graph.
3. Discovers possible paths from an initial identity to a target resource.
4. Scores paths using contextual risk signals.
5. Reports the complete attack path rather than evaluating each relationship in isolation.
6. Measures path complexity across experiments.

### Architecture

```text
Scenario JSON
     │
     ▼
   Loader
     │
     ▼
 Graph Builder
     │
     ▼
Attack-Path Discovery
     │
     ▼
Context-Aware Risk Scoring
     │
     ├──────────────► Path Metrics
     │
     ▼
Security Finding / Report
     │
     ▼
Experiment Evaluation
```

## Security Concepts Demonstrated

The project focuses on practical cloud-security concepts, including:

- IAM privilege escalation
- Credential control
- Role assumption
- Credential pivots
- EC2 instance metadata credentials
- Lambda configuration exposure
- Secrets Manager access
- Multi-step attack paths
- Graph-based security analysis
- Risk prioritization
- Least-privilege analysis
- Cloud identity relationships

## Example Attack Path

One modeled scenario represents a path where a low-privileged identity can eventually reach a sensitive secret through multiple intermediate resources:

```text
Low-privileged identity
        │
        ▼
       EC2
        │
        ▼
  Instance role
        │
        ▼
     Lambda
        │
        ▼
   Credential
        │
        ▼
      Secret
```

The important part is not any single permission. The project evaluates the connected sequence as a security path.

## Experiments

Three locally modeled scenarios were evaluated.

| Experiment | Path length | Credential transitions | Highest individual baseline | CloudPath score | Severity |
|---|---:|---:|---:|---:|---|
| 01 | 3 | 1 | 50 | 100 | Critical |
| 02 | 5 | 2 | 50 | 125 | Critical |
| 03 | 11 | 5 | 50 | 125 | Critical |

Across all three modeled scenarios, the CloudPath path-aware score was higher than the strongest score produced by the project's hand-authored individual-permission baseline.

The differences were:

- Experiment 01: +50
- Experiment 02: +75
- Experiment 03: +75

These results are preliminary. They evaluate the prototype's scoring approach; they do not establish superior detection or real-world security effectiveness.

### Cross-Experiment Evaluation

The cross-experiment analysis consolidates the three experiment results and compares the individual-permission baseline with the contextual CloudPath scores.

The evaluation also records path length and other path characteristics separately, allowing the scoring model and path-complexity measurements to be examined independently.

## Evidence Boundary

The scenarios are locally modeled from publicly documented vulnerable-by-design cloud attack scenarios.

The project did not:

- Deploy CloudGoat infrastructure.
- Use real AWS credentials.
- Access a real AWS account.
- Attack real cloud infrastructure.
- Claim that AWS IAM Access Analyzer or Security Hub produced the project's baseline results.

The individual-permission baseline is hand-authored for this experiment.

Some labels in the modeled scenarios, such as Vault authentication, SSH login, and credential transitions, represent conceptual capabilities in an attack path. They are not claims that those capabilities correspond directly to AWS IAM permissions.

## Relationship to Existing Cloud Security Tools

Cloud-security platforms already provide sophisticated capabilities for identifying access, permissions, misconfigurations, and attack-related relationships.

For example:

- **AWS IAM Access Analyzer** can analyze external, internal, and unused access and evaluate access paths.
- **AWS Security Hub** can surface unused-access findings using IAM Access Analyzer.
- **Microsoft Defender for Cloud** provides cloud security posture management across supported cloud environments.

CloudPath is therefore positioned as a learning and engineering prototype for path-oriented risk analysis, rather than as a replacement for these platforms.

## Risk Scoring Model

CloudPath uses manually selected contextual risk signals to calculate a score for a discovered attack path.

The current model includes:

- Target resource sensitivity.
- IAM access-key creation permissions.
- Credential-control transitions.
- STS role assumption.
- EC2 instance metadata access.
- Lambda function configuration access.
- Secrets Manager access.

The model classifies scores using the following thresholds:

| Score | Severity |
|---|---|
| Below 30 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80 and above | Critical |

The scoring system is prototype-specific and has not been calibrated against production incident data.

## Limitations

The current prototype has several limitations.

### 1. Small Evaluation Set

Only three modeled attack scenarios are currently evaluated.

### 2. Hand-Authored Baseline

The baseline is intentionally simple and is not an implementation of AWS IAM Access Analyzer, Security Hub, or another commercial product.

### 3. Simplified Risk Model

The current scoring model uses manually selected risk signals. It is not calibrated against production incident data.

### 4. Path Complexity

Experiment 03 contains a longer path than Experiment 02 but currently receives the same CloudPath score. This shows that the current model does not yet explicitly reward or penalize additional path complexity.

The project therefore tracks path metrics separately:

- Path length
- Credential transitions
- Unique edge types
- Unique permissions

Future work can investigate a principled way to incorporate these metrics without artificially increasing the risk score simply because a path is longer.

## Project Structure

```text
CloudPath/
│
├── cloudpath/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── baseline.py
│   ├── graph.py
│   ├── loader.py
│   ├── metrics.py
│   ├── models.py
│   ├── report.py
│   └── risk.py
│
├── data/
│   ├── scenario_01.json
│   ├── scenario_02.json
│   └── scenario_03.json
│
├── docs/
│   └── SCENARIO_01.md
│
├── experiments/
│   ├── cross_experiment/
│   │   ├── EVALUATION.md
│   │   ├── path_metrics.txt
│   │   └── results.txt
│   │
│   ├── experiment_01/
│   │   ├── README.md
│   │   └── results.txt
│   │
│   ├── experiment_02/
│   │   ├── README.md
│   │   ├── results.txt
│   │   └── SCENARIO_02.md
│   │
│   ├── experiment_03/
│   │   ├── README.md
│   │   ├── results.txt
│   │   └── SCENARIO_03.md
│   │
│   ├── analyze_experiments.py
│   ├── analyze_path_metrics.py
│   ├── compare_01.py
│   ├── compare_02.py
│   ├── compare_03.py
│   └── run_scenario_01.py
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_baseline.py
│   ├── test_graph.py
│   ├── test_graph_module.py
│   ├── test_metrics.py
│   ├── test_risk.py
│   ├── test_risk_engine.py
│   ├── test_risk_scenario_02.py
│   ├── test_scenario_02.py
│   └── test_scenario_03.py
│
├── pyproject.toml
└── README.md
```

## Testing

The automated test suite covers:

- Graph construction and validation.
- Attack-path discovery.
- Risk scoring and severity classification.
- Scenario-specific behavior.
- Path metrics.
- Risk signal handling.

Run the test suite:

```powershell
pytest -q
```

Latest verified local result:

```text
33 passed in 0.33s
```

## Reproducing the Experiments

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install the project

```powershell
python -m pip install -e ".[dev]"
```

### 3. Run the tests

```powershell
pytest -q
```

### 4. Run the individual experiments

```powershell
python .\experiments\compare_01.py
python .\experiments\compare_02.py
python .\experiments\compare_03.py
```

### 5. Run the cross-experiment evaluation

```powershell
python .\experiments\analyze_experiments.py
```

### 6. Run the path-metrics analysis

```powershell
python .\experiments\analyze_path_metrics.py
```

Detailed experiment evidence is stored under the `experiments/` directory.

## Technology

- Python
- NetworkX
- pytest
- JSON
- Directed graphs
- Graph-based path analysis
- Automated testing

## Why I Built This

Cloud-security findings are often connected by identity, permission, credential, and resource relationships.

I built CloudPath to strengthen my practical understanding of:

- Cloud IAM
- Attack-path reasoning
- Least privilege
- Credential movement
- Graph modeling
- Security-risk prioritization
- Python security engineering

The project is part of my cybersecurity portfolio as a Computer Science graduate interested in cloud security, identity security, and AI security.

## Future Work

Potential engineering improvements include:

- Richer identity and resource models.
- More realistic permission semantics.
- Additional attack-path scenarios.
- Path-complexity scoring.
- Context-aware severity weighting.
- Attack-path deduplication.
- Explainable security findings.
- Visualization of attack graphs.
- Integration with synthetic cloud-configuration datasets.
- Comparison against additional public security-analysis approaches.

## Safety

CloudPath is designed for defensive security learning and local experimentation.

The included scenarios are modeled locally and do not require access to real cloud infrastructure or credentials.