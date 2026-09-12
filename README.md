# CloudPath

## Context-Aware Cloud Attack-Path Risk Analysis

CloudPath is a Python prototype for analyzing multi-step cloud attack paths by representing identities, resources, credentials, and permissions as a directed graph.

The project explores a practical cloud-security question:

> When security findings are evaluated individually, can important multi-step attack paths become harder to prioritize than when permissions and resource relationships are represented as a graph?

This is an engineering prototype and evaluation project. It does **not** claim to replace AWS IAM Access Analyzer, AWS Security Hub, Microsoft Defender for Cloud, or other commercial cloud-security platforms.

---

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
Security Concepts Demonstrated

The project focuses on practical cloud-security concepts including:

IAM privilege escalation
Credential control
Role assumption
Credential pivots
EC2 instance metadata credentials
Lambda configuration exposure
Secrets Manager access
Multi-step attack paths
Graph-based security analysis
Risk prioritization
Least-privilege analysis
Cloud identity relationships
Example Attack Path

One modeled scenario represents a path where a low-privileged identity can eventually reach a sensitive secret through multiple intermediate resources:

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

The important part is not any single permission. The project evaluates the connected sequence as a security path.

Experiments

Three locally modeled scenarios were evaluated.

Experiment    Path length    Credential transitions    Highest individual baseline    CloudPath score    CloudPath severity
01    3    1    50    100    Critical
02    5    2    50    125    Critical
03    11    5    50    125    Critical

Across all three modeled scenarios, the CloudPath path-aware score was higher than the strongest score produced by the project's hand-authored individual-permission baseline.

The differences were:

Experiment 01: +50
Experiment 02: +75
Experiment 03: +75

These results are preliminary and are intended to evaluate the prototype's scoring approach, not to establish superiority over production cloud-security products.

Evidence Boundary

The scenarios are locally modeled from publicly documented vulnerable-by-design cloud attack scenarios.

The project did not:

deploy CloudGoat infrastructure;
use real AWS credentials;
access a real AWS account;
attack real cloud infrastructure;
claim that AWS IAM Access Analyzer or Security Hub produces the project's baseline results.

The individual-permission baseline is hand-authored for this experiment.

Some labels in the modeled scenarios, such as Vault authentication, SSH login, and credential transitions, represent conceptual capabilities in an attack path. They are not claims that those capabilities correspond directly to AWS IAM permissions.

Relationship to Existing Cloud Security Tools

Cloud security platforms already provide sophisticated capabilities for identifying access, permissions, misconfigurations, and attack-related relationships.

For example:

AWS IAM Access Analyzer can analyze external, internal, and unused access and evaluate access paths.
AWS Security Hub can surface unused-access findings using IAM Access Analyzer.
Microsoft Defender for Cloud provides cloud security posture management across supported cloud environments.

CloudPath is therefore positioned as a learning and engineering prototype for path-oriented risk analysis, rather than as a replacement for these platforms.

Limitations

The current prototype has several limitations.

1. Small evaluation set

Only three modeled attack scenarios are currently evaluated.

2. Hand-authored baseline

The baseline is intentionally simple and is not an implementation of AWS IAM Access Analyzer, Security Hub, or another commercial product.

3. Simplified risk model

The current scoring model uses manually selected risk signals. It is not calibrated against production incident data.

4. Path complexity

Experiment 03 contains a longer path than Experiment 02 but currently receives the same CloudPath score. This shows that the current model does not yet explicitly reward or penalize additional path complexity.

The project therefore tracks path metrics separately:

path length;
credential transitions;
unique edge types;
unique permissions.

Future work can investigate a principled way to incorporate these metrics without artificially increasing the risk score simply because a path is longer.

Project Structure
CloudPath/
├── cloudpath/
│   ├── analyzer.py
│   ├── cli.py
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
│
├── experiments/
│   ├── experiment_01/
│   ├── experiment_02/
│   ├── experiment_03/
│   ├── cross_experiment/
│   ├── analyze_experiments.py
│   ├── analyze_path_metrics.py
│   ├── compare_01.py
│   ├── compare_02.py
│   └── compare_03.py
│
├── tests/
│
├── pyproject.toml
└── README.md
Testing

The project currently has an automated test suite covering graph construction, attack-path discovery, risk scoring, scenario behavior, and path metrics.

Run:

pytest -q

Current local result:

17 passed
Reproduce the Experiments

Create and activate the virtual environment:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Install the project:

python -m pip install -e ".[dev]"

Run the tests:

pytest -q

Run the individual experiments:

python .\experiments\compare_01.py
python .\experiments\compare_02.py
python .\experiments\compare_03.py

Run the cross-experiment evaluation:

python .\experiments\analyze_experiments.py

Run the path-metrics analysis:

python .\experiments\analyze_path_metrics.py

Detailed experiment evidence is stored under:

experiments/
Technology
Python
NetworkX
pytest
JSON
Directed graphs
Graph-based path analysis
Automated testing
Why I Built This

Cloud security findings are often connected by identity, permission, credential, and resource relationships.

I built CloudPath to strengthen my practical understanding of:

cloud IAM;
attack-path reasoning;
least privilege;
credential movement;
graph modeling;
security-risk prioritization;
Python security engineering.

The project is part of my cybersecurity portfolio as a Computer Science graduate interested in cloud security, identity security, and AI security.

Future Work

Potential engineering improvements include:

richer identity and resource models;
more realistic permission semantics;
additional attack-path scenarios;
path-complexity scoring;
context-aware severity weighting;
attack-path deduplication;
explainable security findings;
visualization of attack graphs;
integration with synthetic cloud-configuration datasets;
comparison against additional public security-analysis approaches.
Safety

CloudPath is designed for defensive security learning and local experimentation.

The included scenarios are modeled locally and do not require access to real cloud infrastructure or credentials.
