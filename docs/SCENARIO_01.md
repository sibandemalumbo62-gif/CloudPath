# CloudPath Real-World Scenario 01

## Source

CloudGoat - iam_privesc_by_key_rotation

Source:
https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/cloudgoat/scenarios/aws/iam_privesc_by_key_rotation/README.md

## Scenario

The scenario starts with an IAM user named `manager`.

The documented goal is to retrieve a secret from AWS Secrets Manager.

The documented privilege-escalation route involves:

1. Starting as the `manager` user.
2. Manipulating the `admin` user's credentials.
3. Obtaining access as the `admin` user.
4. Assuming the Secrets Manager role using MFA.
5. Retrieving the secret.

## Why this scenario matters

The security impact does not come from one isolated permission alone.

The attack depends on a sequence of capabilities and identity transitions.

CloudPath will model these relationships as a graph and investigate whether attack-path analysis can make the combined security impact easier to understand and prioritize.

## Evidence boundary

This document describes the publicly documented CloudGoat scenario.

We have not independently reproduced the AWS exploitation path yet.

No experimental results are claimed at this stage.

## Project question

Can graph-based analysis expose the relationship between individual cloud permissions and a multi-step privilege-escalation path more clearly than evaluating permissions as isolated findings?
