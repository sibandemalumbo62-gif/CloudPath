# Scenario 02 — CloudGoat data_secrets

## Source

CloudGoat by Rhino Security Labs.

Scenario:

`data_secrets`

## Scenario characteristics

Size: Small

Difficulty: Easy

Starting point: IAM user with limited permissions

Goal: Retrieve the final secret stored in AWS Secrets Manager.

## Documented route

The public scenario documentation describes the following route:

1. Start with limited IAM credentials.
2. Enumerate permissions and discover the ability to read EC2 attributes.
3. Inspect EC2 User Data and discover hardcoded credentials.
4. Use those credentials to access the EC2 instance.
5. Query the EC2 Instance Metadata Service and obtain credentials for the attached IAM role.
6. Use those credentials to enumerate Lambda functions.
7. Discover hardcoded AWS access keys in Lambda environment variables.
8. Use the discovered credentials to retrieve the final Secrets Manager secret.

## Evidence boundary

CloudPath is modeling the documented relationships locally.

No CloudGoat infrastructure is deployed by this experiment.

No AWS credentials are used.

The modeled graph represents the documented attack route, not a claim that every implementation detail of a live AWS environment has been reproduced.

## Purpose

Scenario 02 tests whether CloudPath's path-aware analysis remains useful when the attack path contains multiple cloud services and credential pivots rather than primarily IAM identity relationships.
