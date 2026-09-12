# Scenario 03 — CloudGoat secrets_in_the_cloud

## Source

CloudGoat by Rhino Security Labs.

Scenario:

`secrets_in_the_cloud`

## Scenario characteristics

Size: Large

Difficulty: Hard

Starting point: IAM user `low-priv-user`

Goal: Retrieve the final secret stored in AWS Secrets Manager.

## Documented route

The public scenario documentation describes a multi-service route:

1. Start as the low-privileged IAM user.
2. Discover an S3 bucket containing a URL to a web application hosted on EC2.
3. Enumerate the web application and discover an administrative page.
4. Discover information about environment variables and a HashiCorp endpoint.
5. Enumerate Lambda and discover the web application's API key.
6. Use the API key to obtain a HashiCorp Vault token.
7. Use the Vault token to obtain an SSH private key.
8. Use SSH access to reach the EC2 instance.
9. Query EC2 Instance Metadata Service.
10. Discover credentials through the metadata service.
11. Enumerate DynamoDB and discover IAM credentials.
12. Use the discovered IAM credentials to retrieve the final Secrets Manager secret.

## Evidence boundary

CloudPath is modeling the documented relationships locally.

No CloudGoat infrastructure is deployed by this experiment.

No AWS credentials are used.

The modeled graph represents the documented attack route at a conceptual level. It does not claim to reproduce every implementation detail of the live AWS environment.

## Purpose

Scenario 03 tests whether CloudPath can represent a longer attack path involving storage, web application information, Lambda, application credentials, Vault, EC2, instance metadata, DynamoDB, IAM credentials, and Secrets Manager.

This scenario is intentionally more complex than Experiments 01 and 02.
