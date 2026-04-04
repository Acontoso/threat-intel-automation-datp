# Threat Intel Automation

Containerized threat-intel ingestion service that pulls indicators from Anomali and pushes controls into:

- Microsoft Defender for Endpoint (file hash IOCs)
- Cisco Umbrella (domain IOCs)

The service is exposed via FastAPI and is deployed to AWS ECS Fargate using Terraform.

## High-Level Flow

1. API call hits webhook endpoint.
2. Orchestrator loads credentials (SSM + KMS decrypt), with in-memory TTL cache.
3. Service clients pull indicators from Anomali.
4. Microsoft and Cisco integrations run concurrently.
5. JSON logs are emitted to stdout for ECS/CloudWatch.

## API

- Health: `GET /health`
- Trigger ingestion: `POST /webhook/ingest`

Example request:

```bash
curl -X POST http://localhost:8000/webhook/ingest \
	-H "Content-Type: application/json" \
	-d '{
		"hours_back": 12,
		"run_microsoft": true,
		"run_cisco": true
	}'
```

If `WEBHOOK_SHARED_SECRET` is set, include header `X-Webhook-Secret` with matching value.

## Local Run

```bash
python -m code.main
```

## Configuration

Runtime configuration is defined in `code/config.py` and supports environment-variable overrides, including:

- `AWS_REGION`
- `THREAT_INTEL_CONFIDENCE`
- `SECRET_CACHE_TTL_SECONDS`
- `MS_CLIENT_ID`, `MS_TENANT_ID`
- `UMBRELLA_KEY`, `UMBRELLA_SECRET`
- `ANOMALI_USERNAME`, `ANOMALI_APIKEY`
- `WEBHOOK_SHARED_SECRET`

## AWS and Terraform Assumptions

This repository intentionally assumes core landing-zone and shared dependencies already exist.

Expected pre-existing infrastructure:

- VPC and private subnets for ECS tasks
- Security groups aligned to app ingress/egress policy
- ALB and target group (for service/webhook routing)
- AWS Private CA (for Service Connect / TLS dependencies)
- IAM OIDC trust and roles for GitHub Actions
- Terraform backend resources (S3 state bucket and DynamoDB lock table)

Terraform in this repo focuses on the application layer (task definition, service wiring, IAM, parameters), not foundational networking.

## Secrets and Parameters

Sensitive values are stored in SSM Parameter Store (SecureString), encrypted with KMS. These values are double encrypted and SSM will store an encrypted base64 output that will be decrypted at runtime.

```bash
aws kms encrypt --key-id <kms key id> --plaintext fileb://<(echo -n 'secret') --output text --query

aws kms decrypt --ciphertext-blob "" --output text --query Plaintext | base64 --decode
```

## CI/CD and Release Strategy

The pipeline is designed to avoid unnecessary SemVer increments while still keeping full traceability.

### Build and Publish

On merge to `main`, the deploy workflow:

1. Builds the container image.
2. Pushes to ECR tagged with `github.sha`.
3. Captures image digest (`sha256:...`).
4. Signs the image.

### Deploy

Terraform plan/apply consume the artifact identity from the publish job.

- Deployment uses image digest for ECS task definition when provided.
- This gives immutable runtime behavior, regardless of later tag aliasing.

### Release (SemVer)

After successful deploy, release job:

1. Runs semantic-release to compute and publish SemVer tag.
2. Retags the already-published SHA image in ECR to the SemVer tag.
3. Writes run summary containing:
	 - SemVer tag
	 - Source SHA tag
	 - Image digest

Key point: SemVer is a promotion label over an existing immutable image, not a rebuild trigger.

## Repository Structure

- `code/` application code (API, orchestrator, services, models, utils)
- `terraform/` infrastructure code and variables
- `.github/workflows/` CI/CD workflows
- `tests/` unit tests

## Operational Notes

- ECS logs are JSON formatted for better ingestion/search in CloudWatch.
- Microsoft IOC expiry is set in code to manage indicator quota over time.
- Credential cache in orchestrator reduces SSM calls and API latency.
