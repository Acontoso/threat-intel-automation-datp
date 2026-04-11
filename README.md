# Threat Intel Automation

FastAPI service for streaming threat-intelligence analysis with Strands Agents, Amazon Bedrock, and Amazon Bedrock AgentCore Memory.

The service:

- Authenticates callers with Microsoft Entra ID access tokens
- Extracts actor identity from token claims
- Persists conversation state through AgentCore Memory session management
- Streams model output back to clients in real time
- Uses external threat-intel tools (Open Source Malware and Recorded Future)

## Architecture

1. Client sends a request to the streaming endpoint.
2. FastAPI validates the Entra Bearer token.
3. App extracts actor ID from token (`oid`, fallback `sub`).
4. Session ID is resolved from `X-Session-Id` header or generated server-side.
5. A Strands `Agent` is built with:
   - shared startup clients (model + tool clients)
   - request-scoped AgentCore memory session manager (`memory_id`, `session_id`, `actor_id`)
6. Response is streamed token-by-token to the caller.

## API

### POST `/threat-intel-streaming`

Streams a threat-intelligence response.

Headers:

- `Authorization: Bearer <entra_access_token>` (required)
- `X-Session-Id: <session-id>` (optional, recommended for continuity)

Request body:

```json
{
  "prompt": "Check if package requests==2.32.4 from pypi & if malicious, and summarize risks"
}
```

Response:

- `text/plain` streaming body
- Response headers include:
  - `X-Session-Id`
  - `X-Actor-Id`

Example:

```bash
curl -N -X POST http://localhost:8000/threat-intel-streaming \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: session-123" \
  -d '{"prompt":"Analyze IOC 1.2.3.4 and summarize severity"}'
```

## Authentication

Authentication is implemented as a FastAPI dependency and validates:

- JWT signature via Entra JWKS
- issuer (`https://login.microsoftonline.com/<tenant>/v2.0`)
- audience against allowed audiences
- token subject/identity claims

Actor ID is derived from token claims and used as `actor_id` for memory session isolation.

## Session and Memory Model

- `memory_id`: static resource ID from AgentCore Memory (`AGENTCORE_MEMORY_SHORT_ID`)
- `session_id`: client conversation ID (`X-Session-Id`) or generated UUID
- `actor_id`: authenticated user identity from token claims

An AWS bedrock Agentcore managed memory object is created for short-term memory. This will keep the session & actor historic interactions with the agent for a set defined duration of days. This is passed into the runtime environment variables and when agent is initialised, will reference the memory object/Event objects that are linked to the session & actor ID. The session ID is dervied from the consumer application, whilst the actor object is specific towards the Entra ID user object ID, that links the identity to the session for short-term memory per session & interaction with agent.

## Bedrock Model & GuardRails

AWS Bedrock Guardrails act as a safety layer between an application and an AI model, controlling both what goes into the model (inputs) and what comes out (outputs).

They provide several types of controls:

- Content filters: Detect and block harmful content (e.g. hate, violence, sexual content, insults, misconduct, prompt attacks).
- Denied topics: Let you define specific topics to be avoided
- Word filters: Block or flag specific words or phrases (e.g. profanity, offensive terms).
- Sensitive information filters: Detect and block or mask sensitive data (like PII & PHI).

## Infrastructure

This service is designed to run on AWS ECS Fargate behind an ALB, with TLS-enabled ECS Service Connect and externalized runtime configuration.

### Runtime Topology

- **ALB -> ECS Service (Fargate)** for external ingress and container runtime.
- **ECS Service Connect** for service-to-service routing and mTLS in the service mesh.
- **CloudWatch Logs** for application and Service Connect logs.
- **SSM Parameter Store + KMS** for encrypted runtime secrets.
- **Amazon Bedrock + AgentCore Memory** for model inference, guardrails, and short-term session memory.

### Terraform Scope In This Repository

Terraform in this repo manages the application layer:

- ECS task definition and IAM task/execution roles
- ECS service deployment configuration
- Service Connect namespace/logging/tls wiring
- SSM parameter resources (module-driven)

Foundational components are expected to exist already:

- VPC, subnets, route tables, NAT/egress paths
- Security group baselines and ALB listeners
- ECS cluster
- AWS Private CA
- KMS keys for SSM/ECR/Service Connect TLS
- Terraform backend resources (S3 state bucket, lock table)

### Security Controls

- **Identity and Access**: ECS task and execution roles are separated by responsibility.
- **Secrets**: Sensitive values should be stored in SSM SecureString encrypted by KMS.
- **Transport Security**: Service Connect uses Private CA-issued certificates and KMS key material.
- **Model Safety**: Bedrock Guardrails are configured and passed at runtime.

### Bedrock / AgentCore Dependencies

Current AWS provider maturity means some AI resources are created outside Terraform and referenced as inputs:

- `bedrock_model_arn`
- `bedrock_agentcore_memory_arn`
- `bedrock_guardrail_arn`
- `AGENTCORE_MEMORY_SHORT_ID` runtime env value

### Key Infrastructure Inputs

Important variables for deployment include:

- compute/networking: `service_desired_count`, `subnet_ids`, `security_group_id`, `container_port`
- service mesh: `service_discovery_namespace_name`, `service_discovery_name`, `client_alias_dns_name`
- tls/logging: `aws_private_ca_arn`, `ca_cmk_kms_key_alias`, `ecs_service_logs_prefix`
- image/runtime: `ecr_registry`, `image_repo_name`, `image_tag` or `image_digest`

## CI/CD Process

The recommended CI/CD flow is **build once, promote immutably**.

### 1. Continuous Integration (Pull Request)

On PRs:

- run linting and formatting checks
- run unit tests
- run Terraform validation (`terraform fmt -check`, `terraform validate`)
- optionally run security scans (dependency and image scan)

Goal: block merge if quality/security gates fail.

### 2. Build and Publish (Main Branch)

On merge to `main`:

1. Build Docker image.
2. Push image to ECR with commit SHA tag.
3. Capture immutable image digest (`sha256:...`).
4. Publish deployment metadata (digest, tag, commit).

Use the image **digest** for deployments to guarantee immutable runtime behavior.

### 3. Deploy (Terraform Apply)

Deployment job should:

1. Download build metadata from the publish step.
2. Run Terraform plan/apply with environment-specific variables.
3. Inject image digest and runtime inputs (Bedrock ARNs, memory IDs, auth env vars).
4. Wait for ECS service stabilization.

ECS circuit breaker should remain enabled for automatic rollback on failed deployments.

### 4. Release / Promotion

If you use semantic versioning:

- create SemVer tag **after successful deploy**
- retag already-published digest in ECR

This preserves traceability and avoids rebuilding artifacts for release labels.

### 5. Post-Deploy Verification

Minimum smoke checks:

- health or readiness endpoint (if exposed)
- authenticated call to `/threat-intel-streaming`
- CloudWatch log ingestion and error-rate checks
- service desired/running task count convergence

### 6. Rollback Strategy

- Prefer rollback by reverting ECS task definition image digest to last known-good release.
- Keep previous N deployment digests indexed in release metadata.
- Use Terraform state + deployment metadata as source of truth for recovery.
