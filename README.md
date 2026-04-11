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
The following assumptions around landing zone and core infrastructure in AWS are:
- VPC and auxilliary VPC services that enable public & private subnets across all availability zones across region are deployed.
- AWS private CA configured to enable ECS service connect mesh, ensures transport encryption between ALB & ECS service running strands AI agent.
- KMS keys used to encrypt artefacts such as SSM parameters, and ECR images.
- The bedrock components (AWS provider not mature yet - Agentcore Memory, Model ARN & Guardrails). Build these outside of terraform and reference in variables.
