import os
from contextlib import asynccontextmanager
from uuid import uuid4
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from strands import Agent
from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig
from bedrock_agentcore.memory.integrations.strands.session_manager import AgentCoreMemorySessionManager

from code.middleware.reqlogging import RequestResponseLoggingMiddleware

from .middleware.auth import AuthContext, AuthMiddleware, require_scopes
from .tools.clients import AppClients, create_app_clients


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.clients = await create_app_clients()
    try:
        yield
    finally:
        await app.state.clients.aclose()


app = FastAPI(title="Threat Intel Automation API", version="1.0", lifespan=lifespan)
app.add_middleware(AuthMiddleware)
THREAT_INTEL_REQUIRED_SCOPES = {
    scope.strip()
    for scope in os.getenv("THREAT_INTEL_REQUIRED_SCOPES", "ThreatIntel.Read").split(",")
    if scope.strip()
}
THREAT_INTEL_SYSTEM_PROMPT = """You are a cyber security threat intelligence agent. Your main capabilities are:

1. Check to see if open source packages have been compromised by utilising the tool check_open_source tool
2. Enrich indicators of compromise by utilising the following tools depending on the type of the indicator:
- For IP addresses, use the enrich_ip tool
- For domain names, use the enrich_domain tool
- For file hashes, use the enrich_hash tool

When displaying responses back to requesting services:
- Format threat intelligence data in a human-readable way
- Highlight important information like indicators of compromise, threat levels, and alerts
- Handle errors appropriately
- Don't ask follow-up questions

Always explain the threat intelligence findings clearly and provide context for the analysis.
"""
app.add_middleware(RequestResponseLoggingMiddleware)

class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1)


def build_threat_intel_agent(session_id: str, actor_id: str, clients: AppClients) -> Agent:
    agentcore_memory_short = AgentCoreMemoryConfig(
        memory_id=clients.agentcore_memory_short_id,
        session_id=session_id,
        actor_id=actor_id,
    )
    session_manager = AgentCoreMemorySessionManager(
        agentcore_memory_config=agentcore_memory_short,
        region_name=clients.region,
    )
    agent = Agent(
        model=clients.bedrock_model,
        system_prompt=THREAT_INTEL_SYSTEM_PROMPT,
        tools=[clients.opensource_client.search_package, clients.recordedfuture_client.search_malware, clients.recordedfuture_client.search_ioc, clients.recordedfuture_client.search_sandbox],
        session_manager=session_manager,
        trace_attributes={
            "session.id": session_id,
            "user.id": actor_id,
        },
    )

    return agent


async def run_threat_intel_agent_and_stream_response(
    prompt: str,
    session_id: str,
    actor_id: str,
    clients: AppClients,
):
    agent = build_threat_intel_agent(session_id=session_id, actor_id=actor_id, clients=clients)

    async for item in agent.stream_async(prompt):
        if "data" in item:
            yield item["data"]


@app.post("/threat-intel-streaming")
async def get_threat_intel_streaming(
    request: PromptRequest,
    http_request_context: Request, # The request object that contains global app storage and clients initialised during startup, which can be accessed via http_request_context.app.state.clients
    auth: AuthContext = Depends(require_scopes(THREAT_INTEL_REQUIRED_SCOPES)),
    x_session_id: str | None = Header(default=None),
):
    resolved_session_id = x_session_id or str(uuid4())
    clients: AppClients = http_request_context.app.state.clients

    try:
        return StreamingResponse(
            run_threat_intel_agent_and_stream_response(
                prompt=request.prompt,
                session_id=resolved_session_id,
                actor_id=auth.actor_id,
                clients=clients,
            ),
            media_type="text/plain",
            headers={"X-Session-Id": resolved_session_id, "X-Actor-Id": auth.actor_id},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
