from dataclasses import dataclass
import os
from bedrock_agentcore.memory import MemoryClient
from strands.models import BedrockModel
from code.tools.opensource import OpenSourceClient
from code.tools.recordedfutures import RecordedFutureClient


@dataclass
class AppClients:
    """Long-lived clients shared across requests."""

    opensource_client: OpenSourceClient
    recordedfuture_client: RecordedFutureClient
    memory_client: MemoryClient
    bedrock_model: BedrockModel
    region: str
    agentcore_memory_short_id: str

    async def aclose(self) -> None:
        await self.http.close()


async def create_app_clients() -> AppClients:
    """Create process-wide clients at FastAPI startup."""
    region = os.getenv("REGION", "ap-southeast-2")
    bedrock_model_id = os.getenv("BEDROCK_MODEL_ID", "us.amazon.nova-pro-v1:0")
    guardrail_id = os.getenv("GUARDRAIL_ID", None)
    memory_short_id = os.getenv("AGENTCORE_MEMORY_SHORT_ID", "")

    if not memory_short_id:
        raise ValueError("AGENTCORE_MEMORY_SHORT_ID must be set.")

    opensource_client = OpenSourceClient()
    recordedfuture_client = RecordedFutureClient()
    memory_client = MemoryClient(region=region)
    bedrock_model = BedrockModel(
        model_id=bedrock_model_id,
        temperature=0.2,
        streaming=True,
        guardrail_id=guardrail_id,
        guardrail_latest_message=True
    )

    return AppClients(
        opensource_client=opensource_client,
        recordedfuture_client=recordedfuture_client,
        memory_client=memory_client,
        bedrock_model=bedrock_model,
        region=region,
        agentcore_memory_short_id=memory_short_id,
    )
