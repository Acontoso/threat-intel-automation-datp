import os
from fastapi import FastAPI, HTTPException
from code.config import ThreatIntelConfig
from code.models import IngestionWebhookRequest, IngestionWebhookResponse
from code.orchestrator import ThreatIntelOrchestrator
from code.utils.logs import logger


app = FastAPI(title="Threat Intel Automation API", version="1.0.0")
orchestrator = ThreatIntelOrchestrator(ThreatIntelConfig())


@app.on_event("startup")
async def startup_event() -> None:
    try:
        await orchestrator.warmup()
    except Exception as error:
        logger.error(f"Credential warmup failed, proceeding without cache: {error}")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/ingest", response_model=IngestionWebhookResponse)
async def webhook_ingest(
    body: IngestionWebhookRequest
) -> IngestionWebhookResponse:

    try:
        result = await orchestrator.run(
            hours_back=body.hours_back,
            run_microsoft=body.run_microsoft,
            run_cisco=body.run_cisco,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        logger.error(f"Error: {error}")
        raise HTTPException(status_code=500, detail="Failed to run ingestion") from error

    return IngestionWebhookResponse(
        status="ok",
        message="Ingestion workflow completed",
        triggered_targets=result["triggered_targets"],
        query_since=result["query_since"],
    )
