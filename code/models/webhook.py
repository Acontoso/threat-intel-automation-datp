from pydantic import BaseModel, Field


class IngestionWebhookRequest(BaseModel):
    hours_back: int = Field(default=12, ge=1, le=168)
    run_microsoft: bool = True
    run_cisco: bool = True


class IngestionWebhookResponse(BaseModel):
    status: str
    message: str
    triggered_targets: list[str]
    query_since: str
