import json
import logging
import time
import uuid
from datetime import datetime, timezone
from collections.abc import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger("app.request_response")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


class RequestResponseLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        start = time.perf_counter()
        client_host = request.client.host if request.client else None

        logger.info(
            json.dumps(
                {
                    "event": "request_received",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "client": client_host,
                }
            )
        )

        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response_body = _safe_response_body(response)

        logger.info(
            json.dumps(
                {
                    "event": "response_sent",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "request_id": request_id,
                    "method": request.method,
                    "client": client_host,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "response_body": response_body,
                }
            )
        )

        response.headers["x-request-id"] = request_id
        return response


def _safe_response_body(response: Response) -> str | None:
    body = getattr(response, "body", None)
    if body is None:
        return None

    if isinstance(body, (bytes, bytearray)):
        return body.decode("utf-8", errors="replace")

    return str(body)
