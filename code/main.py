#!/usr/bin/env python
"""FastAPI entrypoint for threat-intel webhook ingestion."""

from code.api import app
import uvicorn

if __name__ == "__main__":
    # Uvicorn will start the eventloop and loads the fastAPI app.
    # ASGI applications are async callables, and are request handlers (controllers)
    uvicorn.run(
        "code.main:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_config=None,
    )
