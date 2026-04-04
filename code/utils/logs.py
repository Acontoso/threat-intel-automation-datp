import logging
import json
import os
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            log_obj["stack"] = self.formatStack(record.stack_info)

        return json.dumps(log_obj, separators=(",", ":"), default=str)


def configure_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()

    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Reuse root handler so uvicorn emits JSON too.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
        uvicorn_logger.setLevel(level)


configure_logging()
logger = logging.getLogger("threat-intel-automation")
