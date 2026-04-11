import logging
import json

RESERVED_ATTRS = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName"
}

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "level": record.levelname,
            "message": record.getMessage(),
            "timestamp": self.formatTime(record),
            "logger": record.name,
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        extras = {k: v for k, v in record.__dict__.items() if k not in RESERVED_ATTRS}
        log_obj.update(extras)

        return json.dumps(log_obj)


logger = logging.getLogger()
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
