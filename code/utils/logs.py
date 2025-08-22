import logging
import json


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "level": record.levelname,
            "message": record.msg,
            "timestamp": self.formatTime(record),
        }
        return json.dumps(log_obj)


logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)
