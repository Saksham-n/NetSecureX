import json
import logging
import sys
from typing import Any, Dict


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as JSON lines for structured log ingestion."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_obj.update(record.extra_fields)
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logger(name: str = "netsecurex", level: str = "INFO", log_format: str = "text", log_file: str = "") -> logging.Logger:
    """Configures and returns a logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if log_format.lower() == "json":
        console_handler.setFormatter(StructuredJsonFormatter())
    else:
        text_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(text_formatter)
    logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(
                StructuredJsonFormatter() if log_format.lower() == "json"
                else logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
            )
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Failed to initialize log file {log_file}: {e}")

    logger.propagate = False
    return logger
