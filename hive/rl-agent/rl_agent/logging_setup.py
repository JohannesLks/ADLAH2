"""
Logging configuration for the RL agent system.
"""
import json
import logging
import os
from datetime import datetime
from typing import Optional


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        
        # Add any extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 
                          'funcName', 'levelname', 'levelno', 'lineno', 
                          'module', 'msecs', 'message', 'pathname', 'process',
                          'processName', 'relativeCreated', 'thread', 'threadName',
                          'exc_info', 'exc_text', 'stack_info']:
                log_obj[key] = value
        
        return json.dumps(log_obj)


def setup_logging(level: Optional[str] = None) -> None:
    """Configure logging for the application (console + optional JSON file)."""
    log_level = getattr(logging, (level or os.getenv("LOG_LEVEL", "INFO")).upper())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Always add console handler so logs appear in docker logs/stdout
    console = logging.StreamHandler()
    console.setLevel(log_level)
    # Emit JSON to stdout so `docker compose logs` shows structured entries
    console.setFormatter(JSONFormatter())
    root_logger.addHandler(console)

    # Add file handler for structured logging if path is writable
    log_file = os.getenv("LOG_FILE_PATH", "/var/log/rl-agent/rl-agent.log")
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(JSONFormatter())
            file_handler.setLevel(log_level)
            root_logger.addHandler(file_handler)
        except (OSError, PermissionError) as e:
            root_logger.warning(f"Failed to create log file handler: {e}")

    # Configure specific loggers
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("kubernetes").setLevel(logging.WARNING)
    logging.getLogger("tensorflow").setLevel(logging.INFO)
    
    # Set our modules to DEBUG if main level is DEBUG
    if log_level == logging.DEBUG:
        for module in ["agent", "features", "event_loop", "k8s", "es", "inference"]:
            logging.getLogger(module).setLevel(logging.DEBUG)