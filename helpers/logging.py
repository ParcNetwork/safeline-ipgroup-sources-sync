import logging
import os
import sys

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("safeline_sync")

    if logger.hasHandlers():
        return logger

    level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.setLevel(level)

    logger.info("Logger initialized with level: %s", level_str)
    return logger