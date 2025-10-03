"""Logging configuration for Hash Forge library."""
import logging
from typing import Final

# Logger name for the library
LOGGER_NAME: Final[str] = "hash_forge"


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance for Hash Forge.

    Args:
        name: Optional module name to append to the logger name

    Returns:
        A configured logger instance
    """
    logger_name = f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME

    return logging.getLogger(logger_name)


def configure_logging(level: int = logging.WARNING) -> None:
    """Configure basic logging for Hash Forge.

    This sets up a basic logging configuration for the library.
    Users can override this by configuring the 'hash_forge' logger
    in their application.

    Args:
        level: The logging level (default: logging.WARNING)

    Example:
        # Enable debug logging for hash_forge
        import logging
        from hash_forge.logging_config import configure_logging

        configure_logging(logging.DEBUG)
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)

    # Only add handler if none exists
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)


# Create default logger for the library
logger = get_logger()
