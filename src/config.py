"""
Application configuration loaded from environment variables.
"""

import logging
import os
from dotenv import load_dotenv

# Load .env file if it exists (silently ignored in production environments
# where env vars are set directly, e.g. GitHub Actions).
load_dotenv()


def get_required_env(name: str) -> str:
    """Read an environment variable or raise a clear error if missing."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable '{name}' is not set. "
            f"Add it to your .env file or export it in your shell."
        )
    return value


# Public configuration values
GEMINI_API_KEY = get_required_env("GEMINI_API_KEY")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Configure root logging once
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)