"""
Entry point for the agentic version of the pipeline.

Unlike src/main.py — which orchestrates the pipeline imperatively —
this script delegates orchestration to a LangGraph agent that decides
which tools to call based on a natural-language request.
"""

import argparse
import logging

from src.agents.threat_intel_agent import run_agent

logger = logging.getLogger(__name__)

DEFAULT_REQUEST = (
    "Fetch the 2 most recently added vulnerabilities from CISA, "
    "analyze each one, and generate a Markdown report covering them. "
    "Then summarize what's in the report."
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the threat intelligence agent against a natural-language request.",
    )
    parser.add_argument(
        "--request",
        type=str,
        default=DEFAULT_REQUEST,
        help="The natural-language request to send to the agent.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logger.info("Running agent with request: %s", args.request)
    output = run_agent(args.request)
    print("\n" + "=" * 80)
    print("Agent response:")
    print("=" * 80)
    print(output)
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()