"""
The threat intelligence agent.

Uses LangGraph's prebuilt ReAct agent pattern: the LLM iteratively decides
which tool to call, observes the result, and continues until it has
fulfilled the user's request.
"""

import logging

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent

from src.config import GEMINI_API_KEY
from src.agents.tools import AVAILABLE_TOOLS

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-2.5-flash"

SYSTEM_PROMPT = """\
You are a senior threat intelligence analyst working for a security operations team.

You have access to three tools:
1. fetch_recent_vulnerabilities — lists recent CVEs from the CISA KEV catalog.
2. analyze_vulnerability — runs a Gemini-based analysis on a specific CVE.
3. save_report_from_analyses — writes a Markdown report to disk using CVE
   analyses that have already been produced earlier in this conversation.

Workflow guidance:
- Always start by fetching recent vulnerabilities to know what is available.
- Then call analyze_vulnerability ONCE per CVE the user is interested in.
  Do not analyze CVEs the user did not ask about.
- If the user wants a written report, finish by calling save_report_from_analyses
  with the list of CVE IDs you have already analyzed. Do NOT re-analyze them.
- After the report is saved, tell the user the file path and a one-paragraph
  summary of what it contains.

Cost discipline:
- The analyze_vulnerability tool is the only one that costs LLM calls.
  Be conservative: only analyze the CVEs the user explicitly cares about.
"""


def build_agent(model_name: str = DEFAULT_MODEL):
    """
    Construct the ReAct agent wired to Gemini and the available tools.

    Returns:
        A LangGraph agent ready to be invoked with .invoke({"messages": [...]}).
    """
    logger.info("Building agent with model %s", model_name)

    llm = ChatGoogleGenerativeAI(
        model=model_name,
        google_api_key=GEMINI_API_KEY,
        temperature=0.1,
    )

    agent = create_react_agent(
        model=llm,
        tools=AVAILABLE_TOOLS,
        prompt=SYSTEM_PROMPT,
    )
    return agent


def run_agent(user_request: str, model_name: str = DEFAULT_MODEL) -> str:
    """
    Run the threat intelligence agent against a user request.

    Args:
        user_request: Natural-language instruction (e.g. "Give me a report
                      on the 3 most recent critical CVEs").
        model_name:   Gemini model to use.

    Returns:
        The agent's final textual response as a plain string.
    """
    agent = build_agent(model_name)

    result = agent.invoke({"messages": [{"role": "user", "content": user_request}]})

    # The last message in the result is the agent's final answer.
    # Depending on the model, .content may be a plain string or a list of
    # content blocks (each a dict with a 'type' field). Normalize both cases.
    final_message = result["messages"][-1]
    return _extract_text(final_message.content)


def _extract_text(content) -> str:
    """
    Normalize the .content field of an AIMessage into a plain text string.

    Some Gemini responses return a list of content blocks like:
        [{"type": "text", "text": "...", "extras": {...}}, ...]
    while others return a plain string. This helper handles both.
    """
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif isinstance(block, str):
                text_parts.append(block)
        return "\n".join(text_parts).strip()

    # Fallback for unexpected shapes
    return str(content)