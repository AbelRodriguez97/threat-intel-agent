# 🛡️ threat-intel-agent

> AI-powered agent that ingests public threat intelligence feeds, extracts Indicators of Compromise (IOCs) using Large Language Models, classifies severity, and generates automated daily reports.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini-API-8E75B2?style=flat&logo=googlegemini&logoColor=white)
![LangChain](https://img.shields.io/badge/LangChain-Agents-1C3C3C?style=flat&logo=langchain&logoColor=white)
[![Daily Report](https://github.com/AbelRodriguez97/threat-intel-agent/actions/workflows/daily-report.yml/badge.svg)](https://github.com/AbelRodriguez97/threat-intel-agent/actions/workflows/daily-report.yml)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🎯 Motivation

Security analysts spend hours every day triaging threat intelligence feeds, extracting IOCs (CVEs, IPs, file hashes) and writing summary reports for stakeholders. This project explores how **LLM-powered agents** can automate that workflow end-to-end while keeping a human-readable output that an analyst can validate quickly.

The project targets one of the most repetitive tasks in security operations: turning raw threat data into actionable, prioritized reports.

---

## 🧩 What it does

- 🔄 **Ingests** threat intelligence feeds from public sources (CISA KEV catalog)
- 🤖 **Uses Gemini API** to summarize vulnerabilities in plain English
- 🔎 **Extracts IOCs** automatically: CVE IDs, affected products, vendor information
- 📊 **Classifies severity** based on exploitation status and asset criticality
- 📝 **Generates daily reports** in Markdown with prioritized findings and recommended actions
- 🤖 **LangChain agent orchestration**: the agent decides which tools to invoke based on the context
- ⚙️ **Runs automatically every day** via GitHub Actions

---

## 🏗️ Architecture

```
┌──────────────────┐
│  CISA KEV Feed   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Feed Ingestor   │
│  (CISAClient)    │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────┐
│  LangGraph ReAct Agent   │
│  (Gemini-powered)        │
│                          │
│  Tools:                  │
│  - fetch_recent_vulns    │
│  - analyze_vulnerability │
│  - save_report           │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────┐
│  Markdown Report │
│  (auto-committed │
│   daily via CI)  │
└──────────────────┘
```

---

## 🛠️ Tech Stack

- **Python 3.11+**
- **Google Gemini API** — LLM backbone (structured output via Pydantic schemas)
- **LangChain + LangGraph** — ReAct agent orchestration and tool calling
- **requests + pydantic** — HTTP client and data validation
- **GitHub Actions** — daily automated execution and report commits

---

## 📦 Project structure

```
threat-intel-agent/
├── .github/
│   └── workflows/
│       └── daily-report.yml   # Daily CI pipeline
├── src/
│   ├── feeds/                 # CISA KEV feed client
│   ├── agents/                # LangGraph agent, tools and Gemini analyzer
│   ├── reports/               # Markdown report generation
│   ├── main.py                # Imperative pipeline entry point
│   └── agent_main.py          # Agentic pipeline entry point
├── tests/                     # Unit tests (15 passing)
├── examples/                  # Sample reports
├── requirements.txt
└── .env.example
```

---

## 🚀 Quick start

```bash
# Clone the repository
git clone https://github.com/AbelRodriguez97/threat-intel-agent.git
cd threat-intel-agent

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate         # Linux/macOS
# .\.venv\Scripts\Activate.ps1   # Windows PowerShell

# Install dependencies
pip install -r requirements.txt

# Configure your API key
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

You can get a free Gemini API key at [aistudio.google.com](https://aistudio.google.com).

---

## 🤖 Two ways to run

This project ships with two entrypoints that solve the same problem with different paradigms:

### Imperative pipeline (`src/main.py`)

Hard-coded orchestration: fetch → analyze → report. Used by the daily CI workflow.

```bash
python -m src.main --limit 2
```

### Agentic pipeline (`src/agent_main.py`) ⭐

The same workflow orchestrated by a **LangGraph ReAct agent** powered by Gemini. The agent decides which tools to call based on a natural-language request.

```bash
python -m src.agent_main
# or with a custom request:
python -m src.agent_main --request "Analyze the latest 2 CVEs and generate a report"
```

The agent has three tools: `fetch_recent_vulnerabilities`, `analyze_vulnerability` and `save_report_from_analyses`. It composes them dynamically based on the user's instruction.

---

## ⚠️ A note on running with the free tier

This project uses the **free tier** of Google's Gemini API by default. The free tier enforces two independent quotas:

- **Per-minute limit**: 5 requests/min for `gemini-2.5-flash`. The project mitigates this with client-side throttling in `GeminiAnalyzer` (15-second minimum gap between calls).
- **Per-day limit**: 20 requests/day for `gemini-2.5-flash`. Once exhausted, the API returns `429 RESOURCE_EXHAUSTED` until midnight UTC.

A typical agent run with 2 CVEs consumes ~5 LLM calls. The default request in `src/agent_main.py` is sized to fit comfortably within both quotas.

---

## 🗺️ Roadmap

- [x] Project setup and initial structure
- [x] CISA KEV feed ingestion
- [x] Gemini API integration for CVE summarization
- [x] Severity classification and Markdown report generation
- [x] Unit tests with pytest (15 passing)
- [x] Sample reports in `examples/`
- [x] LangGraph agent with multi-tool orchestration
- [x] Client-side throttling and LLM cost optimization
- [x] GitHub Actions workflow for daily automated execution
- [ ] IOC extraction with regex + LLM validation
- [ ] AlienVault OTX integration
- [ ] Agent memory with LangGraph checkpointers

---

## 🧠 What I'm learning

- Designing **multi-tool LLM agents** with LangGraph and LangChain
- Working with **Google Gemini API** for structured output extraction
- Building **secure API integrations** (secrets management, rate limiting)
- Threat intelligence data formats (CVE schemas, CISA KEV)
- CI/CD for AI pipelines with GitHub Actions

---

## 📄 Sample output

- [`examples/sample-report.md`](./examples/sample-report.md) — generated by the imperative pipeline
- [`examples/sample-agent-report.md`](./examples/sample-agent-report.md) — generated by the LangGraph agent

---

## 📚 References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [LangChain documentation](https://python.langchain.com/)
- [LangGraph documentation](https://langchain-ai.github.io/langgraph/)
- [Gemini API documentation](https://ai.google.dev/gemini-api/docs)

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 👤 Author

**Abel Rodriguez** — Software Engineer @ Accenture, interested in applying AI to security operations.

📫 [LinkedIn](https://www.linkedin.com/in/abel-rodriguez-gomez-20a446132/) · 📧 abelrodr42malaga@gmail.com
