# 🛡️ threat-intel-agent

> AI-powered agent that ingests public threat intelligence feeds, extracts Indicators of Compromise (IOCs) using Large Language Models, classifies severity, and generates automated daily reports.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini-API-8E75B2?style=flat&logo=googlegemini&logoColor=white)
![LangChain](https://img.shields.io/badge/LangChain-Agents-1C3C3C?style=flat&logo=langchain&logoColor=white)
![Status](https://img.shields.io/badge/status-in%20development-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🎯 Motivation

Security analysts spend hours every day triaging threat intelligence feeds, extracting IOCs (CVEs, IPs, file hashes) and writing summary reports for stakeholders. This project explores how **LLM-powered agents** can automate that workflow end-to-end while keeping a human-readable output that an analyst can validate quickly.

The project targets one of the most repetitive tasks in security operations: turning raw threat data into actionable, prioritized reports.

---

## 🧩 What it does

- 🔄 **Ingests** threat intelligence feeds from public sources (CISA KEV catalog, AlienVault OTX, NVD)
- 🤖 **Uses Gemini API** to summarize vulnerabilities in plain English
- 🔎 **Extracts IOCs** automatically: CVE IDs, affected products, vendor information
- 📊 **Classifies severity** based on CVSS, exploitation status and asset criticality
- 📝 **Generates daily reports** in Markdown with prioritized findings and recommended actions
- 🤖 **LangChain agent orchestration**: the agent decides which tools to invoke based on the context

---

## 🏗️ Architecture

```
┌──────────────────┐
│  CISA KEV Feed   │
│  AlienVault OTX  │──┐
│  NVD API         │  │
└──────────────────┘  │
                      ▼
              ┌───────────────┐
              │ Feed Ingestor │
              └───────┬───────┘
                      ▼
            ┌─────────────────────┐
            │  LangChain Agent    │
            │  (Gemini-powered)   │
            │                     │
            │  Tools:             │
            │  - fetch_cves       │
            │  - enrich_cve       │
            │  - classify         │
            │  - generate_report  │
            └─────────┬───────────┘
                      ▼
            ┌─────────────────────┐
            │  Markdown Report    │
            │  (committed daily)  │
            └─────────────────────┘
```

---

## 🛠️ Tech Stack

- **Python 3.11+**
- **Google Gemini API** — LLM backbone
- **LangChain** — agent orchestration and tool calling
- **requests** — HTTP client for public feeds
- **pydantic** — data validation
- **GitHub Actions** — daily automated execution (planned)

---

## 📦 Project structure

```
threat-intel-agent/
├── src/
│   ├── feeds/         # Public feed clients (CISA, OTX, NVD)
│   ├── agents/        # LangChain agent definitions and tools
│   ├── extractors/    # IOC extraction logic
│   └── reports/       # Markdown report generation
├── tests/             # Unit tests
├── examples/          # Sample inputs and generated reports
├── requirements.txt
└── .env.example
```

---

## 🚀 Quick start

> ⚠️ This project is in active development. Functionality is being added incrementally.

```bash
# Clone the repository
git clone https://github.com/AbelRodriguez97/threat-intel-agent.git
cd threat-intel-agent

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure your API key
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

You can get a free Gemini API key at [aistudio.google.com](https://aistudio.google.com).

---

## 🗺️ Roadmap

- [x] Project setup and initial structure
- [ ] CISA KEV feed ingestion
- [ ] Gemini API integration for CVE summarization
- [ ] IOC extraction with regex + LLM validation
- [ ] LangChain agent with multi-tool orchestration
- [ ] AlienVault OTX integration
- [ ] Severity classification engine
- [ ] Daily report generation in Markdown
- [ ] GitHub Actions workflow for daily execution
- [ ] Unit tests with pytest
- [ ] Sample reports in `examples/`

---

## 🧠 What I'm learning

- Designing **multi-tool LLM agents** with LangChain
- Working with **Google Gemini API** for structured output extraction
- Building **secure API integrations** (secrets management, rate limiting)
- Threat intelligence data formats (STIX-like patterns, CVE schemas)
- CI/CD for AI pipelines with GitHub Actions

---

## 📚 References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [LangChain documentation](https://python.langchain.com/)
- [Gemini API documentation](https://ai.google.dev/gemini-api/docs)
- [AlienVault OTX](https://otx.alienvault.com/)

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 👤 Author

**Abel Rodriguez** — Software Engineer @ Accenture, interested in applying AI to security operations.

📫 [LinkedIn](https://www.linkedin.com/in/abel-rodriguez-gomez-20a446132/) · 📧 abelrodr42malaga@gmail.com