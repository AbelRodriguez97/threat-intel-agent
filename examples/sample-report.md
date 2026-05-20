# 🛡️ Threat Intelligence Report — 2026-05-20

> Generated automatically by `threat-intel-agent` on 2026-05-20 07:51 UTC.

**Vulnerabilities analyzed:** 3  
**Severity breakdown:** 🔴 CRITICAL: 2 · 🟠 HIGH: 1

## 📊 Summary

| CVE | Vendor / Product | Severity | Date added |
|-----|------------------|----------|------------|
| `CVE-2026-20182` | Cisco / Catalyst SD-WAN | 🔴 CRITICAL | 2026-05-14 |
| `CVE-2026-42208` | BerriAI / LiteLLM | 🔴 CRITICAL | 2026-05-08 |
| `CVE-2026-42897` | Microsoft / Microsoft | 🟠 HIGH | 2026-05-15 |

## 🔍 Detailed analysis

### 🔴 CRITICAL — `CVE-2026-20182`

**Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability** — Cisco / Catalyst SD-WAN

📅 Added to KEV: 2026-05-14 · ⏳ CISA due date: 2026-05-17 · 💀 Ransomware: Unknown

#### Executive summary

An urgent security flaw has been discovered in Cisco Catalyst SD-WAN Controller and Manager systems. This vulnerability allows an attacker to bypass security measures without needing a username or password, gaining full administrative control over the affected system from anywhere. Immediate action is required to prevent unauthorized access.

#### Affected technologies

Cisco Catalyst SD-WAN Controller, Cisco Catalyst SD-WAN Manager

#### Recommended actions

  1. Assess exposure and mitigate risks associated with Cisco SD-WAN devices as outlined in CISA’s Emergency Directive 26-03.
  2. Follow CISA’s Hunt & Hardening Guidance for Cisco SD-WAN Devices.
  3. Adhere to the applicable BOD 22-01 guidance for cloud services.
  4. Discontinue use of the product if mitigations are not available.

#### Rationale

_This vulnerability allows an unauthenticated, remote attacker to completely bypass authentication and obtain administrative privileges. This level of access grants full control over the affected SD-WAN infrastructure without any prior credentials, posing an extreme risk to network integrity and data confidentiality._

### 🔴 CRITICAL — `CVE-2026-42208`

**BerriAI LiteLLM SQL Injection Vulnerability** — BerriAI / LiteLLM

📅 Added to KEV: 2026-05-08 · ⏳ CISA due date: 2026-05-11 · 💀 Ransomware: Unknown

#### Executive summary

A critical SQL injection vulnerability has been identified in BerriAI LiteLLM, a component actively exploited in the wild. This flaw allows attackers to steal and potentially alter data from the proxy's database. Successful exploitation could lead to unauthorized access to the proxy and compromise sensitive credentials it manages.

#### Affected technologies

BerriAI LiteLLM

#### Recommended actions

  1. Immediately apply all vendor-provided mitigations and patches for BerriAI LiteLLM.
  2. For deployments utilizing cloud services, ensure adherence to CISA BOD 22-01 guidance.
  3. If no effective mitigations are available from the vendor, discontinue the use of the BerriAI LiteLLM product to prevent exploitation.

#### Rationale

_The vulnerability is rated as critical due to its nature as a SQL injection, which allows for data exfiltration and potential modification. Its presence in the CISA KEV catalog indicates active exploitation, posing an immediate and severe threat. The compromise of a proxy's database and managed credentials could lead to widespread unauthorized access and significant data breaches._

### 🟠 HIGH — `CVE-2026-42897`

**Microsoft Exchange Server Cross-Site Scripting Vulnerability** — Microsoft / Microsoft

📅 Added to KEV: 2026-05-15 · ⏳ CISA due date: 2026-05-29 · 💀 Ransomware: Unknown

#### Executive summary

A critical security flaw (CVE-2026-42897) has been identified in Microsoft Exchange Server's Outlook Web Access. This vulnerability, which is actively being exploited, allows malicious code to run in users' web browsers, potentially leading to unauthorized access or data compromise. Immediate action is required to protect organizational data and systems.

#### Affected technologies

Microsoft Exchange Server, Outlook Web Access, Microsoft

#### Recommended actions

  1. Immediately apply all available vendor-provided mitigations and security updates for Microsoft Exchange Server.
  2. For cloud services utilizing Microsoft Exchange, adhere to BOD 22-01 guidance to ensure compliance and security.
  3. If vendor mitigations or updates are unavailable, evaluate discontinuing the use of the affected product until a secure resolution is provided.

#### Rationale

_The vulnerability is classified as 'high' severity due to its presence in the CISA Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild. While an XSS vulnerability, its impact on a critical enterprise application like Microsoft Exchange Server's Outlook Web Access, combined with active exploitation, poses a significant risk for client-side compromise, data theft, and potential further attacks within the browser context._

---

*Source: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).*  
*Analysis generated with Google Gemini. Always validate with a human analyst before taking action.*