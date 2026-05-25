# 🛡️ Threat Intelligence Report — 2026-05-25

> Generated automatically by `threat-intel-agent` on 2026-05-25 08:38 UTC.

**Vulnerabilities analyzed:** 2  
**Severity breakdown:** 🔴 CRITICAL: 2

## 📊 Summary

| CVE | Vendor / Product | Severity | Date added |
|-----|------------------|----------|------------|
| `CVE-2026-9082` | Drupal / Core | 🔴 CRITICAL | 2026-05-22 |
| `CVE-2025-34291` | Langflow / Langflow | 🔴 CRITICAL | 2026-05-21 |

## 🔍 Detailed analysis

### 🔴 CRITICAL — `CVE-2026-9082`

**Drupal Core SQL Injection Vulnerability** — Drupal / Core

📅 Added to KEV: 2026-05-22 · ⏳ CISA due date: 2026-05-27 · 💀 Ransomware: Unknown

#### Executive summary

A critical SQL injection vulnerability in Drupal Core, identified as CVE-2026-9082, allows attackers to achieve privilege escalation and remote code execution. This vulnerability is actively exploited in the wild, as confirmed by its inclusion in the CISA Known Exploited Vulnerabilities catalog. Immediate action is required to patch affected systems to prevent compromise.

#### Affected technologies

Drupal Core, Drupal

#### Recommended actions

  1. Immediately apply all vendor-provided security patches and mitigations for Drupal Core.
  2. For Drupal Core instances deployed in cloud environments, strictly follow all applicable guidance from CISA BOD 22-01.
  3. If no mitigations or patches are currently available, discontinue the use of Drupal Core until a secure resolution can be implemented.
  4. Conduct an urgent audit of all systems to identify and prioritize any instances of Drupal Core that may be affected.

#### Rationale

_The vulnerability is a SQL injection in Drupal Core that permits remote code execution and privilege escalation, which are impacts of the highest severity. Its inclusion in the CISA KEV catalog explicitly indicates active exploitation, posing an immediate and direct threat to organizational assets. The combination of ease of exploitation, high impact, and confirmed in-the-wild exploitation warrants a critical severity classification._

### 🔴 CRITICAL — `CVE-2025-34291`

**Langflow Origin Validation Error Vulnerability** — Langflow / Langflow

📅 Added to KEV: 2026-05-21 · ⏳ CISA due date: 2026-06-04 · 💀 Ransomware: Unknown

#### Executive summary

Langflow has a critical security vulnerability stemming from an origin validation error and an overly permissive CORS configuration. This flaw, combined with an insecure refresh token cookie setting, allows malicious websites to perform unauthorized cross-origin requests using stolen credentials. Attackers could exploit this to achieve arbitrary code execution and full system compromise, necessitating immediate action to prevent severe data breaches and unauthorized access.

#### Affected technologies

Langflow, Langflow

#### Recommended actions

  1. Apply mitigations per vendor instructions.
  2. Follow applicable BOD 22-01 guidance for cloud services.
  3. Discontinue use of the product if mitigations are unavailable.

#### Rationale

_The vulnerability allows for arbitrary code execution and full system compromise through the exploitation of an origin validation error and insecure CORS/cookie configurations. This direct path to complete system control, coupled with the ability to bypass standard security mechanisms, warrants a critical severity rating._

---

*Source: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).*  
*Analysis generated with Google Gemini. Always validate with a human analyst before taking action.*