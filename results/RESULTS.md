# Before / after results

Measured on 24 November 2026 with the commands in the README, on both branches.
Rows marked *CI* are produced by the GitHub Actions run (Docker images and
community rule packs are downloaded there).

## 1. Summary

| Measure | `vulnerable` | `main` (secure) |
| --- | --- | --- |
| Security regression tests failing (pytest, 10 tests) | **10 / 10** | **0 / 10** |
| Functional tests passing (6 tests) | 6 / 6 | 6 / 6 |
| Custom Semgrep findings (7 rules) | **9** | **0** |
| Bandit findings (high / medium / low) | **2 / 2 / 1** | **0 / 0 / 0** |
| Dependency advisories (pip-audit, unique) | **12** (2 Flask, 10 Werkzeug) | **0** |
| Hardcoded secrets in working tree (Gitleaks) | **1** | **0** |
| Attacks that worked (`scripts/waf_eval.py`, direct) | **6 / 6** | **0 / 6** |

The functional tests pass on both branches: the fixes removed the flaws without
breaking any feature.

## 2. Attack results, app alone vs behind the WAF

| Attack | OWASP | vulnerable, direct | vulnerable + WAF | main, direct | main + WAF |
| --- | --- | --- | --- | --- | --- |
| SQL injection in login | A05 | Worked | *CI* | Refused by app | *CI* |
| SQL injection in course search | A05 | Worked | *CI* | Refused by app | *CI* |
| Stored XSS in profile | A05 | Worked | *CI* | Refused by app | *CI* |
| IDOR: read another student’s grades | A01 | Worked | *CI* | Refused by app | *CI* |
| Student changes a grade | A01 | Worked | *CI* | Refused by app | *CI* |
| Password guessing, 6 attempts | A07 | Worked | *CI* | Refused by app | *CI* |

Fill the WAF columns from the `waf-eval` job summary in GitHub Actions.
Expected pattern: the WAF stops the requests that carry an attack payload
(SQL, script tags) but cannot stop IDOR, a student editing a grade, or slow
password guessing, because those requests look exactly like normal traffic.

## 3. Tool coverage: which tool detects which flaw

| Flaw | pytest security tests | Custom Semgrep | Bandit | pip-audit | Gitleaks |
| --- | --- | --- | --- | --- | --- |
| 1. SQL injection | Yes | Yes (2) | Yes (B608 ×2) | No | No |
| 2. Stored XSS | Yes | Yes (`|safe`) | No | No | No |
| 3. IDOR / missing role check | Yes | Yes (2) | No | No | No |
| 4. MD5 hashing | Yes | Yes | Yes (B324) | No | No |
| 4. No login rate limit | Yes | No | No | No | No |
| 5. Hardcoded key, debug, cookie flag | Yes | Yes (4) | Yes (B201, B105) | No | Yes (key) |
| 6. Outdated dependencies | No | No | No | Yes (12) | No |

**Finding:** the generic static analyser (Bandit) found 3 of the 6 flaw
classes and missed every access-control and template problem. The custom
Semgrep rules, written for this application’s own patterns, found 5 of 6.
Missing rate limiting was caught only by a behaviour test. No single tool
covers everything, which is why the gate layers tests, custom rules, generic
SAST, dependency audit and secret scanning.

## 4. Dependency advisories removed by FIX-6

| Package | Version | Advisory | Fixed in |
| --- | --- | --- | --- |
| Flask | 2.2.2 | CVE-2023-30861 | 2.2.5 |
| Flask | 2.2.2 | CVE-2026-27205 | 3.1.3 |
| Werkzeug | 2.2.2 | CVE-2023-23934 | 2.2.3 |
| Werkzeug | 2.2.2 | CVE-2023-25577 | 2.2.3 |
| Werkzeug | 2.2.2 | CVE-2023-46136 | 2.3.8 |
| Werkzeug | 2.2.2 | CVE-2024-34069 (debugger) | 3.0.3 |
| Werkzeug | 2.2.2 | CVE-2024-49766 | 3.0.6 |
| Werkzeug | 2.2.2 | CVE-2024-49767 | 3.0.6 |
| Werkzeug | 2.2.2 | CVE-2025-66221 | 3.1.4 |
| Werkzeug | 2.2.2 | CVE-2026-21860 | 3.1.5 |
| Werkzeug | 2.2.2 | CVE-2026-27199 | 3.1.6 |
| Werkzeug | 2.2.2 | CVE-2026-102598 | 3.1.9 |

CVE-2024-34069 affects the Werkzeug debugger, which the vulnerable branch also
switches on (VULN-5): two weaknesses that make each other worse.

## 5. Secret in git history

Removing the hardcoded key from the code (FIX-5) does not remove it from git
history: Gitleaks still finds it in the baseline commit. The remediation is
to **rotate** the key (the live key now exists only in an environment variable)
and record the old finding as accepted in `.gitleaksignore`. Lesson: a secret
committed once must be treated as leaked.
