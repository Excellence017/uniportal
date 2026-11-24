# Before / after results

Measured on 24 November 2026 with the commands in the README, on both branches,
and confirmed by the GitHub Actions security gate
(<https://github.com/Excellence017/uniportal/actions>, runs 45422488414 for
`vulnerable` and 45422488683 for `main`). The WAF and ZAP results come from CI.

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
| Attacks that worked behind the WAF | **3 / 6** | **0 / 6** |
| ZAP baseline warnings (DAST, alert types) | **9** | **6** |
| CI security gate | **Fails** (4 of 6 jobs red) | **Passes** (6 of 6 green) |

The functional tests pass on both branches: the fixes removed the flaws without
breaking any feature.

## 2. Attack results, app alone vs behind the WAF

| Attack | OWASP | vulnerable, direct | vulnerable + WAF | main, direct | main + WAF |
| --- | --- | --- | --- | --- | --- |
| SQL injection in login | A05 | Worked | **Blocked by WAF** | Refused by app | Blocked by WAF |
| SQL injection in course search | A05 | Worked | **Blocked by WAF** | Refused by app | Blocked by WAF |
| Stored XSS in profile | A05 | Worked | **Blocked by WAF** | Refused by app | Blocked by WAF |
| IDOR: read another student’s grades | A01 | Worked | **Worked** | Refused by app | Refused by app |
| Student changes a grade | A01 | Worked | **Worked** | Refused by app | Refused by app |
| Password guessing, 6 attempts | A07 | Worked | **Worked** | Refused by app | Refused by app |

WAF: ModSecurity with the OWASP Core Rule Set, run by the `waf-eval` CI job.

**Finding:** in front of the vulnerable app, the WAF stopped 3 of 6 attacks:
the ones whose requests carry an attack payload (SQL syntax, a script tag).
It stopped none of the 3 logic attacks. Reading someone else's grades,
a student editing a grade and slow password guessing all use requests that
look exactly like normal traffic, so a filter that inspects request content
cannot tell them apart. Only the fixed code stopped all 6. The WAF is a useful
second layer, not a replacement for fixing the code.

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


## 6. Dynamic scan (OWASP ZAP baseline)

ZAP crawls the running app and checks responses passively. Report only, it does
not fail the build.

| ZAP alert | `vulnerable` | `main` |
| --- | --- | --- |
| Missing anti-clickjacking header | Warn | Pass |
| X-Content-Type-Options header missing | Warn | Pass |
| Content Security Policy header not set | Warn | Pass |
| Server version in `Server` header | Warn | Warn |
| Non-storable content | Warn | Warn |
| Permissions-Policy header not set | Warn | Warn |
| Authentication request identified | Warn | Warn |
| Absence of anti-CSRF tokens | Warn | Warn |
| Cross-Origin-Embedder-Policy missing | Warn | Warn |
| **Total warnings / passes** | **9 / 59** | **6 / 62** |

The three alerts that disappeared are the security headers added by FIX-2.
The six that remain are hardening items outside the six planted flaws.
The most relevant, missing CSRF tokens, is listed as future work.
ZAP found none of the six planted flaws by itself. A baseline scan does not
log in or send attacks, which is why the gate also needs the targeted tests.

## 7. A gap found in the pipeline itself

On the first CI run, Gitleaks passed on the `vulnerable` branch although the
key is in the code. The cause: on a push, `gitleaks-action` scans only the
newly pushed commits, and the key was added in an earlier commit. The secret
job was changed to run the Gitleaks CLI over the whole history
(`gitleaks git .`). It now fails on `vulnerable` (1 leak, rule
`flask-hardcoded-secret-key`) and passes on `main`, where the rotated
historical finding is accepted in `.gitleaksignore`.
Lesson: a security tool can pass by quietly checking less than you assume.
Each tool in the gate was checked against a known-bad input.
