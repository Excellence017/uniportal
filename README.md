# UniPortal: Breaking and Fixing a Student Portal

Applied Security Capstone · Diyor Arifdjanov (ID 230542)

UniPortal is a small Flask student portal (log in, view grades, edit profile,
search courses; lecturers edit grades). It was built with six intentional
vulnerabilities from the OWASP Top 10:2025, then each one was exploited,
fixed at its root cause, and locked in with an automated security gate.

> **Warning.** The `vulnerable` branch is insecure on purpose. Run it only on
> your own machine. Every port in this lab is bound to `127.0.0.1`.

## Branches

| Branch | What it is |
| --- | --- |
| `vulnerable` | Baseline with the six planted flaws, each marked `VULN-n` in the code |
| `main` | Secure version: one commit per fix (`FIX-1` … `FIX-6`), so `git log` reads as the remediation story |

See any single fix with `git show <commit>`; see all fixes with `git diff vulnerable main -- app.py templates/`.

## The six vulnerabilities

| # | Flaw | OWASP 2025 | Where | Fix |
| --- | --- | --- | --- | --- |
| 1 | SQL injection | A05 Injection | `login()`, `courses()` | Parameterised queries |
| 2 | Stored XSS | A05 Injection | `templates/student.html` | Auto-escaping + Content-Security-Policy |
| 3 | IDOR / missing role check | A01 Broken Access Control | `grades()`, `edit_grade()` | `require_student_access()`, `require_role()` |
| 4 | Weak password storage, no rate limit | A07 Authentication Failures | `hash_password()`, `login()` | Salted scrypt hashing, 5-attempt lockout |
| 5 | Hardcoded secret key, debug on, cookie flags | A02 Security Misconfiguration | `create_app()` | Key from environment, debug off, HttpOnly + SameSite |
| 6 | Outdated Flask/Werkzeug | A03 Software Supply Chain Failures | `requirements.txt` | Upgrade and pin; `pip-audit` in CI |

## Run it

### With Docker (recommended)

```bash
git checkout main            # or: git checkout vulnerable
docker compose up --build    # app on http://127.0.0.1:5000
docker compose --profile waf up --build   # adds the WAF on http://127.0.0.1:8080
```

### Without Docker (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:UNIPORTAL_SECRET_KEY = "lab-" + [guid]::NewGuid()   # needed on main only
python app.py                                             # http://127.0.0.1:5000
```

Reset the demo data at any time with `flask --app app:create_app init-db`.
**When you switch branches, delete `uniportal.db` (or run `init-db`)**: the two
versions store passwords with different hashes, so one branch cannot log in
with the other's database.

Demo accounts (synthetic): `alice` / `Alice#Lab2026` (student), `bob` / `sunshine`
(student, deliberately weak password), `drsmirnova` / `Lecturer#Lab2026` (lecturer).

## Security testing

```bash
pip install pytest semgrep bandit pip-audit
pytest -v                                         # 16 tests: 6 functional + 10 security
semgrep scan --config semgrep-rules/ --metrics=off   # custom UniPortal rules
bandit -r . -x ./tests,./scripts -ll
pip-audit -r requirements.txt
python scripts/waf_eval.py --target http://127.0.0.1:5000 --label main-direct
```

The security tests are identical on both branches: they **fail on `vulnerable`**
(evidence that each flaw exists) and **pass on `main`** (proof that each fix works).

## CI security gate

`.github/workflows/security.yml` runs on every push and pull request:

| Job | Tool | Blocks merge? |
| --- | --- | --- |
| Security regression tests | pytest | Yes |
| Static analysis | Semgrep (custom + community rules), Bandit | Yes |
| Dependency audit | pip-audit | Yes |
| Secret scanning | Gitleaks | Yes |
| Defense in depth | `scripts/waf_eval.py` against the app and the ModSecurity WAF | Reports only |
| Dynamic scan | OWASP ZAP baseline | Reports only |

To make the gate actually block merges: **Settings → Branches → Add rule for
`main` → Require status checks to pass**, and select the first four jobs.

Demo of a blocked pull request:

```bash
git checkout -b demo/regression main
git revert --no-edit <FIX-3 commit>       # brings the IDOR back
git push -u origin demo/regression        # open a PR: checks fail, merge is blocked
```

## Repository layout

```
app.py                 Flask application (all routes, security controls)
db.py                  Schema and synthetic demo data
templates/, static/    Pages and styling
tests/                 pytest: functional + security regression tests
semgrep-rules/         Custom Semgrep rules for UniPortal's code patterns
scripts/waf_eval.py    Defense-in-depth measurement (direct vs through WAF)
docker-compose.yml     Lab: app, optional ModSecurity + OWASP CRS WAF
.github/workflows/     CI security gate
results/               Before/after results
```

## Ethics

All testing targets this application only, on the author's own machine or a CI
runner. All accounts and grades are invented.
