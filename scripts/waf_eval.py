"""Defense-in-depth measurement for the UniPortal lab.

Sends the same test requests used in tests/test_security.py to one target
(the app directly, or the app behind the ModSecurity WAF) and records, for
each request, whether it was:
  - BLOCKED by the WAF (HTTP 403 page that is not UniPortal's), or
  - reached the app and the app REFUSED it (secure code), or
  - reached the app and it WORKED (the flaw is exploitable on this path).

Usage (run only against your own local lab):
    python scripts/waf_eval.py --target http://127.0.0.1:5000 --label vulnerable-direct
    python scripts/waf_eval.py --target http://127.0.0.1:8080 --label vulnerable-waf

Results are printed and saved to results/waf_<label>.md. Standard library only.
"""
import argparse
import http.cookiejar
import os
import urllib.error
import urllib.parse
import urllib.request

ALICE = ("alice", "Alice#Lab2026")
BOB_ID = 2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Session:
    """A tiny browser: keeps cookies, does not follow redirects."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()
        )

    def request(self, method, path, data=None, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", "uniportal-lab-eval/1.0")
        try:
            with self.opener.open(req, timeout=10) as r:
                return r.status, r.headers.get("Location", ""), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location", ""), e.read()

    def login(self, username, password):
        return self.request("POST", "/login", {"username": username, "password": password})


def blocked_by_waf(status, body):
    # UniPortal's own pages, including its error pages, contain the word "UniPortal".
    return status == 403 and b"UniPortal" not in body


def classify(status, body, worked):
    if blocked_by_waf(status, body):
        return "BLOCKED by WAF"
    return "WORKED (flaw exploitable)" if worked else "REFUSED by app"


def case_sqli_login(base):
    s = Session(base)
    status, location, body = s.login("alice' --", "anything")
    return classify(status, body, status == 302 and location.endswith("/dashboard"))


def case_sqli_search(base):
    s = Session(base)
    s.login(*ALICE)
    status, _, body = s.request("GET", "/courses", params={"q": "zzz' OR '1'='1' --"})
    # Safe code searches for the text literally and finds nothing.
    return classify(status, body, status == 200 and b"No courses match" not in body)


def case_stored_xss(base):
    s = Session(base)
    s.login(*ALICE)
    status, _, body = s.request("POST", "/profile", {"about": "<script>alert('xss')</script>"})
    if blocked_by_waf(status, body):
        return "BLOCKED by WAF"
    _, _, page = s.request("GET", "/students/1")
    return classify(200, page, b"<script>alert" in page)


def case_idor(base):
    s = Session(base)
    s.login(*ALICE)
    status, _, body = s.request("GET", "/grades", params={"student_id": BOB_ID})
    return classify(status, body, status == 200 and b"Bobur Rahimov" in body)


def case_student_edits_grade(base):
    s = Session(base)
    s.login(*ALICE)
    status, _, body = s.request("POST", "/grades/edit", {"grade_id": 4, "grade": "A"})
    return classify(status, body, status in (200, 302))


def case_password_guessing(base):
    s = Session(base)
    for _ in range(5):
        s.login("bob", "wrong-guess")
    status, location, body = s.login("bob", "sunshine")
    return classify(status, body, status == 302 and location.endswith("/dashboard"))


CASES = [
    ("SQL injection in login", "A05", case_sqli_login),
    ("SQL injection in course search", "A05", case_sqli_search),
    ("Stored XSS in profile", "A05", case_stored_xss),
    ("IDOR: read another student's grades", "A01", case_idor),
    ("Student changes a grade", "A01", case_student_edits_grade),
    ("Password guessing, 6 attempts", "A07", case_password_guessing),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, help="base URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--label", required=True, help="name for this run, e.g. secure-waf")
    args = parser.parse_args()

    host = urllib.parse.urlparse(args.target).hostname
    if host not in ("127.0.0.1", "localhost"):
        raise SystemExit("Refusing to run: this lab tool only targets 127.0.0.1 / localhost.")

    lines = [f"## {args.label} ({args.target})", "", "| Test | OWASP | Result |", "| --- | --- | --- |"]
    for name, owasp, fn in CASES:
        try:
            result = fn(args.target)
        except Exception as exc:  # report the error instead of stopping the whole run
            result = f"ERROR: {exc}"
        lines.append(f"| {name} | {owasp} | {result} |")
    report = "\n".join(lines) + "\n"
    print(report)

    os.makedirs("results", exist_ok=True)
    safe_label = "".join(c if c.isalnum() or c in "._-" else "-" for c in args.label)
    with open(os.path.join("results", f"waf_{safe_label}.md"), "w", encoding="utf-8") as f:
        f.write(report)


if __name__ == "__main__":
    main()
