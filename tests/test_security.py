"""Security regression tests: one group per planted vulnerability.

On the `vulnerable` branch these tests FAIL, which is the evidence that each
flaw exists. On `main` (secure) they PASS, which proves each fix works. In CI
they stop any change that brings a flaw back.
"""
import hashlib
import re

import pytest

from app import create_app
from conftest import IDS, PASSWORDS, logged_in_user, login


# VULN-1 (A05 Injection): SQL injection ------------------------------------

def test_login_rejects_sql_injection(client):
    # A quote and an SQL comment in the username must not bypass the password check.
    login(client, "alice' --", "anything")
    assert logged_in_user(client) is None


def test_course_search_treats_input_as_text(client):
    # A search term containing SQL must be searched for literally, so it matches nothing.
    login(client, "alice")
    r = client.get("/courses", query_string={"q": "zzz' OR '1'='1' --"})
    assert r.status_code == 200
    assert b"No courses match" in r.data


# VULN-2 (A05 Injection): stored cross-site scripting ----------------------

def test_profile_html_is_escaped(client):
    login(client, "alice")
    client.post("/profile", data={"about": "<script>alert('xss')</script>"})
    client.get("/logout")
    login(client, "bob")
    r = client.get(f"/students/{IDS['alice']}")
    assert b"<script>alert" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_content_security_policy_header(client):
    r = client.get("/login")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "script-src 'self'" in csp or "default-src 'self'" in csp


# VULN-3 (A01 Broken Access Control): IDOR and missing role check ----------

def test_student_cannot_view_other_students_grades(client):
    login(client, "alice")
    r = client.get(f"/grades?student_id={IDS['bob']}")
    assert r.status_code == 403


def test_student_cannot_edit_grades(client):
    login(client, "bob")
    r = client.post("/grades/edit", data={"grade_id": 4, "grade": "A"})
    assert r.status_code == 403


# VULN-4 (A07 Authentication Failures): weak hashing, no rate limit --------

def test_passwords_are_not_stored_as_md5(app):
    import sqlite3
    conn = sqlite3.connect(app.config["DATABASE"])
    stored = conn.execute("SELECT password_hash FROM users WHERE username = 'bob'").fetchone()[0]
    conn.close()
    assert stored != hashlib.md5(PASSWORDS["bob"].encode()).hexdigest()
    assert not re.fullmatch(r"[0-9a-f]{32}", stored)


def test_repeated_failed_logins_are_limited(client):
    for _ in range(5):
        login(client, "bob", "wrong-guess")
    r = login(client, "bob", PASSWORDS["bob"])
    assert r.status_code == 429
    assert logged_in_user(client) is None


# VULN-5 (A02 Security Misconfiguration): hardcoded secret, cookie flags ---

def test_secret_key_comes_from_environment(app, monkeypatch):
    import os
    assert app.config["SECRET_KEY"] == os.environ["UNIPORTAL_SECRET_KEY"]
    monkeypatch.delenv("UNIPORTAL_SECRET_KEY")
    with pytest.raises(RuntimeError):
        create_app({"TESTING": True, "DATABASE": app.config["DATABASE"]})


def test_session_cookie_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


# VULN-6 (A03 Software Supply Chain Failures) is checked by pip-audit in CI.
