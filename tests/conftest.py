import os
import secrets
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# The secure version reads its signing key from the environment.
os.environ.setdefault("UNIPORTAL_SECRET_KEY", "test-" + secrets.token_hex(16))

from app import create_app  # noqa: E402

PASSWORDS = {"alice": "Alice#Lab2026", "bob": "sunshine", "drsmirnova": "Lecturer#Lab2026"}
IDS = {"alice": 1, "bob": 2, "drsmirnova": 3}


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db")})


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username, password=None):
    return client.post(
        "/login",
        data={"username": username, "password": password or PASSWORDS[username]},
    )


def logged_in_user(client):
    with client.session_transaction() as s:
        return s.get("username")
