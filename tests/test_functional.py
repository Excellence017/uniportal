"""Normal behaviour that must keep working on both branches.

These tests show the security fixes do not break the application.
"""
from conftest import IDS, logged_in_user, login


def test_valid_login(client):
    login(client, "alice")
    assert logged_in_user(client) == "alice"


def test_wrong_password_is_rejected(client):
    login(client, "alice", "not-her-password")
    assert logged_in_user(client) is None


def test_student_sees_own_grades(client):
    login(client, "alice")
    r = client.get(f"/grades?student_id={IDS['alice']}")
    assert r.status_code == 200
    assert b"Alice Karimova" in r.data and b"SEC301" in r.data


def test_lecturer_can_view_and_edit_grades(client):
    login(client, "drsmirnova")
    r = client.get(f"/grades?student_id={IDS['bob']}")
    assert r.status_code == 200
    r = client.post("/grades/edit", data={"grade_id": 4, "grade": "B"}, follow_redirects=True)
    assert r.status_code == 200
    assert b">B<" in r.data


def test_course_search(client):
    login(client, "alice")
    r = client.get("/courses?q=Data")
    assert r.status_code == 200
    assert b"Databases" in r.data and b"Discrete" not in r.data


def test_profile_text_is_saved(client):
    login(client, "alice")
    client.post("/profile", data={"about": "I like databases & security"})
    r = client.get(f"/students/{IDS['alice']}")
    assert b"I like databases" in r.data
