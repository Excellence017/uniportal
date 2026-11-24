"""Database schema and synthetic demo data for UniPortal.

All names, accounts and grades are invented for the lab. No real data is used.
"""
import sqlite3

SCHEMA = """
DROP TABLE IF EXISTS grades;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('student', 'lecturer')),
    about         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE courses (
    id       INTEGER PRIMARY KEY,
    code     TEXT NOT NULL,
    title    TEXT NOT NULL,
    lecturer TEXT NOT NULL
);

CREATE TABLE grades (
    id         INTEGER PRIMARY KEY,
    student_id INTEGER NOT NULL REFERENCES users (id),
    course_id  INTEGER NOT NULL REFERENCES courses (id),
    grade      TEXT NOT NULL
);
"""

# (username, password, full name, role, about)
DEMO_USERS = [
    ("alice", "Alice#Lab2026", "Alice Karimova", "student",
     "Second-year computer science student."),
    ("bob", "sunshine", "Bobur Rahimov", "student",
     "Interested in networks and cloud."),
    ("drsmirnova", "Lecturer#Lab2026", "Dr. Elena Smirnova", "lecturer",
     "Module leader, Applied Security."),
]

DEMO_COURSES = [
    ("CS101", "Introduction to Programming", "Dr. Elena Smirnova"),
    ("CS205", "Databases", "Dr. Timur Aliev"),
    ("SEC301", "Applied Security", "Dr. Elena Smirnova"),
    ("MTH110", "Discrete Mathematics", "Dr. Nodira Yusupova"),
]

# (username, course code, grade)
DEMO_GRADES = [
    ("alice", "CS101", "A"),
    ("alice", "CS205", "B+"),
    ("alice", "SEC301", "A-"),
    ("bob", "CS101", "C"),
    ("bob", "MTH110", "B-"),
    ("bob", "SEC301", "C+"),
]


def init_db(path, hash_password):
    """Create the schema and load demo data, hashing passwords with the given function."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for username, password, full_name, role, about in DEMO_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, role, about) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, hash_password(password), full_name, role, about),
        )
    for code, title, lecturer in DEMO_COURSES:
        conn.execute(
            "INSERT INTO courses (code, title, lecturer) VALUES (?, ?, ?)",
            (code, title, lecturer),
        )
    for username, code, grade in DEMO_GRADES:
        conn.execute(
            "INSERT INTO grades (student_id, course_id, grade) VALUES ("
            "(SELECT id FROM users WHERE username = ?), "
            "(SELECT id FROM courses WHERE code = ?), ?)",
            (username, code, grade),
        )
    conn.commit()
    conn.close()
