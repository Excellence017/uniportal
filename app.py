"""UniPortal: a student portal built for the Applied Security Capstone.

WARNING: the `vulnerable` branch of this repository contains intentional
security flaws for teaching. Run it only on your own machine, bound to
127.0.0.1, and never expose it to a network.

On the `vulnerable` branch each planted flaw is marked VULN-<n> (<OWASP id>);
on `main` each fix is marked FIX-<n> at the same place.
"""
import os
import sqlite3
import time
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from db import init_db


def hash_password(password):
    # FIX-4 (A07): slow, salted, memory-hard hash (scrypt in Werkzeug 3).
    # Each password gets its own random salt, and every guess costs real time and memory.
    return generate_password_hash(password)


class LoginLimiter:
    """FIX-4 (A07): after MAX_FAILURES wrong passwords for one account from one
    address within WINDOW seconds, further attempts are refused with 429."""

    MAX_FAILURES = 5
    WINDOW = 15 * 60

    def __init__(self):
        self._failures = {}

    def _recent(self, key):
        now = time.monotonic()
        recent = [t for t in self._failures.get(key, []) if now - t < self.WINDOW]
        self._failures[key] = recent
        return recent

    def is_blocked(self, key):
        return len(self._recent(key)) >= self.MAX_FAILURES

    def record_failure(self, key):
        self._recent(key).append(time.monotonic())

    def reset(self, key):
        self._failures.pop(key, None)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def create_app(test_config=None):
    app = Flask(__name__)
    # FIX-5 (A02): the signing key lives outside the code, in an environment
    # variable. The app refuses to start without one instead of using a default.
    secret_key = os.environ.get("UNIPORTAL_SECRET_KEY")
    if not secret_key:
        raise RuntimeError("Set the UNIPORTAL_SECRET_KEY environment variable.")
    app.config["SECRET_KEY"] = secret_key
    # FIX-5 (A02): scripts cannot read the session cookie, and other sites
    # cannot send it with cross-site form posts.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("UNIPORTAL_HTTPS") == "1"
    app.config["DATABASE"] = os.environ.get("UNIPORTAL_DB", "uniportal.db")
    if test_config:
        app.config.update(test_config)

    if not os.path.exists(app.config["DATABASE"]):
        init_db(app.config["DATABASE"], hash_password)

    limiter = LoginLimiter()
    dummy_hash = hash_password("not-a-real-password")

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def security_headers(response):
        # FIX-2 (A05): second layer against XSS. Even if a script got into a page,
        # the browser only runs scripts loaded from this site, never inline ones.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    # FIX-5 (A02/A10): errors show a plain page; details go to the server log only.
    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, message="You do not have access to this page."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500, message="Something went wrong."), 500

    @app.cli.command("init-db")
    def init_db_command():
        """Reset the database to the demo data."""
        init_db(app.config["DATABASE"], hash_password)
        print("Database reset to demo data.")

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            limiter_key = (username.lower(), request.remote_addr)
            if limiter.is_blocked(limiter_key):
                flash("Too many failed attempts. Try again in 15 minutes.")
                return render_template("login.html"), 429
            # FIX-1 (A05): the query text is fixed; the username is sent separately as
            # a parameter, so the database always treats it as data, never as SQL.
            user = get_db().execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            # FIX-4 (A07): compare against the salted hash. For unknown users we still
            # run one hash check, so response time does not reveal which usernames exist.
            stored = user["password_hash"] if user else dummy_hash
            if check_password_hash(stored, password) and user:
                limiter.reset(limiter_key)
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))
            limiter.record_failure(limiter_key)
            flash("Invalid username or password.")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/grades")
    @login_required
    def grades():
        student_id = request.args.get("student_id", session["user_id"], type=int)
        # VULN-3 (A01): the student_id comes from the URL and is never checked
        # against the logged-in user. Changing the number shows anyone's grades.
        db = get_db()
        student = db.execute(
            "SELECT id, full_name FROM users WHERE id = ? AND role = 'student'",
            (student_id,),
        ).fetchone()
        if student is None:
            abort(404)
        rows = db.execute(
            "SELECT grades.id, courses.code, courses.title, grades.grade "
            "FROM grades JOIN courses ON courses.id = grades.course_id "
            "WHERE grades.student_id = ? ORDER BY courses.code",
            (student_id,),
        ).fetchall()
        return render_template("grades.html", student=student, rows=rows)

    @app.route("/grades/edit", methods=["POST"])
    @login_required
    def edit_grade():
        # VULN-3 (A01): any logged-in user can change a grade; the role is never checked.
        grade_id = request.form.get("grade_id", type=int)
        new_grade = request.form.get("grade", "").strip()[:3]
        db = get_db()
        row = db.execute("SELECT student_id FROM grades WHERE id = ?", (grade_id,)).fetchone()
        if row is None or not new_grade:
            abort(400)
        db.execute("UPDATE grades SET grade = ? WHERE id = ?", (new_grade, grade_id))
        db.commit()
        flash("Grade updated.")
        return redirect(url_for("grades", student_id=row["student_id"]))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        db = get_db()
        if request.method == "POST":
            about = request.form.get("about", "")[:500]
            db.execute("UPDATE users SET about = ? WHERE id = ?", (about, session["user_id"]))
            db.commit()
            flash("Profile saved.")
            return redirect(url_for("student", student_id=session["user_id"]))
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        return render_template("profile.html", user=user)

    @app.route("/students")
    @login_required
    def students():
        rows = get_db().execute(
            "SELECT id, full_name, role FROM users ORDER BY role DESC, full_name"
        ).fetchall()
        return render_template("students.html", rows=rows)

    @app.route("/students/<int:student_id>")
    @login_required
    def student(student_id):
        user = get_db().execute(
            "SELECT id, full_name, role, about FROM users WHERE id = ?", (student_id,)
        ).fetchone()
        if user is None:
            abort(404)
        return render_template("student.html", user=user)

    @app.route("/courses")
    @login_required
    def courses():
        q = request.args.get("q", "")
        # FIX-1 (A05): parameterised query; the search term can never change the SQL.
        pattern = f"%{q}%"
        rows = get_db().execute(
            "SELECT code, title, lecturer FROM courses "
            "WHERE title LIKE ? OR code LIKE ? ORDER BY code",
            (pattern, pattern),
        ).fetchall()
        return render_template("courses.html", rows=rows, q=q)

    return app


if __name__ == "__main__":
    application = create_app()
    # FIX-5 (A02): debug mode is off unless explicitly switched on for development.
    application.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=5000,
        debug=os.environ.get("UNIPORTAL_DEBUG") == "1",
    )
