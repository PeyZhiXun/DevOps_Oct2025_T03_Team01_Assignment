from flask import Flask, request, redirect, session, render_template, flash, abort, url_for
import os
import psycopg
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")


def get_conn():
    return psycopg.connect(
        host=os.getenv("DB_HOST", "db"),
        dbname=os.getenv("DB_NAME", "devops_db"),
        user=os.getenv("DB_USER", "devops_user"),
        password=os.getenv("DB_PASSWORD", "devops_pass@123"),
        port=int(os.getenv("DB_PORT", "5432")),
    )


def ensure_initial_admin():
    username = os.getenv("DEFAULT_ADMIN_USER", "admin")
    password = os.getenv("DEFAULT_ADMIN_PASS", "admin@123")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1;")
            exists = cur.fetchone()
            if not exists:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                    (username, generate_password_hash(password)),
                )
        conn.commit()


try:
    ensure_initial_admin()
except Exception:
    pass


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    return "DevSecOps MVP is running"


@app.route("/db-test")
def db_test():
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                result = cur.fetchone()[0]
        return {"ok": True, "result": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


# AUTH (feat/auth)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, password_hash, role FROM users WHERE username=%s",
                (username,),
            )
            row = cur.fetchone()

    if not row or not check_password_hash(row[1], password):
        flash("Invalid login")
        return redirect("/login")

    session["user_id"] = row[0]
    session["username"] = username
    session["role"] = row[2]

    if row[2] == "admin":
        return redirect("/admin")
    return redirect("/dashboard")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/login")


# ADMIN USERS (feat/admin-users)
@app.route("/admin", methods=["GET"])
@login_required
@admin_required
def admin_dashboard():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, role FROM users ORDER BY id;")
            users = cur.fetchall()

    return render_template("admin.html", users=users)


@app.route("/admin/create_user", methods=["POST"])
@login_required
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "user").strip()

    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for("admin_dashboard"))

    if role not in ("admin", "user"):
        flash("Role must be 'admin' or 'user'.")
        return redirect(url_for("admin_dashboard"))

    password_hash = generate_password_hash(password)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s);",
                    (username, password_hash, role),
                )
            conn.commit()
        flash(f"User '{username}' created.")
    except psycopg.errors.UniqueViolation:
        flash("That username already exists.")
    except Exception:
        flash("Failed to create user due to server error.")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id: int):
    if session.get("user_id") == user_id:
        flash("You cannot delete your own account while logged in.")
        return redirect(url_for("admin_dashboard"))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
            deleted = cur.rowcount
        conn.commit()

    if deleted:
        flash("User deleted.")
    else:
        flash("User not found.")

    return redirect(url_for("admin_dashboard"))


@app.route("/dashboard")
@login_required
def dashboard_placeholder():
    return "Dashboard placeholder (build in feat/file-dashboard)"


@app.errorhandler(403)
def forbidden(_):
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
