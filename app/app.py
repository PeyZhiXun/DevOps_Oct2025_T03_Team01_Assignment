from flask import Flask, request, redirect, session, render_template, flash, abort
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username and password required")
        return redirect("/login")

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

    return redirect("/admin" if row[2] == "admin" else "/dashboard")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/login")


@app.route("/admin")
@login_required
def admin_placeholder():
    if session.get("role") != "admin":
        abort(403)
    return "Admin placeholder (build in feat/admin-users)"


@app.route("/dashboard")
@login_required
def dashboard_placeholder():
    return "Dashboard placeholder (build in feat/file-dashboard)"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
