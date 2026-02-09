from flask import Flask, request, redirect, session, render_template, flash, abort, url_for
import os
import psycopg
import requests
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
from flask import send_file

#Upload folder used for storing user files on the server.
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#Secret key is used to sign session cookies (prevents tampering).
#We read from env so secrets are not hard-coded in code for deployment.
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")


def get_conn():
    #Standardise DB connector using environment variables.
    #This keeps config consistent across local, CI, and deployment environments.
    return psycopg.connect(
        host=os.getenv("DB_HOST", "db"),
        dbname=os.getenv("DB_NAME", "devops_db"),
        user=os.getenv("DB_USER", "devops_user"),
        password=os.getenv("DB_PASSWORD", "devops_pass@123"),
        port=int(os.getenv("DB_PORT", "5432")),
    )

def init_db():
    """Creates the users table if it does not exist."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(200) NOT NULL,
                    role VARCHAR(20) NOT NULL
                );
            """)
        conn.commit()

def init_files_table():
    """Creates the files table to link uploads to users."""
     #Files table ensures data ownership by linking each file to a user_id.
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    filename TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
        conn.commit()

def ensure_initial_admin():
    #Bootstrap an initial admin account if none exists.
    #This makes the MVP usable immediately after deployment.
    username = os.getenv("DEFAULT_ADMIN_USER", "admin")
    password = os.getenv("DEFAULT_ADMIN_PASS", "admin@123")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1;")
            exists = cur.fetchone()
            if not exists:
                cur.execute(
                    #Passwords are stored as hashes (never plain text).
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                    (username, generate_password_hash(password)),
                )
        conn.commit()

#Initialise DB tables on app startup (simple MVP approach).
try:
    init_db()
    init_files_table()
    ensure_initial_admin()
except Exception as e:
    print(f"Error initializing DB: {e}")


def login_required(fn):
    #Authentication guard: blocks access for non-logged-in users.
    #This is used for all routes that require an authenticated session.
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    #Authorization guard: ensures only admins can access admin routes.
    #Non-admin users will receive a 403 Forbidden response.
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
    #Simple check to confirm the app is running.
    return "DevSecOps MVP is running"


@app.route("/db-test")
def db_test():
    # Simple DB connectivity check to validate configuration and connectivity.
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                result = cur.fetchone()[0]
        return {"ok": True, "result": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500
    

#AUTH (feat/auth)
@app.route("/login", methods=["GET", "POST"])
def login():
    #GET shows login form; POST authenticates user credentials.
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_conn() as conn:
        with conn.cursor() as cur:
            #Query user record by username.
            cur.execute(
                "SELECT id, password_hash, role FROM users WHERE username=%s",
                (username,),
            )
            row = cur.fetchone()

    #Password verification uses hashing check, not direct string comparison.
    if not row or not check_password_hash(row[1], password):
        flash("Invalid login")
        return redirect("/login")

    #Store minimal session state (used for RBAC checks and data isolation).
    session["user_id"] = row[0]
    session["username"] = username
    session["role"] = row[2]

    #Role-based routing: admins go to /admin, users go to /dashboard.
    if row[2] == "admin":
        return redirect("/admin")
    return redirect("/dashboard")


#Clears the session to log the user out securely.
@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/login")


#ADMIN USERS (feat/admin-users)
@app.route("/admin", methods=["GET"])
@login_required
@admin_required
    #Admin dashboard lists all registered users (admin-only).
def admin_dashboard():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, role FROM users ORDER BY id;")
            users = cur.fetchall()

    return render_template("admin.html", users=users)


@app.route("/admin/create_user", methods=["POST"])
#Admin-only endpoint for creating a new user account.
#Password is stored as a hash; role is validated.
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

        #Discord notification: demonstrates stakeholder alerts
        #Uses a webhook URL stored in environment variables.
        webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
        
        print(f"DEBUG: Webhook URL found in env: {webhook_url}", flush=True)

        if webhook_url:
            try:
                print("DEBUG: Preparing to send Discord request...", flush=True)
                admin_name = session.get("username", "An Admin")
                
                payload = {
                    "content": f"**Team Alert!**\nAdmin `{admin_name}` just created a new user:\n**User:** `{username}`\n**Role:** `{role}`"
                }
                
                response = requests.post(webhook_url, json=payload)
                print(f"DEBUG: Discord response code: {response.status_code}", flush=True)
                print(f"DEBUG: Discord response text: {response.text}", flush=True)
                
            except Exception as e:
                print(f"DEBUG ERROR: Failed to send Discord alert: {e}", flush=True)
        else:
            print("DEBUG: Webhook URL is NONE. Environment variable not loaded!", flush=True)

        flash(f"User '{username}' created successfully.")
        
    except psycopg.errors.UniqueViolation:
        flash("That username already exists.")
    except Exception as e:
        print(f"Error creating user: {e}")
        flash("Failed to create user due to server error.")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id: int):
    #Prevents admins from deleting their own account while logged in (safety check).
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


@app.route("/dashboard", methods=["GET", "POST"])
    #User dashboard: shows only the current user's uploaded files (data isolation).
@login_required
def dashboard():
    user_id = session["user_id"]

    if request.method == "POST":
        if 'file' not in request.files:
            flash('No file part')
            return redirect(url_for("dashboard"))
            
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for("dashboard"))
            
        if file:
            filename = secure_filename(file.filename)
            
            #Stores file to local uploads directory and records metadata in DB.
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO files (user_id, filename, filepath) VALUES (%s, %s, %s)",
                        (user_id, filename, save_path)
                    )
                conn.commit()
            flash('File uploaded successfully')

    #Query only files owned by the current logged-in user.
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, filename FROM files WHERE user_id = %s",
                (user_id,)
            )
            my_files = cur.fetchall()

    return render_template("dashboard.html", files=my_files, username=session.get("username"))

@app.route("/dashboard/download/<int:file_id>")
@login_required
def download_file(file_id):
    #Data isolation enforcement: file download must match BOTH file_id and user_id.
    #This prevents users from downloading other users' files by guessing IDs.
    user_id = session["user_id"]
    
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT filepath, filename FROM files WHERE id = %s AND user_id = %s",
                (file_id, user_id)
            )
            file_record = cur.fetchone()
            
    if file_record:
        return send_file(file_record[0], as_attachment=True, download_name=file_record[1])
    else:
        flash("Access Denied: You do not own this file.")
        return redirect("/dashboard")

@app.route("/dashboard/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    #Data isolation enforcement: only the owner can delete the file record and disk file.
    user_id = session["user_id"]

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT filepath FROM files WHERE id = %s AND user_id = %s",
                (file_id, user_id)
            )
            result = cur.fetchone()
            
            if result:
                filepath = result[0]
                
                #Delete the DB record first, then attempt disk cleanup.
                cur.execute("DELETE FROM files WHERE id = %s", (file_id,))
                conn.commit()
                
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    flash("File deleted successfully.")
                except Exception as e:
                    print(f"Error deleting file from disk: {e}")
                    flash("File record deleted, but disk cleanup failed.")
            else:
                flash("Error: File not found or Access Denied.")

    return redirect("/dashboard")

@app.errorhandler(403)
def forbidden(_):
     #Custom 403 page to show unauthorized access (RBAC enforcement).
    return render_template("403.html"), 403

@app.after_request
def add_security_headers(response):
    #Basic hardening headers to reduce common browser attacks.
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
