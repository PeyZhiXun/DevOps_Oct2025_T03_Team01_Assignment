import sys
from pathlib import Path

# This fixes: ModuleNotFoundError: No module named 'app'
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import os
import importlib
import pytest
import psycopg
from werkzeug.security import generate_password_hash

os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "5432")
os.environ.setdefault("DB_NAME", "devops_db")
os.environ.setdefault("DB_USER", "devops_user")
os.environ.setdefault("DB_PASSWORD", "devops_pass@123")

@pytest.fixture(scope="session")
def db_conn():
    conn = psycopg.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME", "devops_db"),
        user=os.getenv("DB_USER", "devops_user"),
        password=os.getenv("DB_PASSWORD", "devops_pass@123"),
    )
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_tables(db_conn):
    """
    Clean DB tables before each test so tests are repeatable.
    """
    with db_conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL,
                role VARCHAR(20) NOT NULL
            );
        """)
            
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cur.execute("DELETE FROM files;")
        cur.execute("DELETE FROM users;")
        db_conn.commit()


def create_user(db_conn, username, password, role="user"):
    """
    Helper to seed test users directly in DB.
    """
    pw_hash = generate_password_hash(password)
    with db_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id;",
            (username, pw_hash, role),
        )
        user_id = cur.fetchone()[0]
    db_conn.commit()
    return user_id


@pytest.fixture()
def seed_users(db_conn):
    """
    Creates:
      admin1 / AdminPass123! (admin)
      alice  / AlicePass123! (user)
      bob    / BobPass123!   (user)
    """
    admin_id = create_user(db_conn, "admin1", "AdminPass123!", role="admin")
    user1_id = create_user(db_conn, "alice", "AlicePass123!", role="user")
    user2_id = create_user(db_conn, "bob", "BobPass123!", role="user")
    return {"admin_id": admin_id, "user1_id": user1_id, "user2_id": user2_id}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """
    Flask test client:
    - Forces a test secret key
    - Uses a temp upload folder so we don't write to your real uploads directory
    """
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret")

    # Import your Flask app module (app/app.py) safely
    import app.app as app_module
    importlib.reload(app_module)

    app_module.app.config.update(
        {
            "TESTING": True,
            "UPLOAD_FOLDER": str(tmp_path),
        }
    )

    with app_module.app.test_client() as c:
        yield c
