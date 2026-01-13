# CI trigger comment

from flask import Flask
import os
import psycopg

app = Flask(__name__)

@app.route("/")
def home():
    return "DevSecOps MVP is running"

@app.route("/db-test")
def db_test():
    try:
        conn = psycopg.connect(
            host=os.getenv("DB_HOST", "db"),
            dbname=os.getenv("DB_NAME", "devops_db"),
            user=os.getenv("DB_USER", "devops_user"),
            password=os.getenv("DB_PASSWORD", "devops_pass123"),
            port=int(os.getenv("DB_PORT", "5432")),
        )
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            result = cur.fetchone()[0]
        conn.close()
        return {"ok": True, "result": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
