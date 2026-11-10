from flask import Flask, request
import sqlite3
import subprocess

app = Flask(__name__)

@app.route("/api/query")
def search_handler():
    term = request.args.get("term", "")
    return execute_query_internal(term)

def execute_query_internal(user_term):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    # Reachable SQL injection from route
    cur.execute(f"SELECT * FROM items WHERE name = '{user_term}'")
    return cur.fetchall()

def dead_admin_cleanup(cmd_param):
    # Unreachable dead code command injection
    subprocess.call(cmd_param, shell=True)

@app.route("/api/user")
def safe_user_handler():
    user_id = request.args.get("id", "0")
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE id = ?", (user_id,))
    return cur.fetchall()

if __name__ == "__main__":
    app.run(port=5000)
