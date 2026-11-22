import sqlite3


def search_users_safe(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Safe parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()

