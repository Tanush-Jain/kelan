import sqlite3


def search_users(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQLi via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

