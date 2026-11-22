import subprocess


def handle_request(user_input, cmd):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    subprocess.call(cmd, shell=True)

