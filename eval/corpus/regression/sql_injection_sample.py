import subprocess


def handle_request(user_input, cmd):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)  # noqa: F821
    subprocess.call(cmd, shell=True)

