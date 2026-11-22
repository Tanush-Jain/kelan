import os


def read_user_report(filename):
    base_dir = "/var/reports"
    # Path traversal via open and path join
    filepath = os.path.join(base_dir, filename)
    with open(filepath, "r") as f:
        return f.read()

