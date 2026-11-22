import subprocess


def safe_system_ping(host):
    # Safe command execution with argument array and shell=False
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)

