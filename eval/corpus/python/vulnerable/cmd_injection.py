import os
import subprocess


def run_system_ping(host):
    # Command injection via os.system with formatted string
    os.system(f"ping -c 1 {host}")


def run_subproc_backup(backup_path):
    # Command injection via shell=True
    cmd = f"tar -czf backup.tar.gz {backup_path}"
    subprocess.Popen(cmd, shell=True)
