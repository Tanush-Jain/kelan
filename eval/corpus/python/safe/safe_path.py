from pathlib import Path


def safe_read_report(report_id):
    # Validated path lookup without direct user filename interpolation
    safe_dir = Path("/var/reports").resolve()
    target_file = (safe_dir / f"{int(report_id)}.txt").resolve()
    if safe_dir in target_file.parents:
        return target_file.read_text(encoding="utf-8")
    raise ValueError("Invalid report ID")

