"""
kelan.database — public re-export facade.
Imports from kelan.db.database for backwards compatibility.
"""
from kelan.db.database import (
    init_db,
    get_session,
    save_verdict,
    save_anomaly,
    fetch_verdicts,
    fetch_anomalies,
)

__all__ = [
    "init_db",
    "get_session",
    "save_verdict",
    "save_anomaly",
    "fetch_verdicts",
    "fetch_anomalies",
]
