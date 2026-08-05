"""
conftest.py — shared pytest fixtures for Kelan Security Python tests.
"""
import os

# Set test env vars before any imports touch settings.
# These must be set before any kelan.* import, because pydantic-settings
# reads env vars at class definition time.
os.environ.setdefault("OLLAMA_MODEL", "qwen2.5:3b")
os.environ.setdefault("OLLAMA_ENDPOINT", "http://localhost:11434")
os.environ.setdefault("REQUIRE_PQ", "false")
os.environ.setdefault("KELAN_JWT_SECRET", "test-secret-kelan-ci")
os.environ.setdefault("KELAN_MODE", "hybrid")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///tmp/test_kelan.db")
