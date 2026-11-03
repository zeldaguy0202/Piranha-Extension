"""Compatibility entry point. Prefer: uvicorn app.main:app --app-dir Backend --reload"""

from app.main import app

__all__ = ["app"]
