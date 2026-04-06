"""Package entrypoint for the FastAPI app.

This module intentionally re-exports the existing `api.py` app during the
compatibility phase so existing tests and monkeypatching behavior remain
unchanged.
"""

from api import app


def create_app():
    """Return the FastAPI app instance."""
    return app


__all__ = ["app", "create_app"]

