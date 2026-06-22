"""Package entrypoint for the FastAPI app."""

from semantic_firewall.apps.api_server import app


def create_app():
    """Return the FastAPI app instance."""
    return app


__all__ = ["app", "create_app"]

