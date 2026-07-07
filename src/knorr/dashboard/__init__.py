"""Live threat-telemetry dashboard (stdlib http.server; no web framework dep)."""

from .app import serve

__all__ = ["serve"]
