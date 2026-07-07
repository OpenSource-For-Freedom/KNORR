"""Daemonless registry clients (Docker Hub / OCI Distribution API)."""

from .dockerhub import (
    DockerHubClient,
    ImageRef,
    ManifestResult,
    RateLimited,
    RegistryError,
    parse_image,
    parse_ratelimit,
)

__all__ = [
    "DockerHubClient",
    "ImageRef",
    "ManifestResult",
    "RateLimited",
    "RegistryError",
    "parse_image",
    "parse_ratelimit",
]
