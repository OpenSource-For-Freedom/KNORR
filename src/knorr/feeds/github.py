"""Minimal GitHub client: code-search malicious Dockerfiles + fetch content.

Read-only. Used by the Dockerfile-in-git scanner to reach the pre-publish
supply-chain surface (PRD 7.3) -- malicious build files in source repos that a
registry-only scan never sees.
"""

from __future__ import annotations

import base64
import logging
import time

import requests

from .. import config

log = logging.getLogger(__name__)


class GitHubClient:
    def __init__(self, token: str | None = None, session=None) -> None:
        self.token = token if token is not None else config.GITHUB_TOKEN
        self.session = session or requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": config.USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"

    def search_code(self, query: str, per_page: int = 20) -> list[dict]:
        """Code search; returns items (each: repository.full_name, path, html_url).

        Backs off once on a secondary-rate-limit (403/422 with a Retry-After).
        """
        for attempt in range(2):
            resp = self.session.get(
                f"{config.GITHUB_API_URL}/search/code",
                params={"q": query, "per_page": per_page}, timeout=config.HTTP_TIMEOUT)
            if resp.status_code == 200:
                return resp.json().get("items", [])
            if resp.status_code in (403, 429) and attempt == 0:
                wait = int(resp.headers.get("Retry-After", "12"))
                log.warning("github search rate-limited; backing off %ss", wait)
                time.sleep(min(wait, 30))
                continue
            log.warning("github search %s for %r", resp.status_code, query)
            return []
        return []

    def get_content(self, repo_full: str, path: str, ref: str | None = None) -> str | None:
        """Fetch a file's text via the contents API (base64-decoded). None on error."""
        url = f"{config.GITHUB_API_URL}/repos/{repo_full}/contents/{path}"
        try:
            resp = self.session.get(url, params={"ref": ref} if ref else {},
                                    timeout=config.HTTP_TIMEOUT)
        except requests.RequestException:
            return None
        if resp.status_code != 200:
            return None
        data = resp.json()
        if isinstance(data, dict) and data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode("utf-8", "ignore")
            except (ValueError, KeyError):
                return None
        return None
