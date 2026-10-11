"""In-process HTTP request store + sender — thin-mode replacement for Caido.

The agent builds requests from the API spec and sends them directly over
``httpx``; there is no proxy, no passive capture, and no container. Every
request/response is kept here with a stable ``req_xxxxxxxx`` id so the model
can list, view, and replay-with-modifications exactly as it did with Caido.

Scope is an explicit allow/deny host check run **before** any request leaves
the process, so an out-of-scope target is refused rather than silently sent.
"""

from __future__ import annotations

import fnmatch
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import httpx


# Cap stored body text so a huge/binary response can't blow up memory; the
# model-facing tool output is bounded separately by the factory.
_MAX_STORED_BODY = 200_000


class OutOfScopeError(Exception):
    """Raised when a target host is not allowed by the active scope."""


@dataclass
class StoredRequest:
    id: str
    method: str
    url: str
    headers: dict[str, str]
    body: str | None
    cookies: dict[str, str]
    created_at: float
    response: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class RequestStore:
    """Holds sent requests and the one shared async HTTP client for a scan."""

    allowlist: list[str] = field(default_factory=list)  # host/url globs; empty = allow all
    denylist: list[str] = field(default_factory=list)  # always wins over allowlist
    verify_tls: bool = False  # staging targets routinely use self-signed certs
    timeout: float = 30.0

    _requests: dict[str, StoredRequest] = field(default_factory=dict)
    _order: list[str] = field(default_factory=list)
    _client: httpx.AsyncClient | None = None

    # -- client lifecycle -------------------------------------------------
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            # ponytail: HTTP/1.1 only (no h2 dep); AsyncClient already pools
            # connections for parallel sends. Enable http2 if raw protocol
            # tests ever need it.
            self._client = httpx.AsyncClient(
                verify=self.verify_tls,
                follow_redirects=False,  # a pentest wants to see 30x, not chase it
                timeout=self.timeout,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- scope ------------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname or ""

        def matches(pattern: str) -> bool:
            target = url if ("://" in pattern or "/" in pattern) else host
            return fnmatch.fnmatch(target, pattern)

        if any(matches(p) for p in self.denylist):
            return False
        if not self.allowlist:
            return True
        return any(matches(p) for p in self.allowlist)

    # -- store ------------------------------------------------------------
    def get(self, request_id: str) -> StoredRequest | None:
        return self._requests.get(request_id)

    def all(self) -> list[StoredRequest]:
        return [self._requests[i] for i in self._order]

    def existing_ids(self, request_ids: list[str]) -> set[str]:
        return {rid for rid in request_ids if rid in self._requests}

    def _add(self, req: StoredRequest) -> None:
        self._requests[req.id] = req
        self._order.append(req.id)

    # -- send -------------------------------------------------------------
    async def send(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        cookies: dict[str, str] | None = None,
    ) -> StoredRequest:
        """Send one request over httpx and store it (response or error)."""
        if not self.in_scope(url):
            raise OutOfScopeError(
                f"{urlparse(url).hostname or url!r} is out of scope "
                "(blocked by scope_rules before any bytes were sent)"
            )

        method = (method or "GET").upper()
        headers = dict(headers or {})
        cookies = dict(cookies or {})
        stored = StoredRequest(
            id=f"req_{secrets.token_hex(4)}",
            method=method,
            url=url,
            headers=headers,
            body=body,
            cookies=cookies,
            created_at=time.time(),
        )

        start = time.perf_counter()
        try:
            resp = await self.client().request(
                method,
                url,
                headers=headers or None,
                cookies=cookies or None,
                content=body.encode("utf-8") if isinstance(body, str) else None,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            text = resp.text
            truncated = len(text) > _MAX_STORED_BODY
            stored.response = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": text[:_MAX_STORED_BODY],
                "body_truncated": truncated,
                "length": len(resp.content),
                "elapsed_ms": round(elapsed_ms, 1),
                "http_version": resp.http_version,
            }
        except httpx.HTTPError as exc:
            stored.error = f"{type(exc).__name__}: {exc}"

        self._add(stored)
        return stored


def apply_modifications(base: StoredRequest, mods: dict[str, Any]) -> dict[str, Any]:
    """Overlay a ``repeat_request`` patch onto a stored request.

    Recognized keys: ``url``, ``method``, ``params`` (query merge),
    ``headers`` (merge), ``cookies`` (merge), ``body`` (replace).
    """
    url = str(mods.get("url") or base.url)
    params = mods.get("params")
    if isinstance(params, dict) and params:
        parts = urlsplit(url)
        merged = dict(parse_qsl(parts.query, keep_blank_values=True))
        merged.update({str(k): str(v) for k, v in params.items()})
        url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(merged), parts.fragment)
        )

    headers = {**base.headers, **(mods.get("headers") or {})}
    cookies = {**base.cookies, **(mods.get("cookies") or {})}
    body = mods.get("body", base.body)
    method = str(mods.get("method") or base.method)
    return {
        "method": method,
        "url": url,
        "headers": {str(k): str(v) for k, v in headers.items()},
        "cookies": {str(k): str(v) for k, v in cookies.items()},
        "body": body,
    }
