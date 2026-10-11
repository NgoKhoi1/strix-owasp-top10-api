"""HTTP proxy tools (thin mode): host-side @function_tool wrappers over the
in-process :class:`~strix.tools.proxy.http_store.RequestStore`.

Same tool surface the agents knew from Caido — ``list_requests``,
``view_request``, ``repeat_request``, ``scope_rules`` — plus ``send_request``
to originate a request (no passive capture in thin mode). Caido's sitemap
tools are gone: the store has no request tree, so ``list_requests`` plus the
API spec are the inventory.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any, Literal

from agents import RunContextWrapper, function_tool

from strix.tools.nullish import clean_optional
from strix.tools.proxy.http_store import OutOfScopeError, RequestStore, apply_modifications


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from strix.tools.proxy.http_store import StoredRequest

ScopeAction = Literal["get", "list", "create", "update", "delete"]
RequestPart = Literal["request", "response"]


def _store(ctx: RunContextWrapper) -> RequestStore | None:
    inner: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    store = inner.get("http_store")
    return store if isinstance(store, RequestStore) else None


def _no_store() -> str:
    return json.dumps(
        {"success": False, "error": "HTTP request store not available in run context"},
        ensure_ascii=False,
        default=str,
    )


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {exc}"},
        ensure_ascii=False,
        default=str,
    )


def _result_payload(req: StoredRequest) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "success": req.error is None,
        "request_id": req.id,
        "method": req.method,
        "url": req.url,
    }
    if req.error is not None:
        payload["error"] = req.error
    if req.response is not None:
        payload["status"] = req.response["status"]
        payload["elapsed_ms"] = req.response["elapsed_ms"]
        payload["response"] = req.response
    return payload


async def existing_request_ids(ctx: RunContextWrapper, request_ids: list[str]) -> set[str]:
    """Return which of ``request_ids`` exist in the store (used by reporting)."""
    store = _store(ctx)
    if store is None or not request_ids:
        return set()
    return store.existing_ids(request_ids)


@function_tool(timeout=120, strict_mode=False)
async def send_request(
    ctx: RunContextWrapper,
    url: str,
    method: str = "GET",
    headers: dict[str, Any] | None = None,
    body: str | None = None,
    cookies: dict[str, Any] | None = None,
) -> str:
    """Send a brand-new HTTP request and store it for later replay.

    Use this to originate traffic (thin mode has no passive capture): build the
    request from the API spec, send it, then use ``repeat_request`` on the
    returned ``request_id`` to vary auth/IDs/params for authz tests.

    The target host must be in scope (see ``scope_rules``); an out-of-scope URL
    is refused before any bytes are sent.

    Args:
        url: Full absolute URL (``https://host/path?query``).
        method: HTTP method (default ``GET``).
        headers: Request headers to set.
        body: Raw request body string (e.g. a JSON document).
        cookies: Cookies to set.
    """
    store = _store(ctx)
    if store is None:
        return _no_store()
    try:
        req = await store.send(
            method=method, url=url, headers=headers, body=body, cookies=cookies
        )
    except OutOfScopeError as exc:
        return json.dumps({"success": False, "out_of_scope": True, "error": str(exc)}, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("send_request", exc)
    return json.dumps(_result_payload(req), ensure_ascii=False, default=str)


@function_tool(timeout=120, strict_mode=False)
async def repeat_request(
    ctx: RunContextWrapper,
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> str:
    """Repeat a stored request, overlaying only the fields you specify.

    Inherits everything from the original (method, URL, headers, cookies, body)
    and patches the keys in ``modifications``. This is the core authz-testing
    move: replay request A with tenant B's token/ID and compare responses.

    Args:
        request_id: ID from ``send_request`` / ``list_requests``.
        modifications: Patch dict. Recognized keys:

            - ``url`` — replace the URL.
            - ``method`` — replace the HTTP method.
            - ``params`` — dict of query-string keys to add/update.
            - ``headers`` — dict of headers to add/update.
            - ``cookies`` — dict of cookies to add/update.
            - ``body`` — replace the body string entirely.
    """
    store = _store(ctx)
    if store is None:
        return _no_store()
    base = store.get(request_id)
    if base is None:
        return json.dumps(
            {"success": False, "error": f"Request {request_id} not found"}, default=str
        )
    try:
        patched = apply_modifications(base, modifications or {})
        req = await store.send(**patched)
    except OutOfScopeError as exc:
        return json.dumps({"success": False, "out_of_scope": True, "error": str(exc)}, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("repeat_request", exc)
    return json.dumps(_result_payload(req), ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def list_requests(
    ctx: RunContextWrapper,
    httpql_filter: str | None = None,
    first: int = 50,
    sort_order: str = "desc",
) -> str:
    """List requests sent so far, newest first.

    Thin-mode filtering (no HTTPQL): ``httpql_filter`` is a plain
    case-insensitive substring matched against the method, URL, and response
    body — handy for sweeps like ``"password"`` or ``"/api/v1/"``.

    Args:
        httpql_filter: Case-insensitive substring to match (optional).
        first: Max entries to return (default 50).
        sort_order: ``asc`` or ``desc`` by send time.
    """
    store = _store(ctx)
    if store is None:
        return _no_store()
    try:
        needle = (clean_optional(httpql_filter) or "").lower()
        entries = []
        for req in store.all():
            body = (req.response or {}).get("body", "") if req.response else ""
            haystack = f"{req.method} {req.url} {body}".lower()
            if needle and needle not in haystack:
                continue
            entries.append(
                {
                    "request_id": req.id,
                    "method": req.method,
                    "url": req.url,
                    "status": (req.response or {}).get("status") if req.response else None,
                    "length": (req.response or {}).get("length") if req.response else None,
                    "created_at": req.created_at,
                    "error": req.error,
                }
            )
        if sort_order == "desc":
            entries.reverse()
        return json.dumps(
            {"success": True, "total": len(entries), "entries": entries[:first]},
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
        return _err("list_requests", exc)


def _render_request(req: StoredRequest) -> str:
    lines = [f"{req.method} {req.url}"]
    lines += [f"{k}: {v}" for k, v in req.headers.items()]
    if req.cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in req.cookies.items()))
    if req.body:
        lines += ["", req.body]
    return "\n".join(lines)


def _render_response(req: StoredRequest) -> str:
    resp = req.response
    if resp is None:
        return f"<no response: {req.error or 'not sent'}>"
    lines = [f"HTTP {resp['status']} ({resp.get('elapsed_ms')} ms)"]
    lines += [f"{k}: {v}" for k, v in resp.get("headers", {}).items()]
    lines += ["", resp.get("body", "")]
    return "\n".join(lines)


@function_tool(timeout=60)
async def view_request(
    ctx: RunContextWrapper,
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> str:
    """View a stored request or its response, optionally regex-searched.

    With ``search_pattern``: up to 20 regex hits with surrounding context.
    Without: the requested page of raw content plus a ``has_more`` flag.

    Args:
        request_id: ID from ``send_request`` / ``list_requests``.
        part: ``"request"`` or ``"response"``.
        search_pattern: Optional regex; switches to compact hit mode.
        page: 1-indexed page (only without ``search_pattern``).
        page_size: Lines per page.
    """
    store = _store(ctx)
    if store is None:
        return _no_store()
    req = store.get(request_id)
    if req is None:
        return json.dumps(
            {"success": False, "error": f"Request {request_id} not found"}, default=str
        )
    try:
        content = _render_request(req) if part == "request" else _render_response(req)
        if search_pattern:
            return json.dumps(_format_search_hits(content, search_pattern), default=str)
        return json.dumps(_format_text_page(content, page=page, page_size=page_size), default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("view_request", exc)


def _format_search_hits(content: str, pattern: str) -> dict[str, Any]:
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return {"success": False, "error": f"Invalid regex: {exc}"}
    hits = []
    for match in regex.finditer(content):
        start, end = match.span()
        hits.append(
            {
                "match": match.group(0),
                "position": start,
                "before": content[max(0, start - 40) : start],
                "after": content[end : end + 40],
            }
        )
        if len(hits) >= 20:
            break
    return {"success": True, "hits": hits, "total_hits": len(hits)}


def _format_text_page(content: str, *, page: int, page_size: int) -> dict[str, Any]:
    lines = content.splitlines()
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "success": True,
        "content": "\n".join(lines[start:end]),
        "page": page,
        "page_size": page_size,
        "total_lines": len(lines),
        "has_more": end < len(lines),
    }


@function_tool(timeout=30, strict_mode=False)
async def scope_rules(
    ctx: RunContextWrapper,
    action: ScopeAction,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> str:
    """Get or set the scope allow/deny host patterns checked before every send.

    Thin mode has one global scope (no named scopes). Patterns are globs
    (``*.example.com``, ``api.test.com``); a pattern containing ``/`` or
    ``://`` matches the full URL instead of the host. **Empty allowlist = allow
    all; denylist always wins.** An out-of-scope target is refused before any
    bytes are sent.

    Args:
        action: ``get`` / ``list`` read the current scope; ``create`` /
            ``update`` replace allowlist+denylist; ``delete`` clears both.
        allowlist: Host/URL globs to allow.
        denylist: Host/URL globs to deny.
    """
    store = _store(ctx)
    if store is None:
        return _no_store()
    try:
        if action in ("get", "list"):
            pass
        elif action == "delete":
            store.allowlist, store.denylist = [], []
        else:  # create / update
            if allowlist is not None:
                store.allowlist = [str(p) for p in allowlist]
            if denylist is not None:
                store.denylist = [str(p) for p in denylist]
        return json.dumps(
            {"success": True, "allowlist": store.allowlist, "denylist": store.denylist},
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
        return _err("scope_rules", exc)
