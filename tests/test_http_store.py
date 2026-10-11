"""Thin-mode HTTP store: scope gating, modification merge, send+store."""

from __future__ import annotations

import httpx
import pytest

from strix.tools.proxy.http_store import (
    OutOfScopeError,
    RequestStore,
    StoredRequest,
    apply_modifications,
)


def test_scope_allow_deny() -> None:
    s = RequestStore()
    assert s.in_scope("https://x.test/a")  # empty allowlist = allow all

    s.allowlist = ["*.example.com", "api.test"]
    assert s.in_scope("https://api.example.com/users")
    assert s.in_scope("https://api.test/v1")
    assert not s.in_scope("https://evil.com/")

    s.denylist = ["*.example.com"]  # deny always wins
    assert not s.in_scope("https://api.example.com/users")


def test_apply_modifications_merges_not_replaces() -> None:
    req = StoredRequest(
        id="req_1",
        method="GET",
        url="https://api.test/users/1?page=1",
        headers={"Authorization": "Bearer A", "Accept": "application/json"},
        body=None,
        cookies={"s": "A"},
        created_at=0.0,
    )
    out = apply_modifications(
        req, {"headers": {"Authorization": "Bearer B"}, "params": {"page": "2", "limit": "5"}}
    )
    # overlaid
    assert out["headers"]["Authorization"] == "Bearer B"
    # inherited
    assert out["headers"]["Accept"] == "application/json"
    assert out["cookies"] == {"s": "A"}
    assert out["method"] == "GET"
    # query merged (page overwritten, limit added)
    assert "page=2" in out["url"] and "limit=5" in out["url"]


@pytest.mark.asyncio
async def test_send_stores_response_and_blocks_out_of_scope() -> None:
    s = RequestStore(allowlist=["api.test"])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"ok": True})

    s._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    req = await s.send(method="POST", url="https://api.test/orders", body='{"x":1}')
    assert req.response is not None
    assert req.response["status"] == 201
    assert s.get(req.id) is req
    assert s.existing_ids([req.id, "nope"]) == {req.id}

    with pytest.raises(OutOfScopeError):
        await s.send(method="GET", url="https://evil.com/")

    await s.aclose()
