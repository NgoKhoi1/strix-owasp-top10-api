---
name: api_inventory_management
description: OWASP API9 — old/undocumented API versions, non-prod hosts, and shadow/debug endpoints
---

# Improper Inventory Management (API9:2023)

Organizations lose track of what they expose: an old `/v1` left running after
`/v2` shipped, a staging host reachable from the internet, a debug route, an
endpoint the spec never documented. These shadow surfaces are rarely patched or
monitored, so a weakness fixed on the current API often still lives on an old
one. The goal here is **discovery of surface the spec omits**, then testing it
with the other API skills.

Thin-mode tools: enumerate candidates with `send_request`, and when you find a
sibling, `repeat_request` a known-good current request against it (swap the host
or version segment) to see if it answers.

## What to look for

**Version siblings**
- If the documented base is `/v2`, probe `/v1`, `/v3`, `/beta`, `/internal`,
  `/legacy` with an otherwise-identical request. An old version that still
  answers — especially one that accepts the same token — is the finding; then
  test it for the bugs (BOLA/BFLA/auth) the current version fixed.
- Look for the version in the path (`/api/v1/...`), a header (`Accept:
  application/vnd.x.v1+json`, `X-API-Version`), or a query param, and vary each.

**Non-production / wrong-environment hosts**
- Hostname patterns: `staging.`, `dev.`, `test.`, `uat.`, `qa.`, `sandbox.`,
  `api-internal.`, `old.`, numbered (`api2.`). Only probe hosts that are within
  the authorized scope — do not expand scope to go hunting new hostnames.
- A non-prod environment answering production-style requests often has weaker
  auth, verbose errors, or real data.

**Undocumented / shadow endpoints**
- Compare what the spec declares against what responds: siblings of documented
  paths (`/users/{id}` → `/users/{id}/export`, `/users/search`, `/users/bulk`),
  obvious CRUD verbs the spec omits, and resource roots that list.
- Method expansion: an endpoint documented for `GET` that also answers `PUT` /
  `DELETE` / `PATCH` (send those via `send_request` and read the status).

**Debug / introspection / meta surfaces**
- `/debug`, `/actuator`, `/metrics`, `/health`, `/status`, `/swagger`,
  `/openapi.json`, `/.well-known/`, `/graphql` (introspection), `/console`.
- A reachable spec/introspection endpoint is itself inventory leakage and feeds
  every other test — grab it first and use it to widen the endpoint list.

**Deprecated-but-live**
- Responses carrying `Deprecation` / `Sunset` headers that still function, or
  docs referencing retired endpoints that still answer.

## Proving it

- Capture the request_id of the undocumented/old endpoint responding, plus the
  documented-equivalent request it mirrors, so the report shows "this surface is
  not in the spec yet returns data / accepts this method".
- Inventory leakage (an open `/openapi.json`, `/metrics`, verbose `/actuator`) is
  a finding on its own under API8/API9; an old version that is also exploitable is
  a higher-severity chained finding — report the concrete downstream bug too.

## Not a finding

- A documented version appearing exactly as the spec says.
- A `404`/`401` on a probed sibling (surface absent or properly gated).
- `/health` or `/openapi.json` that is intentionally public and leaks nothing
  sensitive — note it, but weigh severity by what it actually discloses.

## Remediation (for the report)

- Maintain an authoritative, current API inventory; retire or firewall old
  versions and non-prod hosts; keep the spec in sync with what is deployed;
  remove debug/introspection surfaces from production; and front deprecated
  endpoints with `Sunset` and real removal.
