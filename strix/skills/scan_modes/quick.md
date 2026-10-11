---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities
---

# Quick Testing Mode

Time-boxed assessment focused on high-impact vulnerabilities. Prioritize breadth over depth.

## Approach

Optimize for fast feedback on critical security issues. Skip exhaustive enumeration in favor of targeted testing on high-value attack surfaces.

## Phase 1: Rapid Orientation

- Pull the endpoint inventory from the API spec; pick the highest-value
  operations (auth, object-scoped reads/writes, admin actions).
- Map the principals available in scope (tokens/tenants/roles) for authz diffs.
- Skip exhaustive enumeration—test what the spec and provided credentials make
  immediately reachable.

## Phase 2: High-Impact Targets

Test in priority order (OWASP API Top 10):

1. **Broken Object Level Auth (API1/BOLA)** - cross-principal object access
2. **Broken Function Level Auth (API5/BFLA)** - low-priv calling privileged ops
3. **Broken Authentication (API2)** - login/session/JWT weaknesses
4. **Broken Object Property Level Auth (API3)** - mass assignment, data exposure
5. **SSRF (API7)** - URL params, webhooks, integrations
6. **Security misconfig (API8)** - permissive CORS, verbose errors, headers

Skip for quick scans:
- Exhaustive undocumented-endpoint sweeps
- Low-severity information disclosure
- Theoretical issues without a working two-request PoC

## Phase 3: Validation

- Confirm exploitability with minimal proof-of-concept
- Demonstrate real impact, not theoretical risk
- Report findings immediately as discovered

## Chaining

When a strong primitive is found (auth weakness, injection point, internal access), immediately attempt one high-impact pivot to demonstrate maximum severity. Don't stop at a low-context "maybe"—turn it into a concrete exploit sequence that reaches privileged action or sensitive data.

## Operational Guidelines

- Drive each endpoint with `send_request`; prove authz issues with a
  `repeat_request` diff (same request, different principal/id).
- Use `list_requests`/`view_request` to inspect what you have sent.
- Skip broad fuzzing—use targeted probes only.
- Create subagents only for parallel high-priority tasks.

## Mindset

Think like a time-boxed bug bounty hunter going for quick wins. Prioritize breadth over depth on critical areas. If something looks exploitable, validate quickly and move on. Don't get stuck—if an attack vector isn't yielding results quickly, pivot.
