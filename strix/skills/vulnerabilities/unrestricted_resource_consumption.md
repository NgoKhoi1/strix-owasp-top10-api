---
name: unrestricted_resource_consumption
description: OWASP API4 — missing rate/size/pagination/complexity limits abusable for DoS, cost, or enumeration
---

# Unrestricted Resource Consumption (API4:2023)

An API that does not bound how much work a single caller can demand — requests
per window, response/page size, upload size, query complexity, or fan-out to
paid downstreams — can be driven into denial of service or runaway cost. Unlike
authorization bugs, the proof here is **quantitative**: show that the limit is
absent or far too high, with evidence, not that one request succeeded.

Thin-mode tools: build each probe with `send_request`, repeat at volume or with
a changed size parameter via `repeat_request`, and read status/timing/length
from each result. Concurrency is fine — issue many sends to measure a limit.

## What to test

**Rate limiting (per endpoint, per principal, per IP)**
- Send the same request N times in quick succession and watch for `429`,
  `Retry-After`, or `RateLimit-*` headers. No throttling after dozens of rapid
  requests to an expensive or auth endpoint is the finding.
- Test the limit on the endpoints that matter: login / OTP / password-reset
  (credential-stuffing and SMS/email cost), search, export, report generation.
- Check whether the limit is enforced per-token only (rotate/omit the token and
  see if the counter resets) — a per-token limit with open registration is weak.

**Pagination / response size**
- Drive `limit` / `page_size` / `per_page` / `count` far past the documented
  maximum (`?limit=100000`). If the API returns everything, it has no server-side
  cap — large responses exhaust memory/bandwidth.
- Request page 0 / negative / huge offsets and malformed values; note 5xx or
  full-table returns.

**Payload / upload size**
- Send a very large body (deeply nested JSON, long strings, large arrays) and a
  large declared `Content-Length` where accepted. Absent a size cap, this is an
  amplification/DoS vector. (httpx normalizes headers, so this is body-size, not
  malformed-framing, testing.)

**Query complexity / fan-out**
- GraphQL: deeply nested or aliased queries that multiply resolver work
  (see `protocols/graphql`). Batch arrays of operations in one request.
- REST: parameters that expand work — `include=`/`expand=` chains, wide date
  ranges, N-item batch endpoints, regex/search terms causing heavy scans.

**Third-party cost amplification**
- Operations that call a paid downstream per request (SMS, email, maps, LLM,
  image processing). Unbounded, these are a direct cost-DoS.

## Proving it

- Capture the request_ids for: one baseline request, and the burst/oversized
  request that shows no limit. Record the counts and timings that demonstrate the
  absence of a bound (e.g. "60 logins in 4s, all `200`, no `429`").
- Distinguish a real missing limit from a transient: if early requests 200 and a
  limit kicks in, the limit EXISTS — report the exact threshold only if it is set
  implausibly high for the operation's cost.
- Severity scales with the operation's cost and reachability: an unauthenticated,
  expensive, third-party-billed endpoint with no limit is high; a cheap
  authenticated read with a generous limit is informational.

## Not a finding

- A single slow response, or one large response you requested within documented
  limits.
- A `429`/`Retry-After` appearing — that is the control working; note the
  threshold only if it is set far too high for the operation.
- Latency of the proxy/your own network rather than the server.

## Remediation (for the report)

- Enforce per-user and per-IP rate limits with `429` + `Retry-After` on sensitive
  and expensive endpoints; cap `limit`/`page_size` server-side; cap request body
  and upload size; bound query depth/complexity and batch sizes; and put spend
  limits / quotas in front of paid downstreams.
