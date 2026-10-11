# Migration Plan — API Red-Team từ Strix (OWASP API Top 10)

> Paste file này vào một session mới để thực hiện. File tự chứa đủ context — không cần lịch sử hội thoại trước.

## 0. Bối cảnh (đọc trước khi làm gì)

**Nguồn:** `D:\AI_Thuc_Chien\VSF_Build_Phase\strix` — Strix, một tool pentest AstD multi-agent mã nguồn mở (Python 3.12+, quản lý bằng `uv`). Agent dựng trên SDK `agents` (`from agents import ...`, `from agents.sandbox import SandboxAgent`).

**Mục tiêu:** fork Strix thành một hệ thống AI red-team **chỉ xoay quanh OWASP API Security Top 10 (2023)**, theo thiết kế **thin / HTTP-only**:
- Agent **chỉ gửi HTTP request** (test authz/logic qua spec), **không chạy CLI tool tùy ý** → **không cần Docker sandbox**.
- Giữ nguyên engine multi-agent của Strix (điều phối, budget, report). Không viết lại coordinator.
- Thay layer proxy Caido (bám container) bằng `httpx` chạy in-process.

**Nguyên tắc xuyên suốt (ponytail):** lấy lại tối đa, viết mới tối thiểu. Giữ **nguyên signature tool** để skill/prompt không phải đổi. Không thêm abstraction thừa.

### Vì sao API Top 10 hợp với thiết kế này
Bug API nguy hiểm nhất là **"cùng request, token khác, vẫn thành công"** (authz-shaped), không phải payload-shaped. Chúng chỉ cần: ingest spec → đi từng endpoint → replay có sửa token/ID → so response. Không có mã tùy ý nào chạy → không cần cô lập.

---

## 1. Kiến trúc Strix (bản đồ để biết đụng đâu)

```
interface/ (CLI, TUI, viewer React, cloud)   ← DROP phần lớn
core/      runner · execution · agents · hooks · sessions   ← KEEP nguyên (engine)
agents/    factory.py · prompt.py · prompts/*.jinja          ← KEEP, chỉnh prompt + skill list
tools/     agents_graph, proxy, shell, reporting, coverage…  ← KEEP lõi, THAY proxy
skills/    vulnerabilities/*.md + tooling + scan_modes        ← THU HẸP về bộ API
runtime/   Docker sandbox + Caido bootstrap                   ← DROP (thin mode)
report/    findings · SARIF (CWE→STRIDE sẵn) · dedupe          ← KEEP nguyên
```

Trái tim multi-agent nằm gọn ở 3 file (agnostic với loại vuln, lấy nguyên):
- `strix/core/agents.py` — `AgentCoordinator`: owner duy nhất giữ state cây agent (statuses, parent_of, mailbox, budget, snapshot/resume).
- `strix/tools/agents_graph/tools.py` — 6 tool điều phối: `create_agent`, `agent_finish`, `wait_for_agents`, `send_message_to_agent`, `view_agent_graph`, `stop_agent`.
- `strix/agents/factory.py` — `build_strix_agent` lắp ráp agent; root dùng `finish_scan`, child dùng `agent_finish`; `tool_use_behavior` chỉ dừng khi lifecycle tool báo xong (`_finish_tool_use_behavior`, factory.py ~552).

---

## 2. KEEP / REPLACE / DROP (bảng quyết định)

### KEEP nguyên (không sửa logic)
- `strix/core/` toàn bộ — coordinator, runner, execution, hooks, sessions, inputs, paths.
- `strix/tools/agents_graph/`, `tools/reporting/`, `tools/coverage/`, `tools/notes/`, `tools/threat_model/`, `tools/finish/`, `tools/load_skill/`, `tools/thinking/`, `tools/todo/`, `tools/web_search/`, `tools/mcp/`.
- `strix/report/` — gồm SARIF đã map CWE→STRIDE (`report/sarif.py` ~103). **Việc thêm nhỏ:** thêm dict CWE→OWASP-API-category (~20 dòng) để report gắn nhãn API1..API10.
- `strix/skills/` layout + loader (`skills/__init__.py`) — cơ chế `register_skill_dir` cho phép thêm/override skill từ thư mục ngoài mà không sửa package.

### REPLACE (giữ signature, đổi ruột)
- **`strix/tools/proxy/`** — Caido → httpx. Xem Phần 4. **Giữ y signature** `list_requests`, `view_request`, `repeat_request`, (`list_sitemap`, `view_sitemap_entry`, `scope_rules` tùy chọn).
- **Agent base** — `SandboxAgent` → `Agent` thường của SDK `agents`; bỏ capabilities `Shell` + `Filesystem`. Xem Phần 5.

### DROP (thin mode — không cần)
- `strix/runtime/` toàn bộ (Docker client, session_manager, caido_bootstrap/handle, backends). → gỡ một trong hai lý do cần container.
- `strix/interface/tui/`, `strix/interface/viewer/` (React frontend), `strix/interface/cloud/`.
- `containers/` (Dockerfile, entrypoint).
- Tool shell/filesystem/browser: `exec_command`, `write_stdin`, `view_image`, `agent_browser` + skills `tooling/agent_browser`, `tooling/python`.
- Toàn bộ CLI-tool skills trong `tooling/` (nmap, ffuf, nuclei, sqlmap, httpx-cli, katana, naabu, subfinder, semgrep, hurl, hypothesis) — agent không gọi CLI ở v1.

### DEFER (nhánh tùy chọn, không làm ở v1)
- `sqlmap` (blind SQLi extraction) và `jwt_tool -C` (crack HMAC secret) là **chạy subprocess tùy ý** → kéo theo sandbox trở lại. Gate sau **một "deep-exploit agent" tùy chọn chạy trong sandbox**, không nhét vào hệ chính. Xem Phần 6.

---

## 3. OWASP API Top 10 (2023) — coverage & việc cần làm

| API | Tên | Skill Strix có sẵn | Việc |
|---|---|---|---|
| API1 | Broken Object Level Auth (BOLA) | `vulnerabilities/idor.md` + `custom/api_spec_testing.md` | Keep |
| API2 | Broken Authentication | `authentication_jwt.md`, `protocols/oauth.md`, `weak_password_detection.md` | Keep; JWT forge bằng PyJWT (Phần 6) |
| API3 | Broken Object Property Level Auth | `mass_assignment.md` + `information_disclosure.md` | Keep |
| API4 | Unrestricted Resource Consumption | — (chỉ `business_logic`, `race_conditions` chạm nhẹ) | **VIẾT MỚI skill** |
| API5 | Broken Function Level Auth | `broken_function_level_authorization.md` | Keep |
| API6 | Unrestricted Access to Sensitive Business Flows | `business_logic.md` (partial) | Keep; bổ sung note business-flow |
| API7 | SSRF | `ssrf.md` | Keep |
| API8 | Security Misconfiguration | `information_disclosure.md`, `header_injection.md` (CORS/headers) | Keep |
| API9 | Improper Inventory Management | `api_spec_testing.md` (undocumented siblings, partial) | **VIẾT MỚI skill** |
| API10 | Unsafe Consumption of APIs | — | Viết nếu target có integration bên thứ ba; else defer |

**2 skill phải viết mới** (file `.md`, đặt trong thư mục skill của fork, category `vulnerabilities/`):
1. `unrestricted_resource_consumption.md` (API4) — rate-limit/pagination/payload-size/batching abuse; đo bằng bắn request song song (`httpx.AsyncClient`).
2. `api_inventory_management.md` (API9) — phát hiện version cũ (`/v1` vs `/v2`), env non-prod, endpoint undocumented, debug routes.

---

## 4. Thay Caido bằng httpx (phần code mới thật sự)

**Caido thực chất là một request-store có trạng thái**, không chỉ "cái gửi request". Nó cho: passive capture, request-store + ID ổn định, HTTPQL query, sitemap, scope rules. Mô hình model nhìn thấy là *stateful*: browse → capture → list → chọn ID → modify → replay.

Với **spec-driven API testing**, agent tự dựng mọi request từ OpenAPI inventory → **passive capture gần như vô nghĩa**; phần phải giữ chỉ là **store + ID + replay**.

### Phải tự dựng
Một `RequestStore` nhỏ (in-process, có thể persist JSON để resume):
- Giữ mọi request/response agent đã gửi, cấp ID ổn định (`req_xxxxxxxx`).
- `repeat_request` kế thừa request gốc theo ID rồi overlay `modifications` (merge dict thuần — bê logic `apply_modifications`/`full_url_from_components` từ `caido_api.py`, bỏ phần raw-bytes).

### Giữ NGUYÊN signature (skill/prompt không đổi)
```python
# list_requests(ctx, httpql_filter=None, first=50, after=None, sort_by="timestamp",
#               sort_order="desc", scope_id=None) -> str (JSON)
#   → thay HTTPQL bằng filter Python cho 2-3 case thực dùng:
#     resp.code>=N, req.path chứa substring, quét toàn văn "password"/"secret".
# view_request(ctx, request_id, ...) -> str
# repeat_request(ctx, request_id, modifications: {url, params, headers, body, cookies}) -> str
#   → dùng httpx.AsyncClient gửi, trả {success, status, elapsed_ms, response:{status,headers,body}}
```

### Được thêm
- `httpx.AsyncClient` hỗ trợ HTTP/2 + async → **race condition (API6/API4) bắn N request song song dễ hơn Caido**.

### Caveat (flag, đừng giải quyết ở v1)
- httpx normalize header, **không gửi được request méo** (duplicate header, byte lạ) → mất khả năng test **request smuggling / header injection raw**. Những cái này **không thuộc core API Top 10**. Nếu cần sau: giữ một đường raw-socket riêng.

### Scope (bắt buộc giữ)
- Reimplement `scope_rules` thành **allowlist URL check trước khi gửi** trong `repeat_request`/client — chặn agent gọi out-of-scope. Rõ ràng hơn bản ngầm của Caido.

---

## 5. Đổi SandboxAgent → Agent (bỏ container)

File: `strix/agents/factory.py` → `build_strix_agent` (~663).

- Hiện: trả `SandboxAgent(..., capabilities=[Filesystem(...), Shell(...)])`.
- Đổi: dùng `Agent` thường của SDK `agents`, **bỏ `capabilities`**, bỏ `SandboxRunConfig` ở runner.
- **Kiểm tra trước khi đổi** (trong SDK `agents`): `Agent` thường có nhận `tools`, `instructions`, `tool_use_behavior`, và `RunContextWrapper` còn hoạt động như cũ không. Nếu SDK buộc `SandboxAgent` cho một số cơ chế, giữ `SandboxAgent` nhưng cấp một backend no-op/local thay vì Docker (xem `runtime/backends.py:register_backend` — có hook sẵn cho custom backend).
- `strix/core/runner.py` (~409): bỏ `sandbox=SandboxRunConfig(...)`; bỏ bring-up/teardown sandbox session (~359-372, ~685); bỏ `bootstrap_caido`. Khởi tạo `RequestStore` + `httpx.AsyncClient`, nhét vào context thay cho `caido_client`/`sandbox_session`.

Các tool trong `_BASE_TOOLS` (factory.py ~574) là `function_tool` thuần **không đụng sandbox** (think, load_skill, todo, notes, coverage, threat_model, web_search, reporting, agents_graph) → chạy nguyên. Chỉ cần gỡ shell/filesystem/browser tool khỏi agent.

---

## 6. JWT & SQLi — quyết định đã chốt

- **JWT forging** (alg=none, RS256→HS256 confusion, kid/jku/x5u/jwk injection, claim edit) → **viết bằng PyJWT (~30 dòng) trong luồng HTTP**, rồi replay token qua `repeat_request`. **Không cần CLI.** Mô hình đúng như `authentication_jwt.md` mô tả: tool sinh token, HTTP tool giao token.
- **JWT secret cracking** (`jwt_tool -C -d wordlist`, brute HMAC) → compute-bound, **không thay bằng HTTP được**. DEFER vào deep-exploit agent.
- **sqlmap** → blind/time-based detection + extraction, LLM làm tay rất yếu. DEFER vào deep-exploit agent.
- **Deep-exploit agent (tùy chọn, không v1):** một specialist chạy trong sandbox (dùng lại `runtime/` + `register_backend`), chỉ spawn khi gặp (a) tham số injectable xác nhận cần extract, hoặc (b) API HS256 nghi secret yếu. Hệ chính vẫn thin; chỉ con agent này mới cần container.

---

## 7. Thu hẹp skill về bộ API

File: `strix/agents/prompt.py` → `_resolve_skills` (~24). **Đây là điểm DUY NHẤT quyết định agent nạp skill gì.**

- Bỏ khỏi auto-load: `tooling/agent_browser`, `tooling/python` (không còn shell).
- Danh sách skill cho phép spawn (`create_agent(skills=[...])`) thu về đúng bộ API:
  ```
  idor, broken_function_level_authorization, mass_assignment, information_disclosure,
  authentication_jwt, weak_password_detection, ssrf, header_injection, business_logic,
  race_conditions, nosql_injection, sql_injection,
  unrestricted_resource_consumption (mới), api_inventory_management (mới),
  protocols/oauth, protocols/graphql, custom/api_spec_testing
  ```
- Drop skill ngoài phạm vi: `cloud/*`, `technologies/active_directory`, `electron_desktop_apps`, `subdomain_takeover`, `xss`, `ssti`, `csrf`, `prototype_pollution`, `xxe`, `open_redirect`, `insecure_file_uploads`, `path_traversal_lfi_rfi`, `insecure_deserialization`, `http_request_smuggling`, `argument_injection` (trừ khi target cần).
- `validate_requested_skills` (`skills/__init__.py` ~224) tự ăn theo danh sách thư mục → chỉ cần giới hạn skill có mặt trong search dir là đủ.

### Root prompt (orchestration)
File: `strix/agents/prompts/system_prompt.jinja` + skill `coordination/root_agent.md`. Chỉnh để root spawn specialist con **theo nhóm API**, gợi ý:
- Agent **Authorization** (API1 BOLA + API5 BFLA + API3 property-level) — nặng two-account diff.
- Agent **Authentication** (API2 + JWT/OAuth).
- Agent **Injection/SSRF** (API7 + sql/nosql injection).
- Agent **Resource/Business-flow** (API4 + API6).

### Input model (bắt buộc)
Hệ thống phải nhận qua instruction/context (giống block `--instruction` trong `skills/api-security-testing/SKILL.md`): **≥2 token / 2 tenant, example object IDs, tenant map, rate limits, out-of-scope routes, đường dẫn spec**. Đây là cấu hình, không phải code engine. Không bịa token; chỉ test API được uỷ quyền.

---

## 8. Thứ tự thực hiện (phased)

1. **Khởi tạo fork** — copy `strix/core/`, `strix/agents/`, `strix/skills/`, `strix/report/`, `strix/tools/` (trừ proxy/shell), `strix/config/`, `strix/utils/`. Bỏ `runtime/`, `interface/tui|viewer|cloud`, `containers/`. `make dev-install` (uv).
2. **Cắt sandbox** — Phần 5: `SandboxAgent`→`Agent`, bỏ Shell/Filesystem, dọn runner. Chạy được một agent đơn với tool thuần (think/web_search/reporting) là mốc xanh đầu tiên.
3. **httpx proxy** — Phần 4: `RequestStore` + 3 tool giữ signature + scope allowlist. Test: capture 1 request, `repeat_request` đổi header, nhận response.
4. **Skill API** — Phần 7: thu `_resolve_skills`, viết 2 skill mới (API4, API9), chỉnh root prompt.
5. **JWT PyJWT** — Phần 6: tool/skill forge token.
6. **Report nhãn OWASP-API** — Phần 2: dict CWE→API category trong `report/`.
7. **E2E** — chạy một scan thật vào một API staging **được uỷ quyền** với OpenAPI + 2 token; kiểm `penetration_test_report.md`, `vulnerabilities/*.md`, `findings.sarif`.

---

## 9. Acceptance (định nghĩa "xong v1")

- [ ] Chạy một scan **không cần Docker**, in-process, trên host.
- [ ] Agent spawn được specialist con theo nhóm API và nhận completion report (engine multi-agent còn nguyên).
- [ ] `repeat_request` chứng minh được một **BOLA two-account diff** (request tenant A + token tenant B → trả data tenant A).
- [ ] Forge được JWT alg=none / claim-edit bằng PyJWT và replay.
- [ ] Scope allowlist chặn request ngoài phạm vi.
- [ ] Report gắn nhãn API1..API10; SARIF xuất được.
- [ ] 2 skill mới (API4, API9) load được qua `_resolve_skills`.

---

## 10. Open questions (xác nhận với chủ dự án trước/khi làm)

1. **SDK `agents` có `Agent` thường dùng được không**, hay buộc `SandboxAgent`? (Quyết định Phần 5 đi đường "bỏ capability" hay "custom no-op backend".)
2. **Có cần deep-exploit agent (sqlmap/jwt-crack) ngay không**, hay v1 thuần HTTP là đủ? (Mặc định: defer.)
3. **API10 (Unsafe Consumption)** — target có integration bên thứ ba không? Nếu không, bỏ qua.
4. **Persist RequestStore ra đĩa** để resume scan, hay in-memory là đủ cho v1?
5. **Giữ MCP tools** (`tools/mcp`) không? Hữu ích nếu muốn cắm nguồn dữ liệu ngoài; bỏ nếu không dùng.

---

## Phụ lục — file tham chiếu (đường dẫn trong repo gốc)
- Engine: `strix/core/agents.py`, `strix/core/runner.py`, `strix/core/execution.py`
- Lắp agent: `strix/agents/factory.py` (`build_strix_agent` ~663, `_finish_tool_use_behavior` ~552, `_BASE_TOOLS` ~574)
- Skill resolve: `strix/agents/prompt.py` (`_resolve_skills` ~24); loader `strix/skills/__init__.py`
- Điều phối: `strix/tools/agents_graph/tools.py`
- Proxy (thay): `strix/tools/proxy/tools.py`, `strix/tools/proxy/caido_api.py`
- Caido/sandbox (drop): `strix/runtime/caido_bootstrap.py`, `strix/runtime/session_manager.py`, `strix/runtime/backends.py`
- Skill API sẵn: `strix/skills/custom/api_spec_testing.md`, `strix/skills/protocols/{oauth,graphql}.md`, `strix/skills/vulnerabilities/*.md`
- Workflow tham chiếu: `skills/api-security-testing/SKILL.md`
- Report/SARIF: `strix/report/sarif.py`, `strix/report/state.py`, `strix/report/writer.py`
