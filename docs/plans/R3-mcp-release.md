# R3 — MCP release: implementation plan

Work plan for issue [#4](https://github.com/fewshotOS/fewshotOS/issues/4) (`docs/issues/R3.md`), plus the last open item of R2 ([#3](https://github.com/fewshotOS/fewshotOS/issues/3)). Written for an implementing agent working task by task. Every design decision is already made here; if something is unclear or seems wrong, **stop and write it down** (see "When stuck") instead of inventing a new design.

## Read first

1. `README.md`: invariants I1–I6.
2. `docs/adr/0007-portable-runtime-first.md` and `docs/ARCHITECTURE.md` §4.4–4.6, §5.2, §6.1, §10.
3. `docs/adr/0005-labeled-value-handles.md`, `docs/adr/0006-approval-binding.md`.
4. `libs/README.md` (including "Not in R2"), then `libs/gate/src/lib.rs`, `libs/gate/src/action.rs`, `libs/labeld/src/lib.rs`, `libs/executor/src/host.rs`.
5. `docs/plans/R2-agent-runtime.md`: R3 keeps its ground rules and style.

## Ground rules

- **Branches.** One branch per task, `r3/t<n>-<slug>`, based on `main` once the task's dependencies have merged, or on the dependency's branch if they have not. Never push to `main`, never force-push, never merge your own PR.
- **Implementing agent (Qwen):** commit locally on the task branch only. Do **not** push and do **not** open PRs; the reviewer does both after review.
- **Before every commit, all of these must pass:**
  ```sh
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
  cargo build --locked --target x86_64-unknown-none  --no-default-features -p fewshot-labels -p fewshot-labeld -p fewshot-host -p fewshot-gate -p fewshot-plan -p fewshot-executor
  cargo build --locked --target aarch64-unknown-none --no-default-features -p fewshot-labels -p fewshot-labeld -p fewshot-host -p fewshot-gate -p fewshot-plan -p fewshot-executor
  cargo run --locked -p fewshot-harness --bin injection-bench
  ```
  After adding a dependency, run `cargo build` once without `--locked` to update `Cargo.lock`, and commit the lockfile. Pin new dependencies to an exact current release (`cargo add name@x.y.z`).
- **TCB crates** are `fewshot-labels`, `fewshot-labeld` and `fewshot-gate`. Only T1 changes them; it is written by the reviewer, not the implementing agent. Never delete or weaken an existing assertion in `libs/gate/tests/invariants.rs`.
- `unsafe_code = "forbid"` and `missing_docs = "warn"` apply to every crate. Every new crate uses `[lints] workspace = true`. The R1/R2 `no_std` crates stay `no_std`; everything new in R3 is `std`.
- **No network code** except: Ollama on localhost (`fewshot-models`), the `http.get` action (T3), and nothing else. Telemetry never sends anything anywhere.
- Match the existing style: short doc comments, tests named after the property they check, `BTreeMap` in `no_std` code.
- Commit messages: first line `R3/Tn: <summary>`, body says what changed and why, last line `Refs #4` (T0: `Refs #3`).
- **When stuck:** if one approach fails three times, or a task seems to need a TCB change it doesn't list, stop. Write `BLOCKED.md` at the repo root saying what you tried, the exact error, and what you think is needed. Don't work around it.

## Key decision: how MCP clients map onto labels

An MCP client (Claude Code, Claude Desktop, any other) is one LLM whose context may hold content Fewshot never saw. So Fewshot cannot know what steered a literal argument. The runtime therefore:

1. **Treats each MCP connection as one session.** Its capabilities and its *literal integrity* come from the client's entry in the config file. Literal arguments the client passes are interned at `literal_integrity` (default `ThirdParty`, allowed range `UntrustedWeb..=SystemApp`; `User` is rejected because a model is not the user's trusted input path), joined with the session's principal label.
2. **Returns handles, not content.** Read actions return a handle plus metadata (`{"handle":"v3", "bytes":1834, "label":"untrusted-web"}`). The client never sees untrusted bytes unless it asks.
3. **Offers three ways to use content:**
   - `fewshot_extract {handle, schema}` runs the quarantined reader (local Ollama) and returns a new handle. A `choice` schema gives `Bounded` integrity; `text` keeps the source's label.
   - `fewshot_reveal {handle}` returns the bytes into the client's context **and** raises the session's principal label (it is a `SessionView::read`). From then on every call in that session carries that taint, which is exactly what has happened to the client's context.
   - `fewshot_run_task {request, inputs}` runs the full R2 planner/executor in-process with the local planner. This is the CaMeL path: the client model never sees the content at all.
4. **Blocks on approval.** When the gate says `NeedsApproval`, `tools/call` waits for the approval app (up to `approval_timeout_s`, default 300) and then returns the result, a refusal, or a timeout. Clients need no changes.

`docs/LIMITATIONS.md` (T9) states plainly: on a host OS, a process running as the user can read the config, talk to the daemon directly, and read the approval key; the runtime does not enforce I1 or I6 against such a process.

## Target layout

```
libs/
  gate/       (T1: action outputs, audit sink — TCB, reviewer-written)
  models/     (T0: planner that produces usable plans)
  runtime/    NEW fewshot-runtime   std: config, sessions, built-in actions, host Effects, file audit sink
  approval/   NEW fewshot-approval  std: approval wire protocol, templates, batching (no GUI)
apps/
  fewshot/          NEW binary `fewshot`: `fewshot mcp` (stdio MCP server), `fewshot audit`, `fewshot stats`
  fewshot-approve/  NEW binary `fewshot-approve`: the approval app (eframe window), holds the signing key
```

Dependency direction: `gate ← runtime ← approval ← apps`. `runtime` also uses `executor` and `models`. `apps/fewshot` never depends on anything that can sign approvals; a source test (T5) greps for `Approver` in `apps/fewshot` and `libs/runtime` and fails if found.

---

## T0 — Close R2: a live planner that writes usable plans (models)

**Problem.** `cargo test -p fewshot-models -- --ignored` fails: `live_reader_round_trip` passes, but `qwen3.8-114k` answers the planner round trip with 40+ `Let` steps binding `"inbox"`/`"archive"` under ever-new names and no `for_each` or `call`. That plan is schema-valid and validates, so the retries never fire. This is the usual degenerate loop of schema-constrained decoding at temperature 0 with no worked example.

**Changes (all in `libs/models`, plus `PLAN_JSON_SCHEMA` in `libs/plan`):**
- `PLAN_JSON_SCHEMA`: add `"maxItems": 32` to the top-level `steps` and to every `body`/`then`/`otherwise` array. The validator already limits depth and loops; add the same 32-step limit there as `PlanError::TooManySteps` with a test.
- `PLANNER_SYSTEM`: add one short worked example after the step list: a request, its actions and inputs, and the exact plan JSON (a `for_each` over a list input with a `choice` read and a `call`). Keep the whole prompt under 60 lines. The example must use different names from the live test (e.g. sorting receipts into folders) so the test is not just copying.
- New `fn lint(plan: &Plan) -> Result<(), String>` in `planner.rs`, checked after `validate`. It rejects with a message the model can act on:
  - a plan that offers actions but contains no `call` ("the plan calls no action; the request needs one");
  - a `let` whose variable is never used ("`x` is bound but never used; remove it").
  A lint failure is fed back exactly like a parse error and counts against `RETRIES`.
- `ChatRequest` gains `options: Value`, sent as Ollama's `options`. The planner sends `{"temperature":0,"seed":<config>,"repeat_penalty":1.1,"num_predict":2048}`; the reader sends `{"temperature":0,"seed":<config>,"num_predict":512}`.

**Tests:** unit tests for `lint` (both rules, plus a clean plan passing); a fake-`Chat` test that a lint failure is retried with the lint message in the user turn; the schema `maxItems` round trip. Then run the live tests **three times in a row**; all must pass. Paste the plan printed by the last run into the commit body.

**Also:** tick "Planner / quarantined reader split against a local model" in `docs/issues/R2.md`.

## T1 — Action outputs and an audit sink (gate, **TCB — written by the reviewer**)

- `ActionSpec` gains `output: Option<Label>`: the label of what the action returns. `Registry::validate` rejects an output on an action whose effect is not immediate (`Read`, `LocalReversible`), because queued effects run at commit when nobody is waiting for a value.
- `Effects::run` returns `Result<Vec<u8>, EffectError>`. `Decision::Executed` carries `Result<Vec<u8>, EffectError>`. Actions with `output: None` must return an empty vec; the gate turns anything else into `EffectError("unexpected output")`.
- `AuditKind::EffectFinished { output_hash: [u8; 32] }` is appended after an immediate effect returns, hashing the output bytes. The gate does **not** intern outputs: it has no `Ingress`. The host interns them with label `spec.output ⊔ (labels of the arguments)` (helper `fewshot_gate::output_label(&spec, &resolved_args)`), so a read steered by tainted arguments yields tainted output.
- `AuditLog` gains an optional `Box<dyn AuditSink>` (`fn append(&mut self, entry: &AuditEntry)`), called for each entry right after it is chained and before the effect runs. A sink error refuses the effect (`Reason::AuditUnavailable`), keeping I4 when the disk is full.
- Invariant tests: `i4_audit_before_effect` gains "a failing sink stops the effect"; a new `outputs` module checks output-label joins, that queued effects can't declare outputs, and that `EffectFinished` hashes match.
- Update `executor`, `harness`, and all `Effects` impls for the new signature (they return `Ok(vec![])`).

## T2 — `fewshot-runtime`: config and sessions

New std crate `libs/runtime`.

- **Config** (`config.rs`, TOML via `toml` + `serde`). The file is `fewshot.toml` in `dirs::config_dir()/fewshot/`, overridable with `FEWSHOT_CONFIG`:
  ```toml
  [runtime]
  data_dir = "..."               # default: dirs::data_dir()/fewshot
  approval_timeout_s = 300
  telemetry = false

  [ollama]                       # same fields and env overrides as fewshot_models::OllamaConfig

  [[client]]
  name = "claude-code"
  literal_integrity = "third_party"
  actions = ["fs.list", "fs.read", "fs.write", "notes.append", "http.get"]

  [[root]]                       # directories the fs actions may touch
  path = "C:/Users/me/Documents/fewshot"
  integrity = "third_party"      # label of file contents read from here
  secrecy = ["personal"]

  [tags]                         # secrecy tag names → Tag index
  personal = 1
  ```
  Unknown keys are an error. `literal_integrity = "user"` is an error. Paths are canonicalized at load.
- **Runtime** (`lib.rs`): owns `ValueTable`, `Ingress`, `Gate<SystemClock>`, the registry of built-in actions (T3), and a map of sessions. `Runtime::open_session(client_name) -> SessionId` grants exactly the client's actions. `Runtime::literal(session, bytes) -> Handle` interns at the client's `literal_integrity` joined with `table.principal_label(session)`. `Runtime::call(session, action_name, args: Vec<Handle>) -> CallResult` invokes the gate and, on an immediate effect with output, interns it with `fewshot_gate::output_label`. `Runtime::reveal(session, handle) -> Vec<u8>` goes through `SessionView::read`. `Runtime::extract(session, handle, schema)` goes through `fewshot_executor::host::Quarantine` with `OllamaReader`. `Runtime::run_task(session, request, inputs)` runs the planner and executor (approvals are handled by the caller, see T4).
- **File audit sink** (`audit.rs`): one JSON object per line in `data_dir/audit/<yyyy-mm-dd>.jsonl`, `fsync` after each line. Each line carries the entry and its chain hash. `fn load(dir) -> Result<Vec<AuditEntry>, AuditFileError>` re-verifies the chain across files.
- **Tests:** config parse and every rejection; literal integrity; output labels after a tainted read; audit file survives reopen and detects an edited line.

## T3 — Built-in actions (runtime)

`libs/runtime/src/actions/`. Each action is an `ActionSpec` plus an implementation behind one `HostEffects: fewshot_gate::Effects`.

| Name | Effect | Params | Output | Notes |
|---|---|---|---|---|
| `fs.list` | Read | `dir` | root's label | Newline-separated names. |
| `fs.read` | Read | `path` | root's label | Max 1 MiB. |
| `fs.write` | LocalReversible | `path`, `content` | — | Before overwriting, copies the old file to `data_dir/undo/<digest>`; compensation is `fs.restore`. Integrity floor `SystemApp`. |
| `fs.restore` | LocalReversible | `path`, `content` | — | Compensation of `fs.write`: `content` is the undo id. |
| `fs.delete` | LocalIrreversible | `path` | — | Queued; moves to `data_dir/trash/`. Floor `SystemApp`. |
| `notes.append` | LocalReversible | `text` | — | Appends to `data_dir/notes.md`. Floor `ThirdParty`, so routine. |
| `http.get` | Read | `url` | `UntrustedWeb`, no secrecy | `https` only, 2 MiB cap, 15 s timeout, via `ureq` with rustls. External egress of the URL itself: `egress_clearance` empty, so a URL carrying secret data is refused. |

Path rules, enforced before any I/O and tested: the path must canonicalize to inside a configured root; `..`, symlinks out of a root, and Windows device names (`NUL`, `CON`, `\\?\`) are refused with `EffectError`. Tests use `tempfile` roots; `http.get` is tested against a local `std::net::TcpListener` serving a fixed response (allow `http://127.0.0.1` only under `#[cfg(test)]`).

## T4 — `fewshot mcp`: the MCP server

New binary crate `apps/fewshot` (`clap` for subcommands). `fewshot mcp --client <name>` speaks MCP over stdio: newline-delimited JSON-RPC 2.0, protocol version `2025-06-18`, `tools` capability only. Hand-written on `serde_json`: no MCP SDK dependency.

- `initialize` → server info `fewshot` + crate version, `capabilities: {"tools": {}}`. `notifications/initialized` is accepted. `ping` answers `{}`.
- `tools/list`: one tool per granted action, named with `.` → `_` (`fs_read`), with an `inputSchema` of string properties in parameter order, all required, and `choice` params as `enum`. Descriptions come from a fixed table in the source, not from config. Plus `fewshot_extract`, `fewshot_reveal`, `fewshot_run_task`, `fewshot_commit` (commits the session's outbox and reports what ran), `fewshot_status` (outbox length, principal label, pending approvals).
- Arguments: a string value is a literal; a value of the form `{"handle":"v12"}` is a handle from an earlier result in the same session. Anything else is a JSON-RPC `-32602` error.
- `tools/call` results: `content: [{"type":"text","text": <json>}]` with `isError` set for refusals and failures. Refusals render the structured `Refusal` through the fixed templates from T5, never model text.
- **Approvals:** on `NeedsApproval`, send the request to the approval app (T5) and block the call until it answers or times out. Approved → retry with the signed approval and return the result. Denied → `isError: true`, "the user declined". Approval app not running → `isError: true` with how to start it.
- Logging goes to stderr only. stdout carries protocol only.
- **Tests:** an in-process test drives `initialize`, `tools/list`, a literal call, a handle round trip, `fewshot_reveal` raising the principal label (a following `fs.write` then needs approval), and malformed requests. A test with a fake approver covers approved, denied and timeout.

## T5 — Approval protocol and the approval app

**`libs/approval`** (no GUI): the wire protocol and everything that can be tested headless.
- Transport: a local socket via `interprocess` (Unix domain socket on Linux and macOS, named pipe on Windows), name `fewshot-approval-<username>`. Length-prefixed JSON frames. Messages: `Request { id, session, client, items: Vec<ApprovalRequest + rendered text> }`, `Answer { id, decisions: Vec<Approved(SignedApproval) | Denied> }`.
- **Templates** (`templates.rs`): a fixed table keyed by action name and refusal reason, e.g. `fs.write` → "Overwrite {path} with {bytes} bytes of text that came from {source}". Fields are filled only from the gate's `ApprovalRequest`/`ArgSummary` and the registry. A test checks every built-in action and every `Reason` has a template.
- **Batching:** requests from one session that arrive within 2 s of each other go out as one `Request` with several items ("Send these 3 files to the notes"). The user can approve all or tick items; each item is still signed over its own digest (ADR-0006).
- **Key:** generated on first run of `fewshot-approve` with `ed25519-dalek` + `OsRng`, stored as `config_dir/fewshot/approval.key` (owner-only permissions on Unix; on Windows rely on the per-user profile ACL and say so in LIMITATIONS). The public key is written to `approval.pub`, which the runtime reads at start. The runtime refuses to start without it. A source test fails if `Approver` appears under `libs/runtime` or `apps/fewshot`.

**`apps/fewshot-approve`** (`eframe`/`egui`): a small always-on-top window that shows pending requests with the rendered template text, per-argument provenance ("from http.get https://…"), and Approve / Deny / Approve all. Keyboard: Enter does nothing by default, so a stray keypress can't approve. It also has an **Audit** tab (T6). No other logic lives in the GUI crate; it calls `libs/approval`.

## T6 — Audit timeline

- `fewshot audit [--day yyyy-mm-dd] [--session N] [--verify]`: prints a human-readable timeline from the T2 audit files ("10:42:07 claude-code fs.write notes/todo.md — approved by you"). `--verify` exits 1 on a broken chain and names the first bad line.
- The approval app's Audit tab shows the same timeline, newest first, with a filter by client. It reads files only; it never writes them.
- Rendering lives in `libs/runtime/src/timeline.rs` so both share it. Test against a fixture audit file.

## T7 — Approval-rate telemetry (local, opt-in)

- Only when `[runtime] telemetry = true`. Appends to `data_dir/telemetry.jsonl`: `{ts, client, action, outcome: approved|denied|timeout|auto}`. Nothing else: no argument values, no paths, no URLs.
- `fewshot stats [--days 7]` prints prompts per active hour per client, the approval rate, and the most-prompted actions. An "active hour" is a clock hour with at least one call.
- A test checks nothing is written when telemetry is off, and a source test checks `libs/runtime/src/telemetry.rs` has no `std::net`, `ureq` or socket use.

## T8 — Builds and installers

- CI (`.github/workflows/rust.yml`): add a matrix job building and testing the workspace on `ubuntu-latest`, `windows-latest` and `macos-latest` (the no_std and spec jobs stay Linux-only).
- Releases with `dist` (cargo-dist): installers for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc` (MSI + PowerShell installer), `aarch64-apple-darwin` and `x86_64-apple-darwin`, for both binaries. Generated `release.yml` runs only on version tags. No code signing in R3; LIMITATIONS says so.
- The reviewer runs `dist plan` locally and checks the output before the PR.

## T9 — Docs and issue

- `README.md`: a "Try the runtime" section: install, run `fewshot-approve`, then `claude mcp add fewshot -- fewshot mcp --client claude-code`. Change "Status" to say the runtime is usable.
- `docs/LIMITATIONS.md`: a "Runtime on a host OS" section stating what is not enforced (I1 and I6 against same-user processes; key storage; no code signing; literal integrity is a configured guess; the client's context is outside Fewshot's view).
- `libs/README.md`: rows for the new crates and apps; replace "Not in R2" with "Not in R3".
- `docs/issues/R3.md`: tick what the work meets. The "≤ 3 prompts per hour" criterion needs a week of dogfooding with telemetry on; leave it unticked and say so in the PR.

## Out of scope for R3 (do not build)

- Store branches (M2): `fs.write` uses undo copies instead.
- Budgets, standing policies, declassification.
- MCP resources, prompts, sampling, HTTP/SSE transport. stdio tools only.
- Mail, calendar or any action needing third-party credentials.
- Code signing and auto-update.

## Task order and who does it

| Task | Depends on | TCB | Who | Size |
|---|---|---|---|---|
| T0 live planner fix | — | no | Qwen | S |
| T1 action outputs, audit sink | — | **yes** | reviewer | M |
| T2 runtime: config, sessions, audit file | T1 | no | Qwen | M |
| T3 built-in actions | T2 | no | Qwen | M |
| T4 MCP server | T3 | no | Qwen | L |
| T5 approval protocol + app | T2 | no | Qwen | L |
| T6 audit timeline | T2, T5 | no | Qwen | S |
| T7 telemetry | T4 | no | Qwen | S |
| T8 builds and installers | T4, T5 | no | reviewer | S |
| T9 docs, issue | all | no | reviewer | S |

T0 and T1 can run in parallel, and later T3 and T5. Each task is its own PR. To avoid the R2 problem of stacked PRs merging into each other instead of `main`, retarget each PR to `main` once its dependency has merged, before merging it.
