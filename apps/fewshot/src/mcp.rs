//! `fewshot mcp`: one MCP client over stdio, one runtime session (T4).
//!
//! Newline-delimited JSON-RPC 2.0, protocol `2025-06-18`, the `tools`
//! capability only, written directly on `serde_json`. Reads return handles,
//! not content: the client sees untrusted bytes only through
//! `fewshot_reveal`, which taints the session, or works on them through
//! `fewshot_extract` and `fewshot_run_task`. Calls that need approval block
//! until the approval app answers. Refusals are rendered through the fixed
//! templates, never by a model.

use crate::approvals::{Answer, Approvals, START_HINT};
use fewshot_approval::{WireItem, integrity_name, render_refusal, render_request};
use fewshot_executor::{Planner, Reader};
use fewshot_gate::{ActionSpec, ApprovalRequest, Effects, ParamKind, Registry, SignedApproval};
use fewshot_labeld::{Handle, Label, SessionId};
use fewshot_plan::Schema;
use fewshot_runtime::{CallResult, Runtime, RuntimeError, TaskInput, TaskOutcome};
use serde_json::{Map, Value, json};
use std::io::{BufRead, Write};

/// The MCP protocol version this server speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Default `max_len` for a text `fewshot_extract`.
pub const DEFAULT_EXTRACT_LEN: u32 = 2000;

/// JSON-RPC error codes.
mod code {
    pub const PARSE: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
}

/// A JSON-RPC error.
#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError { code: code::INVALID_PARAMS, message: message.into() }
}

/// The fixed tool descriptions. Never taken from config or a model.
fn describe_action(name: &str) -> &'static str {
    match name {
        "fs.list" => "List a directory inside a configured root. Returns a handle to the newline-separated names.",
        "fs.read" => {
            "Read a file inside a configured root (at most 1 MiB). Returns a handle, not the content: pass it to \
             another tool as {\"handle\": \"vN\"}, or use fewshot_reveal or fewshot_extract."
        }
        "fs.write" => {
            "Write a file inside a configured root. The old content is kept so the write can be undone. Usually \
             asks the user to approve."
        }
        "fs.restore" => "Undo an fs.write: pass the same path and content.",
        "fs.delete" => "Move a file into Fewshot's trash. Queued until fewshot_commit.",
        "notes.append" => "Append a line to the user's notes file.",
        "http.get" => "Fetch an https URL. Returns a handle to the body, labeled untrusted web content.",
        _ => "A built-in Fewshot action.",
    }
}

/// The tool name for an action: `.` becomes `_`.
fn tool_name(action: &str) -> String {
    action.replace('.', "_")
}

/// The MCP server for one client: its runtime, session, approval channel and
/// the local models `fewshot_extract` and `fewshot_run_task` use.
pub struct Server<E: Effects, A: Approvals> {
    rt: Runtime<E>,
    session: SessionId,
    client: String,
    approvals: A,
    reader: Box<dyn Reader>,
    planner: Box<dyn Planner>,
    /// Handles given to the client; `v<n>` is `handles[n - 1]`.
    handles: Vec<Handle>,
}

impl<E: Effects, A: Approvals> Server<E, A> {
    /// Opens `client`'s session in `rt`.
    pub fn new(
        mut rt: Runtime<E>,
        client: &str,
        approvals: A,
        reader: Box<dyn Reader>,
        planner: Box<dyn Planner>,
    ) -> Result<Self, RuntimeError> {
        let session = rt.open_session(client)?;
        Ok(Server { rt, session, client: client.into(), approvals, reader, planner, handles: Vec::new() })
    }

    /// The runtime, for tests and the binary's shutdown.
    pub fn runtime(&self) -> &Runtime<E> {
        &self.rt
    }

    /// The client's session.
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// Serves lines from `input` until it ends, writing responses to `output`.
    pub fn serve(&mut self, input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle_line(&line) {
                writeln!(output, "{response}")?;
                output.flush()?;
            }
        }
        Ok(())
    }

    /// Handles one JSON-RPC message. `None` for notifications.
    pub fn handle_line(&mut self, line: &str) -> Option<Value> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Some(error(Value::Null, code::PARSE, &format!("not JSON: {e}"))),
        };
        let id = msg.get("id").cloned();
        let method = match (&msg, msg.get("jsonrpc"), msg.get("method")) {
            (Value::Object(_), Some(Value::String(v)), Some(Value::String(m))) if v == "2.0" => m.clone(),
            _ => {
                return Some(error(id.unwrap_or(Value::Null), code::INVALID_REQUEST, "not a JSON-RPC 2.0 request"));
            }
        };
        // Notifications (no id) get no response.
        let id = id?;
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result = match method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "fewshot", "version": env!("CARGO_PKG_VERSION") },
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tools() })),
            "tools/call" => self.call_tool(&params),
            other => Err(RpcError { code: code::METHOD_NOT_FOUND, message: format!("unknown method {other:?}") }),
        };
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error(id, e.code, &e.message),
        })
    }

    /// The granted actions, in the client's configured order.
    fn granted(&self) -> Vec<ActionSpec> {
        let registry = self.rt.gate().registry();
        let cfg = self.rt.config().client.iter().find(|c| c.name == self.client);
        cfg.map(|c| c.actions.iter().filter_map(|n| registry.iter().find(|a| &a.name == n).cloned()).collect())
            .unwrap_or_default()
    }

    fn tools(&self) -> Vec<Value> {
        let mut tools: Vec<Value> = self
            .granted()
            .iter()
            .map(|a| {
                let mut props = Map::new();
                for p in &a.params {
                    let mut schema = json!({ "type": "string" });
                    if let ParamKind::Choice(options) = &p.kind {
                        let options: Vec<String> =
                            options.iter().map(|o| String::from_utf8_lossy(o).into_owned()).collect();
                        schema["enum"] = json!(options);
                    }
                    props.insert(p.name.clone(), schema);
                }
                let required: Vec<&str> = a.params.iter().map(|p| p.name.as_str()).collect();
                json!({
                    "name": tool_name(&a.name),
                    "description": describe_action(&a.name),
                    "inputSchema": { "type": "object", "properties": props, "required": required },
                })
            })
            .collect();
        let handle =
            json!({ "type": "object", "properties": { "handle": { "type": "string" } }, "required": ["handle"] });
        tools.push(json!({
            "name": "fewshot_reveal",
            "description": "Return a value's content. The content enters your context, so every later call in this \
                            session carries its label and may need the user's approval.",
            "inputSchema": { "type": "object", "properties": { "handle": { "type": "string" } }, "required": ["handle"] },
        }));
        tools.push(json!({
            "name": "fewshot_extract",
            "description": "Have Fewshot's quarantined local reader extract from a value without you seeing it. With \
                            `options`, it picks one of them and the result may be used without approval; otherwise it \
                            returns at most `max_len` bytes of text with the source's label. Returns a handle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": { "type": "string" },
                    "options": { "type": "array", "items": { "type": "string" } },
                    "max_len": { "type": "integer", "minimum": 1 },
                },
                "required": ["handle"],
            },
        }));
        tools.push(json!({
            "name": "fewshot_run_task",
            "description": "Have Fewshot's local planner do a task with your granted actions, on values you never \
                            see. `inputs` maps variable names to handles, e.g. {\"doc\": {\"handle\": \"v1\"}}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request": { "type": "string" },
                    "inputs": { "type": "object", "additionalProperties": handle },
                },
                "required": ["request"],
            },
        }));
        tools.push(json!({
            "name": "fewshot_commit",
            "description": "Run the effects queued in this session and report what ran.",
            "inputSchema": { "type": "object", "properties": {} },
        }));
        tools.push(json!({
            "name": "fewshot_status",
            "description": "This session's queued effects and the label of everything it has read.",
            "inputSchema": { "type": "object", "properties": {} },
        }));
        tools
    }

    fn call_tool(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = params.get("name").and_then(Value::as_str).ok_or_else(|| invalid("tools/call needs a name"))?;
        let args = match params.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return Err(invalid("arguments must be an object")),
        };
        match name {
            "fewshot_reveal" => self.reveal(&args),
            "fewshot_extract" => self.extract(&args),
            "fewshot_run_task" => self.run_task(&args),
            "fewshot_commit" => Ok(self.commit()),
            "fewshot_status" => Ok(self.status()),
            _ => {
                let spec = self
                    .granted()
                    .into_iter()
                    .find(|a| tool_name(&a.name) == name)
                    .ok_or_else(|| invalid(format!("unknown tool {name:?}")))?;
                self.action(&spec, &args)
            }
        }
    }

    /// One granted action: arguments in parameter order, then the gate,
    /// asking the approval app when it says so.
    fn action(&mut self, spec: &ActionSpec, args: &Map<String, Value>) -> Result<Value, RpcError> {
        if let Some(extra) = args.keys().find(|k| !spec.params.iter().any(|p| &p.name == *k)) {
            return Err(invalid(format!("{} has no parameter {extra:?}", tool_name(&spec.name))));
        }
        let mut handles = Vec::with_capacity(spec.params.len());
        for p in &spec.params {
            let v = args.get(&p.name).ok_or_else(|| invalid(format!("missing argument {:?}", p.name)))?;
            handles.push(self.argument(v)?);
        }
        let mut approval: Option<SignedApproval> = None;
        loop {
            let result = match self.rt.call(self.session, &spec.name, handles.clone(), approval.take()) {
                Ok(r) => r,
                Err(e) => return Ok(tool_error(&e.to_string())),
            };
            return Ok(match result {
                CallResult::Done { output: Some(h) } => tool_json(&self.handle_info(h)),
                CallResult::Done { output: None } => tool_json(&json!({ "status": "done" })),
                CallResult::Queued { position } => tool_json(&json!({
                    "status": "queued",
                    "position": position,
                    "next": "call fewshot_commit to run queued effects",
                })),
                CallResult::Failed(e) => tool_error(&format!("{} failed: {e}", spec.name)),
                CallResult::Refused(r) => tool_error(&render_refusal(&r, Some(&spec.name))),
                CallResult::NeedsApproval(req) => match self.ask(&req, spec) {
                    Ok(a) => {
                        approval = Some(a);
                        continue;
                    }
                    Err(why) => tool_error(&why),
                },
            });
        }
    }

    /// Sends `req` to the approval app. `Err` is the text to show the client.
    fn ask(&mut self, req: &ApprovalRequest, spec: &ActionSpec) -> Result<SignedApproval, String> {
        ask(&mut self.approvals, &self.client, req, spec)
    }

    /// A literal (a string) or a handle (`{"handle":"v3"}`) from this session.
    fn argument(&mut self, v: &Value) -> Result<Handle, RpcError> {
        match v {
            Value::String(s) => {
                self.rt.literal(self.session, s.clone().into_bytes()).map_err(|e| invalid(e.to_string()))
            }
            Value::Object(m) if m.len() == 1 => {
                let name =
                    m.get("handle").and_then(Value::as_str).ok_or_else(|| invalid("expected {\"handle\": \"vN\"}"))?;
                self.lookup(name)
            }
            _ => Err(invalid("an argument is a string, or {\"handle\": \"vN\"} from an earlier result")),
        }
    }

    fn lookup(&self, name: &str) -> Result<Handle, RpcError> {
        name.strip_prefix('v')
            .and_then(|n| n.parse::<usize>().ok())
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| self.handles.get(i).copied())
            .ok_or_else(|| invalid(format!("no value {name:?} in this session")))
    }

    fn handle_arg(&self, args: &Map<String, Value>) -> Result<Handle, RpcError> {
        let name = args.get("handle").and_then(Value::as_str).ok_or_else(|| invalid("missing argument \"handle\""))?;
        self.lookup(name)
    }

    /// Gives the client a name for `h` and describes it without its bytes.
    fn handle_info(&mut self, h: Handle) -> Value {
        self.handles.push(h);
        let name = format!("v{}", self.handles.len());
        match self.rt.describe(self.session, h) {
            Ok(info) => json!({
                "handle": name,
                "bytes": info.bytes,
                "from": info.origin,
                "label": self.label_json(info.label),
            }),
            Err(e) => json!({ "handle": name, "error": e.to_string() }),
        }
    }

    fn label_json(&self, label: Label) -> Value {
        let bits = label.secrecy.bits();
        let tags: Vec<String> = (0..64u8)
            .filter(|i| bits & (1u64 << i) != 0)
            .map(|i| {
                self.rt
                    .config()
                    .tags
                    .iter()
                    .find(|(_, t)| **t == i)
                    .map(|(n, _)| n.clone())
                    .unwrap_or(format!("tag{i}"))
            })
            .collect();
        json!({ "integrity": integrity_name(label.integrity), "secrecy": tags })
    }

    fn reveal(&mut self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        let h = self.handle_arg(args)?;
        Ok(match self.rt.reveal(self.session, h) {
            Ok(bytes) => tool_text(&String::from_utf8_lossy(&bytes)),
            Err(e) => tool_error(&e.to_string()),
        })
    }

    fn extract(&mut self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        let h = self.handle_arg(args)?;
        let schema = match (args.get("options"), args.get("max_len")) {
            (Some(Value::Array(opts)), None) => Schema::Choice {
                options: opts
                    .iter()
                    .map(|o| o.as_str().map(String::from).ok_or_else(|| invalid("options must be strings")))
                    .collect::<Result<_, _>>()?,
            },
            (None, max) => Schema::Text {
                max_len: match max {
                    None => DEFAULT_EXTRACT_LEN,
                    Some(v) => v
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|n| *n > 0)
                        .ok_or_else(|| invalid("max_len must be a positive integer"))?,
                },
            },
            _ => return Err(invalid("give either options (a list of strings) or max_len, not both")),
        };
        Ok(match self.rt.extract(self.session, h, &schema, &mut *self.reader) {
            Ok(out) => tool_json(&self.handle_info(out)),
            Err(e) => tool_error(&e.to_string()),
        })
    }

    fn run_task(&mut self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        let request =
            args.get("request").and_then(Value::as_str).ok_or_else(|| invalid("missing argument \"request\""))?;
        let mut inputs = Vec::new();
        match args.get("inputs") {
            None | Some(Value::Null) => {}
            Some(Value::Object(m)) => {
                for (var, v) in m {
                    let name = v
                        .get("handle")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid(format!("input {var:?} must be {{\"handle\": \"vN\"}}")))?;
                    inputs.push(TaskInput { var: var.clone(), value: self.lookup(name)? });
                }
            }
            Some(_) => return Err(invalid("inputs must be an object")),
        }
        let registry: Registry = self.rt.gate().registry().clone();
        let (approvals, client) = (&mut self.approvals, self.client.as_str());
        let outcome = self.rt.run_task(self.session, request, &inputs, &mut *self.planner, &mut *self.reader, |req| {
            let spec = registry.get(req.action).ok_or("the plan called an unknown action")?;
            ask(approvals, client, req, spec)
        });
        Ok(match outcome {
            Ok(TaskOutcome::Done { queued }) => tool_json(&json!({
                "status": "done",
                "queued": queued,
                "next": if queued > 0 { "call fewshot_commit to run queued effects" } else { "nothing queued" },
            })),
            Ok(TaskOutcome::NotApproved(why)) => tool_error(&why),
            // The executor does not say which step was refused.
            Ok(TaskOutcome::Refused(r)) => tool_error(&format!("the task stopped: {}", render_refusal(&r, None))),
            Ok(TaskOutcome::Failed(why)) => tool_error(&format!("the task failed: {why}")),
            Err(e) => tool_error(&e.to_string()),
        })
    }

    fn commit(&mut self) -> Value {
        match self.rt.commit(self.session) {
            Ok(report) => tool_json(&json!({
                "ran": report.executed.len(),
                "failed": report.failed.map(|(_, e)| e.0),
                "not_run": report.not_run.len(),
            })),
            Err(e) => tool_error(&e.to_string()),
        }
    }

    fn status(&self) -> Value {
        tool_json(&json!({
            "client": self.client,
            "queued": self.rt.gate().outbox_len(self.session),
            "values": self.handles.len(),
            "context": self.label_json(self.rt.principal_label(self.session)),
        }))
    }
}

/// Renders `req` through the fixed template and asks `approvals`.
fn ask<A: Approvals>(
    approvals: &mut A,
    client: &str,
    req: &ApprovalRequest,
    spec: &ActionSpec,
) -> Result<SignedApproval, String> {
    let text = render_request(req, spec);
    match approvals.ask(client, WireItem::from_request(req, &spec.name, text.clone())) {
        Answer::Approved(a) => Ok(a),
        Answer::Denied => Err(format!("the user declined: {text}")),
        Answer::Timeout => Err(format!("no answer from the approval app in time; nothing was done: {text}")),
        Answer::Unavailable(why) if why.contains(START_HINT) => Err(why),
        Answer::Unavailable(why) => Err(format!("{why}; {START_HINT}")),
    }
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_text(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

fn tool_json(v: &Value) -> Value {
    tool_text(&v.to_string())
}

fn tool_error(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}
