//! The file audit sink (I4, T2) plus a reader for the JSONL it writes.
//!
//! The gate is `no_std` and its [`AuditEntry`](fewshot_gate::AuditEntry) type
//! deliberately carries no `serde` derives, so the JSON mapping is written by
//! hand here. Each entry is one JSON object on one line; the hex strings are
//! lowercase, 64 characters for a 32-byte digest. [`load_file`] / [`load_dir`]
//! read the lines back and re-verify the hash chain with
//! [`fewshot_gate::verify_chain`].
//!
//! One file holds one gate run: every gate starts its chain at `seq` 0, and two
//! files for the same run would each look like two halves of one log.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use fewshot_gate::{
    ActionId, ApprovalError, AuditEntry, AuditKind, AuditSink, Digest, Nonce, Reason, SinkError, verify_chain,
};
use fewshot_labeld::SessionId;
use serde_json::{Value, json};

/// Durable audit storage: an append-only JSONL file under a directory.
pub struct FileAuditSink {
    file: File,
    path: PathBuf,
}

impl FileAuditSink {
    /// Creates `dir` if needed and opens a fresh
    /// `<dir>/<unix_ms>-<pid>.jsonl` for appending.
    pub fn create(dir: &Path) -> Result<Self, SinkError> {
        fs::create_dir_all(dir).map_err(|e| SinkError(e.to_string()))?;
        let name = format!("{}-{}.jsonl", unix_ms_now(), process::id());
        let path = dir.join(name);
        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(|e| SinkError(e.to_string()))?;
        Ok(FileAuditSink { file, path })
    }

    /// The file this sink appends to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), SinkError> {
        let line = entry_to_json(entry);
        self.file.write_all(line.as_bytes()).map_err(|e| SinkError(e.to_string()))?;
        self.file.write_all(b"\n").map_err(|e| SinkError(e.to_string()))?;
        self.file.sync_data().map_err(|e| SinkError(e.to_string()))?;
        Ok(())
    }
}

/// Serializes one entry to a JSON object (no trailing newline).
pub fn entry_to_json(e: &AuditEntry) -> String {
    let action = e.action.map(|a| json!(a.0));
    let digest = e.digest.map(|d| hex(&d.0));
    let v = json!({
        "seq": e.seq,
        "at_ms": e.at_ms,
        "session": e.session.0,
        "action": action,
        "digest": digest,
        "kind": kind_to_json(&e.kind),
        "prev": hex(&e.prev),
        "hash": hex(&e.hash),
    });
    v.to_string()
}

/// Parses one line produced by [`entry_to_json`] back into an entry.
///
/// On a malformed line the error is a `BadLine` with an empty path and line
/// number; [`load_file`] re-wraps it with the file and line it came from.
pub fn entry_from_json(line: &str) -> Result<AuditEntry, AuditFileError> {
    let v: Value = serde_json::from_str(line).map_err(|e| bad(e.to_string()))?;
    let obj = v.as_object().ok_or_else(|| bad("entry is not a JSON object".into()))?;

    let seq = obj.get("seq").and_then(Value::as_u64).ok_or_else(|| bad("missing or non-integer \"seq\"".into()))?;
    let at_ms =
        obj.get("at_ms").and_then(Value::as_u64).ok_or_else(|| bad("missing or non-integer \"at_ms\"".into()))?;
    let session =
        obj.get("session").and_then(Value::as_u64).ok_or_else(|| bad("missing or non-integer \"session\"".into()))?;

    let action = match obj.get("action") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| bad("\"action\" is not an integer".into()))?;
            Some(ActionId(u32::try_from(n).map_err(|_| bad("\"action\" does not fit in u32".into()))?))
        }
    };

    let digest = match obj.get("digest") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = v.as_str().ok_or_else(|| bad("\"digest\" is not a string".into()))?;
            Some(Digest(bytes_from_hex(s)?))
        }
    };

    let prev = bytes_from_hex(obj.get("prev").and_then(Value::as_str).ok_or_else(|| bad("missing \"prev\"".into()))?)?;
    let hash = bytes_from_hex(obj.get("hash").and_then(Value::as_str).ok_or_else(|| bad("missing \"hash\"".into()))?)?;
    let kind = kind_from_json(obj.get("kind").ok_or_else(|| bad("missing \"kind\"".into()))?)?;

    Ok(AuditEntry { seq, at_ms, session: SessionId(session), action, digest, kind, prev, hash })
}

/// The `kind` object for one entry. Exhaustive over [`AuditKind`]: a new
/// variant fails to compile here until mapped.
fn kind_to_json(kind: &AuditKind) -> Value {
    match kind {
        AuditKind::SessionOpened => json!({ "type": "session_opened" }),
        AuditKind::Refused(r) => json!({ "type": "refused", "reason": reason_to_string(r) }),
        AuditKind::ApprovalRequested(n) => json!({ "type": "approval_requested", "nonce": n.0 }),
        AuditKind::EffectStarted => json!({ "type": "effect_started" }),
        AuditKind::Queued => json!({ "type": "queued" }),
        AuditKind::EffectSucceeded => json!({ "type": "effect_succeeded" }),
        AuditKind::EffectReturned(h) => json!({ "type": "effect_returned", "output": hex(h) }),
        AuditKind::EffectFailed => json!({ "type": "effect_failed" }),
        AuditKind::OutboxDropped(n) => json!({ "type": "outbox_dropped", "count": n }),
        AuditKind::SessionClosed => json!({ "type": "session_closed" }),
    }
}

/// The `kind` string back to an [`AuditKind`]. Exhaustive: a new wire type is a
/// `BadLine` error here rather than a silent drop.
fn kind_from_json(v: &Value) -> Result<AuditKind, AuditFileError> {
    let obj = v.as_object().ok_or_else(|| bad("\"kind\" is not an object".into()))?;
    let t = obj.get("type").and_then(Value::as_str).ok_or_else(|| bad("missing or non-string \"kind.type\"".into()))?;
    match t {
        "session_opened" => Ok(AuditKind::SessionOpened),
        "refused" => {
            let r = obj
                .get("reason")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("missing or non-string \"reason\"".into()))?;
            Ok(AuditKind::Refused(reason_from_string(r)?))
        }
        "approval_requested" => {
            let n = obj
                .get("nonce")
                .and_then(Value::as_u64)
                .ok_or_else(|| bad("missing or non-integer \"nonce\"".into()))?;
            Ok(AuditKind::ApprovalRequested(Nonce(n)))
        }
        "effect_started" => Ok(AuditKind::EffectStarted),
        "queued" => Ok(AuditKind::Queued),
        "effect_succeeded" => Ok(AuditKind::EffectSucceeded),
        "effect_returned" => {
            let h = obj
                .get("output")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("missing or non-string \"output\"".into()))?;
            Ok(AuditKind::EffectReturned(bytes_from_hex(h)?))
        }
        "effect_failed" => Ok(AuditKind::EffectFailed),
        "outbox_dropped" => {
            let n = obj
                .get("count")
                .and_then(Value::as_u64)
                .ok_or_else(|| bad("missing or non-integer \"count\"".into()))?;
            Ok(AuditKind::OutboxDropped(u32::try_from(n).map_err(|_| bad("\"count\" does not fit in u32".into()))?))
        }
        "session_closed" => Ok(AuditKind::SessionClosed),
        other => Err(bad(format!("unknown \"kind.type\" {other:?}"))),
    }
}

/// A [`Reason`] string, as written to the file. Exhaustive over [`Reason`] and
/// [`ApprovalError`]: a new variant fails to compile here until mapped.
fn reason_to_string(r: &Reason) -> &'static str {
    match r {
        Reason::UnknownSession => "unknown_session",
        Reason::UnknownAction => "unknown_action",
        Reason::MissingCapability => "missing_capability",
        Reason::WrongArity => "wrong_arity",
        Reason::UnknownHandle => "unknown_handle",
        Reason::EgressNotCleared => "egress_not_cleared",
        Reason::ApprovalInvalid(a) => match a {
            ApprovalError::UnknownNonce => "approval_unknown_nonce",
            ApprovalError::Reused => "approval_reused",
            ApprovalError::Expired => "approval_expired",
            ApprovalError::BadSignature => "approval_bad_signature",
            ApprovalError::DigestMismatch => "approval_digest_mismatch",
        },
    }
}

/// A reason string back to a [`Reason`]. Exhaustive: a new wire name is a
/// `BadLine` error here rather than a silent drop.
fn reason_from_string(s: &str) -> Result<Reason, AuditFileError> {
    Ok(match s {
        "unknown_session" => Reason::UnknownSession,
        "unknown_action" => Reason::UnknownAction,
        "missing_capability" => Reason::MissingCapability,
        "wrong_arity" => Reason::WrongArity,
        "unknown_handle" => Reason::UnknownHandle,
        "egress_not_cleared" => Reason::EgressNotCleared,
        "approval_unknown_nonce" => Reason::ApprovalInvalid(ApprovalError::UnknownNonce),
        "approval_reused" => Reason::ApprovalInvalid(ApprovalError::Reused),
        "approval_expired" => Reason::ApprovalInvalid(ApprovalError::Expired),
        "approval_bad_signature" => Reason::ApprovalInvalid(ApprovalError::BadSignature),
        "approval_digest_mismatch" => Reason::ApprovalInvalid(ApprovalError::DigestMismatch),
        other => return Err(bad(format!("unknown reason {other:?}"))),
    })
}

/// Lowercase hex encode, two chars per byte.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xf) as usize] as char);
    }
    out
}

/// Decode a 64-character lowercase/uppercase hex string into 32 bytes.
fn bytes_from_hex(s: &str) -> Result<[u8; 32], AuditFileError> {
    if s.len() != 64 || !s.is_ascii() {
        return Err(bad(format!("expected 64 hex digits, got {s:?}")));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| bad(e.to_string()))?;
    }
    Ok(out)
}

/// A line is malformed, without file context (filled in by [`load_file`]).
fn bad(message: String) -> AuditFileError {
    AuditFileError::BadLine { path: PathBuf::new(), line: 0, message }
}

/// Reads and re-verifies every non-empty line of one audit file.
pub fn load_file(path: &Path) -> Result<Vec<AuditEntry>, AuditFileError> {
    let text = fs::read_to_string(path).map_err(|e| AuditFileError::Io(e.to_string()))?;
    let mut entries = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match entry_from_json(line) {
            Ok(e) => entries.push(e),
            Err(AuditFileError::BadLine { message, .. }) => {
                return Err(AuditFileError::BadLine { path: path.to_path_buf(), line: i + 1, message });
            }
            Err(other) => return Err(other),
        }
    }
    verify_chain(&entries).map_err(|seq| AuditFileError::BrokenChain { path: path.to_path_buf(), seq })?;
    Ok(entries)
}

/// Reads every `*.jsonl` file in `dir`, in file-name order, re-verifying each.
pub fn load_dir(dir: &Path) -> Result<Vec<(PathBuf, Vec<AuditEntry>)>, AuditFileError> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| AuditFileError::Io(e.to_string()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    files.into_iter().map(|p| load_file(&p).map(|entries| (p, entries))).collect()
}

/// Why reading an audit file failed.
#[derive(Debug)]
pub enum AuditFileError {
    /// The file could not be read.
    Io(String),
    /// A line is not a valid entry.
    BadLine {
        /// The file.
        path: PathBuf,
        /// The 1-based line number.
        line: usize,
        /// What was wrong.
        message: String,
    },
    /// The hash chain does not verify.
    BrokenChain {
        /// The file.
        path: PathBuf,
        /// The first broken `seq`.
        seq: u64,
    },
}

impl fmt::Display for AuditFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditFileError::Io(m) => write!(f, "audit file: {m}"),
            AuditFileError::BadLine { path, line, message } => {
                write!(f, "audit file {}: line {line}: {message}", path.display())
            }
            AuditFileError::BrokenChain { path, seq } => {
                write!(f, "audit file {}: broken hash chain at seq {seq}", path.display())
            }
        }
    }
}

impl std::error::Error for AuditFileError {}

/// Milliseconds since the Unix epoch, for the file name.
fn unix_ms_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}
