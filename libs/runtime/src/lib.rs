//! The runtime host (T2): config, sessions and the file audit log.
//!
//! An MCP connection opens exactly one session. Its capabilities are the
//! client's configured actions, and literal arguments the client passes are
//! interned at the client's `literal_integrity` joined with the session's
//! principal label: the model's context may hold content Fewshot never saw, so
//! we cannot do better than the configured guess, and everything the client
//! has read then taints its later calls.
//!
//! The runtime is a thin, trusted host over the gate: it never computes or
//! changes a label itself. Outputs come back already labeled by the gate, and
//! the runtime brings them into the value table with exactly that label. It
//! holds no approval signing key and must never construct an
//! [`Approver`](fewshot_gate::Approver).
//!
//! `fewshot-runtime` is a `std` crate: it reads files, the wall clock and the
//! config directory. The policy core it hosts stays `no_std`.

pub mod actions;
pub mod audit;
pub mod config;
pub mod telemetry;
pub mod timeline;

use std::collections::BTreeMap;
use std::fmt;

use fewshot_executor::host::Quarantine;
use fewshot_executor::{Reader, ReaderHost};
use fewshot_gate::{
    ApprovalRequest, CapSet, CommitReport, Decision, Effects, Gate, Invocation, Refusal, Registry, RegistryError,
    SignedApproval, VerifyingKey,
};
use fewshot_host::SystemClock;
use fewshot_labeld::{Handle, Ingress, Label, SessionId, ValueTable};
use fewshot_plan::Schema;

pub use audit::{AuditFileError, FileAuditSink, entry_from_json, entry_to_json, load_dir, load_file};
pub use config::{ClientConfig, Config, ConfigError, RootConfig};

/// The runtime: one config, one value table, one gate, the effects
/// implementation, and the sessions it has opened with their client names.
pub struct Runtime<E: Effects> {
    config: Config,
    table: ValueTable,
    ingress: Ingress,
    gate: Gate<SystemClock>,
    effects: E,
    /// Open sessions, session id to client name.
    sessions: BTreeMap<SessionId, String>,
    /// Next session id to hand out.
    next_session: u64,
}

/// What a call did, as returned by [`Runtime::call`].
#[derive(Debug, Clone)]
pub enum CallResult {
    /// An immediate effect ran now. `Some` when the action declared an output.
    Done {
        /// The output value, interned at exactly the gate's label.
        output: Option<Handle>,
    },
    /// The effect ran but failed.
    Failed(String),
    /// The effect is queued in the outbox, at `position`.
    Queued {
        /// Position in the outbox.
        position: usize,
    },
    /// Arguments are below the integrity floor: show the request to the user.
    NeedsApproval(ApprovalRequest),
    /// The gate refused the call.
    Refused(Refusal),
}

/// The runtime could not do what was asked.
#[derive(Debug, Clone)]
pub enum RuntimeError {
    /// The action registry failed validation.
    Registry(RegistryError),
    /// `open_session` named a client that is not in the config.
    UnknownClient {
        /// The client name given.
        name: String,
    },
    /// A client's config names an action that is not registered.
    UnknownAction {
        /// The client naming it.
        client: String,
        /// The action name.
        action: String,
    },
    /// The session is not open in this runtime.
    UnknownSession {
        /// The session id.
        id: SessionId,
    },
    /// The value table rejected an operation.
    Table(String),
    /// The gate refused a call.
    Refused(Refusal),
    /// The audit sink could not be created.
    Audit(String),
    /// The quarantined reader failed.
    Read(String),
    /// Setting up the effects host failed (data directories, …).
    Io(String),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::Registry(e) => write!(f, "runtime: action registry invalid: {e:?}"),
            RuntimeError::UnknownClient { name } => write!(f, "runtime: no client named {name:?} in the config"),
            RuntimeError::UnknownAction { client, action } => {
                write!(f, "runtime: client {client:?} names action {action:?}, which is not registered")
            }
            RuntimeError::UnknownSession { id } => write!(f, "runtime: session {} is not open in this runtime", id.0),
            RuntimeError::Table(m) => write!(f, "runtime: value table: {m}"),
            RuntimeError::Refused(r) => write!(f, "runtime: {r}"),
            RuntimeError::Audit(m) => write!(f, "runtime: audit sink: {m}"),
            RuntimeError::Read(m) => write!(f, "runtime: quarantined read: {m}"),
            RuntimeError::Io(m) => write!(f, "runtime: i/o: {m}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl<E: Effects> Runtime<E> {
    /// Validates the registry and the config's action names, builds the gate
    /// over it, and attaches a fresh
    /// [`FileAuditSink`](crate::audit::FileAuditSink) for
    /// `config.data_dir()/audit`.
    pub fn new(
        config: Config,
        registry: Registry,
        approval_key: VerifyingKey,
        effects: E,
    ) -> Result<Self, RuntimeError> {
        registry.validate().map_err(RuntimeError::Registry)?;
        for client in &config.client {
            for action in &client.actions {
                if !registry.iter().any(|a| &a.name == action) {
                    return Err(RuntimeError::UnknownAction { client: client.name.clone(), action: action.clone() });
                }
            }
        }
        let mut gate = Gate::new(registry, approval_key, SystemClock);
        let sink = FileAuditSink::create(&config.data_dir().join("audit")).map_err(|e| RuntimeError::Audit(e.0))?;
        gate.set_audit_sink(Box::new(sink));
        let (table, ingress) = ValueTable::new();
        Ok(Runtime { config, table, ingress, gate, effects, sessions: BTreeMap::new(), next_session: 1 })
    }

    /// Opens a session for `client`, holding exactly that client's actions.
    pub fn open_session(&mut self, client: &str) -> Result<SessionId, RuntimeError> {
        let cc = self.client(client)?;
        let mut ids = Vec::with_capacity(cc.actions.len());
        for name in &cc.actions {
            let id = self
                .gate
                .registry()
                .iter()
                .find(|a| &a.name == name)
                .map(|a| a.id)
                .ok_or_else(|| RuntimeError::UnknownAction { client: client.to_string(), action: name.clone() })?;
            ids.push(id);
        }
        let session = SessionId(self.next_session);
        self.next_session += 1;
        self.gate.open_session(session, CapSet::new(ids));
        self.sessions.insert(session, client.to_string());
        Ok(session)
    }

    /// Closes a session, dropping its outbox. Returns how many were dropped.
    pub fn close_session(&mut self, session: SessionId) -> Result<usize, RuntimeError> {
        if !self.sessions.contains_key(&session) {
            return Err(RuntimeError::UnknownSession { id: session });
        }
        let dropped = self.gate.close_session(session);
        self.table.end_session(session);
        self.sessions.remove(&session);
        Ok(dropped)
    }

    /// Interns a literal argument the client sent, at the client's literal
    /// integrity joined with the session's principal label.
    pub fn literal(&mut self, session: SessionId, bytes: Vec<u8>) -> Result<Handle, RuntimeError> {
        let cc = self.client_cfg(session)?;
        let label = cc.literal_label().join(self.table.principal_label(session));
        self.table
            .intern(&self.ingress, session, bytes, label, format!("literal:{}", cc.name))
            .map_err(|e| RuntimeError::Table(e.to_string()))
    }

    /// Invokes `action` with argument handles through the gate. On a
    /// successful output it is interned with exactly the gate's label.
    pub fn call(
        &mut self,
        session: SessionId,
        action: &str,
        args: Vec<Handle>,
        approval: Option<SignedApproval>,
    ) -> Result<CallResult, RuntimeError> {
        let client_name = self.client_cfg(session)?.name.clone();
        let spec = self
            .gate
            .registry()
            .iter()
            .find(|a| a.name == action)
            .ok_or_else(|| RuntimeError::UnknownAction { client: client_name, action: action.to_string() })?;
        let spec_id = spec.id;
        let spec_name = spec.name.clone();

        let mut inv = Invocation::new(spec_id, args);
        if let Some(a) = approval {
            inv = inv.with_approval(a);
        }

        match self.gate.invoke(&self.table, session, &inv, &mut self.effects) {
            Ok(Decision::Executed(result)) => match result {
                Ok(None) => Ok(CallResult::Done { output: None }),
                Ok(Some(out)) => {
                    let handle = self
                        .table
                        .intern(&self.ingress, session, out.value, out.label, format!("action:{spec_name}"))
                        .map_err(|e| RuntimeError::Table(e.to_string()))?;
                    Ok(CallResult::Done { output: Some(handle) })
                }
                Err(e) => Ok(CallResult::Failed(e.0)),
            },
            Ok(Decision::Queued { position, .. }) => Ok(CallResult::Queued { position }),
            Ok(Decision::NeedsApproval(req)) => Ok(CallResult::NeedsApproval(req)),
            Err(refusal) => Ok(CallResult::Refused(refusal)),
        }
    }

    /// Runs the session's outbox. Returns what ran, failed and was not run.
    pub fn commit(&mut self, session: SessionId) -> Result<CommitReport, RuntimeError> {
        self.client_cfg(session)?;
        self.gate.commit(&self.table, session, &mut self.effects).map_err(RuntimeError::Refused)
    }

    /// Drops the session's outbox without running anything. Returns the count.
    pub fn abort(&mut self, session: SessionId) -> Result<usize, RuntimeError> {
        self.client_cfg(session)?;
        self.gate.abort(session).map_err(RuntimeError::Refused)
    }

    /// Reads a value's bytes into the caller, raising the session's principal
    /// label. That is an honest account of the client's context now holding
    /// the content.
    pub fn reveal(&mut self, session: SessionId, h: Handle) -> Result<Vec<u8>, RuntimeError> {
        self.client_cfg(session)?;
        let mut view = self.table.view(session);
        let bytes = view.read(h).map_err(|e| RuntimeError::Table(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    /// Runs a quarantined reader over a value, returning the new handle.
    /// `choice` schemas yield at most `Bounded` integrity via the reader host;
    /// `text` schemas keep the source's label.
    pub fn extract<R: Reader>(
        &mut self,
        session: SessionId,
        h: Handle,
        schema: &Schema,
        reader: R,
    ) -> Result<Handle, RuntimeError> {
        self.client_cfg(session)?;
        let mut q = Quarantine::new(&self.ingress, reader);
        q.read(&mut self.table, session, h, schema).map_err(|e| RuntimeError::Read(e.to_string()))
    }

    /// The session's principal label: everything it has read.
    pub fn principal_label(&self, session: SessionId) -> Label {
        self.table.principal_label(session)
    }

    /// The label of a live value in a session, without reading it.
    pub fn label_of(&self, session: SessionId, h: Handle) -> Result<Label, RuntimeError> {
        self.client_cfg(session)?;
        self.table.resolve(session, h).map(|r| r.label).map_err(|e| RuntimeError::Table(e.to_string()))
    }

    /// The gate, for callers that need the audit log or approval requests.
    pub fn gate(&self) -> &Gate<SystemClock> {
        &self.gate
    }

    /// The parsed config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The name of the client whose session `session` is, if open.
    pub fn client_of(&self, session: SessionId) -> Option<&str> {
        self.sessions.get(&session).map(|s| s.as_str())
    }

    /// The client named in the config, or `UnknownClient`.
    fn client(&self, name: &str) -> Result<&ClientConfig, RuntimeError> {
        self.config
            .client
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| RuntimeError::UnknownClient { name: name.to_string() })
    }

    /// The client of an open session, or `UnknownSession`.
    fn client_cfg(&self, session: SessionId) -> Result<&ClientConfig, RuntimeError> {
        let name = self.sessions.get(&session).ok_or(RuntimeError::UnknownSession { id: session })?;
        self.client(name)
    }
}

/// The runtime over the built-in actions (T3): the registry `config` allows,
/// and one [`actions::HostEffects`] that runs them.
pub fn builtin_runtime(
    config: Config,
    approval_key: VerifyingKey,
) -> Result<Runtime<actions::HostEffects>, RuntimeError> {
    let effects = actions::HostEffects::new(&config).map_err(|e| RuntimeError::Io(e.to_string()))?;
    let registry = actions::builtin_registry(&config);
    Runtime::new(config, registry, approval_key, effects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_stable() {
        let r = RuntimeError::UnknownClient { name: "claude".into() };
        assert!(r.to_string().contains("claude"));
    }
}
