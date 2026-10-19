//! The gate: the single choke point for every action (docs/ARCHITECTURE.md §4.5).
//!
//! For each invocation, in order:
//! 1. **Capability** — the session must hold one for the action (I1).
//! 2. **Labels** — argument labels are resolved from the [`ValueTable`], never
//!    taken from the caller (ADR-0005).
//! 3. **Egress** — external effects may carry only cleared secrecy (I3).
//! 4. **Integrity floor** — arguments below it need a signed approval bound to
//!    this exact invocation (I2, ADR-0006). `Bounded` values may fill
//!    [`ParamKind::Choice`] parameters with a pre-approved option.
//! 5. **Audit, then effect** — every decision is logged before any effect
//!    runs (I4). Irreversible and external effects wait in the session's
//!    outbox until [`Gate::commit`]; [`Gate::abort`] drops them unrun (I5).
//!
//! The ordering and approval rules are model-checked in `specs/tla/Txn.tla`;
//! the decision logic mirrors `specs/verus/gate.rs`.
#![no_std]

extern crate alloc;

mod action;
mod approval;
mod audit;
mod caps;
mod refusal;

pub use action::{ActionId, ActionSpec, DuplicateAction, Effect, Param, ParamKind, Registry, RegistryError};
pub use approval::{ApprovalRequest, Approver, ArgSummary, Digest, Nonce, SignedApproval, signed_message};
pub use audit::{AuditEntry, AuditKind, AuditLog};
pub use caps::CapSet;
pub use ed25519_dalek::VerifyingKey;
pub use refusal::{ApprovalError, Grantor, Reason, Refusal};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use approval::{invocation_digest, verify};
use fewshot_host::Clock;
use fewshot_labeld::{Handle, Integrity, Label, Provenance, Resolved, SessionId, ValueTable};

/// An effect implementation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectError(pub String);

/// Runs effects. Implemented by the host; the gate calls it only after the
/// effect's audit entry exists, and passes that entry in.
pub trait Effects {
    /// Runs `action` with resolved argument values. `record.digest` is the
    /// effect's idempotency key.
    fn run(&mut self, action: &ActionSpec, args: &[&[u8]], record: &AuditEntry) -> Result<(), EffectError>;
}

/// A call to an action. Carries value handles, never labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// Action to invoke.
    pub action: ActionId,
    /// Argument handles, in parameter order.
    pub args: Vec<Handle>,
    /// A signed approval from a previous [`Decision::NeedsApproval`].
    pub approval: Option<SignedApproval>,
}

impl Invocation {
    /// A call without approval.
    pub fn new(action: ActionId, args: impl IntoIterator<Item = Handle>) -> Self {
        Invocation { action, args: args.into_iter().collect(), approval: None }
    }

    /// The same call with an approval attached.
    pub fn with_approval(mut self, approval: SignedApproval) -> Self {
        self.approval = Some(approval);
        self
    }
}

/// What the gate did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Read or local-reversible effect: ran now.
    Executed(Result<(), EffectError>),
    /// Irreversible or external effect: queued until commit.
    Queued {
        /// Position in the outbox.
        position: usize,
        /// Invocation digest.
        digest: Digest,
    },
    /// Arguments are below the integrity floor: show this to the user.
    NeedsApproval(ApprovalRequest),
}

/// Result of [`Gate::commit`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitReport {
    /// Effects that ran, in order.
    pub executed: Vec<Digest>,
    /// The effect that failed, if any. Commit stops there.
    pub failed: Option<(Digest, EffectError)>,
    /// Effects dropped without running after a failure.
    pub not_run: Vec<Digest>,
}

struct Queued {
    action: ActionId,
    args: Vec<Handle>,
    digest: Digest,
}

struct SessionState {
    caps: CapSet,
    outbox: Vec<Queued>,
}

/// The gate.
pub struct Gate<C> {
    registry: Registry,
    approval_key: VerifyingKey,
    clock: C,
    audit: AuditLog,
    sessions: BTreeMap<SessionId, SessionState>,
    pending: BTreeMap<Nonce, (SessionId, Digest)>,
    used: BTreeSet<Nonce>,
    next_nonce: u64,
}

impl<C: Clock> Gate<C> {
    /// A gate over `registry` that accepts approvals signed by `approval_key`.
    pub fn new(registry: Registry, approval_key: VerifyingKey, clock: C) -> Self {
        Gate {
            registry,
            approval_key,
            clock,
            audit: AuditLog::default(),
            sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
            used: BTreeSet::new(),
            next_nonce: 1,
        }
    }

    /// The action registry.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The audit log.
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Opens a session holding `caps`.
    pub fn open_session(&mut self, session: SessionId, caps: CapSet) {
        self.sessions.insert(session, SessionState { caps, outbox: Vec::new() });
        self.log(session, None, None, AuditKind::SessionOpened);
    }

    /// Closes a session, dropping its outbox unrun. Returns how many were dropped.
    pub fn close_session(&mut self, session: SessionId) -> usize {
        let dropped = self.abort(session).unwrap_or(0);
        if self.sessions.remove(&session).is_some() {
            self.log(session, None, None, AuditKind::SessionClosed);
        }
        dropped
    }

    /// Number of effects waiting in a session's outbox.
    pub fn outbox_len(&self, session: SessionId) -> usize {
        self.sessions.get(&session).map_or(0, |s| s.outbox.len())
    }

    /// Checks and routes one invocation.
    pub fn invoke(
        &mut self,
        table: &ValueTable,
        session: SessionId,
        inv: &Invocation,
        effects: &mut impl Effects,
    ) -> Result<Decision, Refusal> {
        let act = Some(inv.action);
        let Some(state) = self.sessions.get(&session) else {
            return Err(self.refuse(
                session,
                act,
                Reason::UnknownSession,
                "session is not open",
                "open a session",
                Grantor::None,
            ));
        };

        // 1. Capability (I1).
        if !state.caps.contains(inv.action) {
            let detail = format!("no capability for action {}", inv.action.0);
            return Err(self.refuse(
                session,
                act,
                Reason::MissingCapability,
                detail,
                "delegate this action to the session",
                Grantor::User,
            ));
        }
        let Some(spec) = self.registry.get(inv.action).cloned() else {
            let detail = format!("action {} is not registered", inv.action.0);
            return Err(self.refuse(
                session,
                act,
                Reason::UnknownAction,
                detail,
                "register the action",
                Grantor::Manifest,
            ));
        };
        if inv.args.len() != spec.params.len() {
            let detail = format!("{} takes {} arguments, got {}", spec.name, spec.params.len(), inv.args.len());
            return Err(self.refuse(
                session,
                act,
                Reason::WrongArity,
                detail,
                "pass one handle per parameter",
                Grantor::None,
            ));
        }

        // 2. Labels from the value table only (ADR-0005).
        let mut resolved = Vec::with_capacity(inv.args.len());
        for &h in &inv.args {
            match table.resolve(session, h) {
                Ok(r) => resolved.push(r),
                Err(e) => {
                    return Err(self.refuse(
                        session,
                        act,
                        Reason::UnknownHandle,
                        e.to_string(),
                        "pass handles from this session",
                        Grantor::None,
                    ));
                }
            }
        }
        let label = Label::join_all(resolved.iter().map(|r| r.label));

        // 3. Egress (I3).
        if spec.effect == Effect::External && !label.secrecy.is_subset(spec.egress_clearance) {
            let detail = format!(
                "{} would send secrecy {:?} beyond clearance {:?}",
                spec.name, label.secrecy, spec.egress_clearance
            );
            return Err(self.refuse(
                session,
                act,
                Reason::EgressNotCleared,
                detail,
                "declassify the data or clear the destination",
                Grantor::User,
            ));
        }

        // 4. Integrity floor (I2, ADR-0006).
        let below: Vec<bool> =
            resolved.iter().zip(&spec.params).map(|(r, p)| !passes_floor(r, p, spec.integrity_floor)).collect();
        let digest = if below.contains(&true) {
            match &inv.approval {
                None => return Ok(self.request_approval(session, &spec, &resolved, &below)),
                Some(a) => {
                    if let Err(e) = self.accept_approval(session, inv.action, a, &resolved) {
                        let detail = format!("approval for {} rejected: {e:?}", spec.name);
                        return Err(self.refuse(
                            session,
                            act,
                            Reason::ApprovalInvalid(e),
                            detail,
                            "request a new approval for this exact call",
                            Grantor::User,
                        ));
                    }
                    a.digest
                }
            }
        } else {
            let nonce = self.fresh_nonce();
            invocation_digest(session, inv.action, nonce, &resolved)
        };

        // 5. Audit, then route (I4, I5).
        if spec.effect.is_immediate() {
            let args: Vec<&[u8]> = resolved.iter().map(|r| r.value).collect();
            let result = self.run_effect(session, &spec, digest, &args, effects);
            Ok(Decision::Executed(result))
        } else {
            self.log(session, act, Some(digest), AuditKind::Queued);
            let outbox = &mut self.sessions.get_mut(&session).expect("checked above").outbox;
            outbox.push(Queued { action: inv.action, args: inv.args.clone(), digest });
            Ok(Decision::Queued { position: outbox.len() - 1, digest })
        }
    }

    /// Runs the session's outbox in order. Stops at the first failure and
    /// drops the rest unrun.
    pub fn commit(
        &mut self,
        table: &ValueTable,
        session: SessionId,
        effects: &mut impl Effects,
    ) -> Result<CommitReport, Refusal> {
        let Some(state) = self.sessions.get_mut(&session) else {
            return Err(self.refuse(
                session,
                None,
                Reason::UnknownSession,
                "session is not open",
                "open a session",
                Grantor::None,
            ));
        };
        let mut queue = core::mem::take(&mut state.outbox).into_iter();
        let mut report = CommitReport::default();
        for q in queue.by_ref() {
            let spec = self.registry.get(q.action).cloned().expect("queued actions are registered");
            let values: Result<Vec<&[u8]>, _> =
                q.args.iter().map(|&h| table.resolve(session, h).map(|r| r.value)).collect();
            let result = match values {
                Ok(args) => self.run_effect(session, &spec, q.digest, &args, effects),
                Err(e) => {
                    self.log(session, Some(q.action), Some(q.digest), AuditKind::EffectFailed);
                    Err(EffectError(e.to_string()))
                }
            };
            match result {
                Ok(()) => report.executed.push(q.digest),
                Err(e) => {
                    report.failed = Some((q.digest, e));
                    break;
                }
            }
        }
        report.not_run = queue.map(|q| q.digest).collect();
        if !report.not_run.is_empty() {
            self.log(session, None, None, AuditKind::OutboxDropped(report.not_run.len() as u32));
        }
        Ok(report)
    }

    /// Drops the session's outbox without running anything. Returns how many were dropped.
    pub fn abort(&mut self, session: SessionId) -> Result<usize, Refusal> {
        let Some(state) = self.sessions.get_mut(&session) else {
            return Err(self.refuse(
                session,
                None,
                Reason::UnknownSession,
                "session is not open",
                "open a session",
                Grantor::None,
            ));
        };
        let n = core::mem::take(&mut state.outbox).len();
        self.log(session, None, None, AuditKind::OutboxDropped(n as u32));
        Ok(n)
    }

    fn run_effect(
        &mut self,
        session: SessionId,
        spec: &ActionSpec,
        digest: Digest,
        args: &[&[u8]],
        effects: &mut impl Effects,
    ) -> Result<(), EffectError> {
        let record =
            *self.audit.append(self.clock.now_ms(), session, Some(spec.id), Some(digest), AuditKind::EffectStarted);
        let result = effects.run(spec, args, &record);
        let kind = if result.is_ok() { AuditKind::EffectSucceeded } else { AuditKind::EffectFailed };
        self.log(session, Some(spec.id), Some(digest), kind);
        result
    }

    fn request_approval(
        &mut self,
        session: SessionId,
        spec: &ActionSpec,
        resolved: &[Resolved<'_>],
        below: &[bool],
    ) -> Decision {
        let nonce = self.fresh_nonce();
        let digest = invocation_digest(session, spec.id, nonce, resolved);
        self.pending.insert(nonce, (session, digest));
        self.log(session, Some(spec.id), Some(digest), AuditKind::ApprovalRequested(nonce));
        let args = resolved
            .iter()
            .zip(&spec.params)
            .zip(below)
            .map(|((r, p), &below_floor)| ArgSummary {
                param: p.name.clone(),
                label: r.label,
                origin: match r.provenance {
                    Provenance::Ingress { origin } => origin.clone(),
                    Provenance::Derived { op, .. } => format!("derived:{op}"),
                },
                below_floor,
            })
            .collect();
        Decision::NeedsApproval(ApprovalRequest { digest, nonce, session, action: spec.id, args })
    }

    fn accept_approval(
        &mut self,
        session: SessionId,
        action: ActionId,
        a: &SignedApproval,
        resolved: &[Resolved<'_>],
    ) -> Result<(), ApprovalError> {
        if self.used.contains(&a.nonce) {
            return Err(ApprovalError::Reused);
        }
        let pending = match self.pending.get(&a.nonce) {
            Some(&(s, d)) if s == session => d,
            _ => return Err(ApprovalError::UnknownNonce),
        };
        if self.clock.now_ms() > a.expires_at_ms {
            return Err(ApprovalError::Expired);
        }
        if !verify(&self.approval_key, a) {
            return Err(ApprovalError::BadSignature);
        }
        if a.digest != pending || invocation_digest(session, action, a.nonce, resolved) != a.digest {
            return Err(ApprovalError::DigestMismatch);
        }
        self.pending.remove(&a.nonce);
        self.used.insert(a.nonce);
        Ok(())
    }

    fn refuse(
        &mut self,
        session: SessionId,
        action: Option<ActionId>,
        reason: Reason,
        detail: impl Into<String>,
        remedy: &str,
        grantor: Grantor,
    ) -> Refusal {
        self.log(session, action, None, AuditKind::Refused(reason));
        Refusal { reason, detail: detail.into(), remedy: remedy.into(), grantor }
    }

    fn log(&mut self, session: SessionId, action: Option<ActionId>, digest: Option<Digest>, kind: AuditKind) {
        self.audit.append(self.clock.now_ms(), session, action, digest, kind);
    }

    fn fresh_nonce(&mut self) -> Nonce {
        let n = Nonce(self.next_nonce);
        self.next_nonce += 1;
        n
    }
}

/// An argument passes the floor by integrity, or as a `Bounded` value picking
/// one of a choice parameter's pre-approved options.
fn passes_floor(r: &Resolved<'_>, p: &Param, floor: Integrity) -> bool {
    r.label.integrity >= floor
        || (r.label.integrity == Integrity::Bounded
            && matches!(&p.kind, ParamKind::Choice(opts) if opts.iter().any(|o| o.as_slice() == r.value)))
}
