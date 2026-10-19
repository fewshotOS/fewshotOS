//! Shared fixture for the invariant suites.
#![allow(dead_code, missing_docs)]

use fewshot_gate::*;
use fewshot_host::{Clock, ManualClock};
use fewshot_labeld::{Handle, Ingress, Integrity, Label, Secrecy, SessionId, Tag, ValueTable};

pub const S1: SessionId = SessionId(1);
pub const S2: SessionId = SessionId(2);

pub const READ: ActionId = ActionId(1);
pub const NOTE: ActionId = ActionId(2);
pub const SEND: ActionId = ActionId(3);
pub const FILE: ActionId = ActionId(4);

pub const WORK: Tag = match Tag::new(1) {
    Some(t) => t,
    None => unreachable!(),
};
pub const HEALTH: Tag = match Tag::new(2) {
    Some(t) => t,
    None => unreachable!(),
};

pub fn registry() -> Registry {
    let mut r = Registry::new();
    let mk = |id, name: &str, effect, floor, clearance, params| ActionSpec {
        id,
        name: name.into(),
        effect,
        integrity_floor: floor,
        egress_clearance: clearance,
        params,
        draft_for: None,
        compensation: None,
    };
    r.register(mk(READ, "doc.read", Effect::Read, Integrity::UntrustedWeb, Secrecy::EMPTY, vec![Param::open("doc")]))
        .unwrap();
    r.register(mk(
        NOTE,
        "notes.append",
        Effect::LocalReversible,
        Integrity::ThirdParty,
        Secrecy::EMPTY,
        vec![Param::open("text")],
    ))
    .unwrap();
    r.register(mk(
        SEND,
        "mail.send",
        Effect::External,
        Integrity::User,
        Secrecy::EMPTY.with(WORK),
        vec![Param::open("to"), Param::open("body")],
    ))
    .unwrap();
    r.register(mk(
        FILE,
        "mail.file",
        Effect::LocalIrreversible,
        Integrity::SystemApp,
        Secrecy::EMPTY,
        vec![Param::choice("folder", [b"inbox".to_vec(), b"archive".to_vec()])],
    ))
    .unwrap();
    r
}

pub fn all_caps() -> CapSet {
    CapSet::new([READ, NOTE, SEND, FILE])
}

/// Records every effect it is asked to run, with the audit entry it was given.
#[derive(Default)]
pub struct Recorder {
    pub calls: Vec<(ActionId, Vec<Vec<u8>>, AuditEntry)>,
    pub fail_on: Option<ActionId>,
}

impl Effects for Recorder {
    fn run(&mut self, action: &ActionSpec, args: &[&[u8]], record: &AuditEntry) -> Result<(), EffectError> {
        self.calls.push((action.id, args.iter().map(|a| a.to_vec()).collect(), *record));
        if self.fail_on == Some(action.id) { Err(EffectError("boom".into())) } else { Ok(()) }
    }
}

pub struct World {
    pub gate: Gate<&'static ManualClock>,
    pub table: ValueTable,
    pub ingress: Ingress,
    pub approver: Approver,
    pub fx: Recorder,
    pub clock: &'static ManualClock,
}

impl World {
    pub fn new() -> Self {
        Self::with_caps(all_caps())
    }

    pub fn with_caps(caps: CapSet) -> Self {
        let clock: &'static ManualClock = Box::leak(Box::new(ManualClock::new(1_000)));
        let approver = Approver::from_secret([7; 32]);
        let mut gate = Gate::new(registry(), approver.verifying_key(), clock);
        gate.open_session(S1, caps);
        let (table, ingress) = ValueTable::new();
        World { gate, table, ingress, approver, fx: Recorder::default(), clock }
    }

    pub fn value(&mut self, session: SessionId, bytes: &[u8], label: Label) -> Handle {
        self.table.intern(&self.ingress, session, bytes.to_vec(), label, "test").unwrap()
    }

    pub fn user(&mut self, bytes: &[u8]) -> Handle {
        self.value(S1, bytes, Label::new(Secrecy::EMPTY, Integrity::User))
    }

    pub fn web(&mut self, bytes: &[u8]) -> Handle {
        self.value(S1, bytes, Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb))
    }

    pub fn invoke(&mut self, inv: &Invocation) -> Result<Decision, Refusal> {
        self.gate.invoke(&self.table, S1, inv, &mut self.fx)
    }

    pub fn commit(&mut self) -> CommitReport {
        self.gate.commit(&self.table, S1, &mut self.fx).unwrap()
    }

    /// Invokes, expects an approval request, approves it, and returns the request and approval.
    pub fn request(&mut self, inv: &Invocation) -> (ApprovalRequest, SignedApproval) {
        let Ok(Decision::NeedsApproval(req)) = self.invoke(inv) else { panic!("expected approval request") };
        let approval = self.approver.approve(&req, self.clock.now_ms() + 60_000);
        (req, approval)
    }
}

/// I4 over a whole log: every effect outcome has an earlier start for the same digest.
pub fn assert_audit_before_effect(log: &AuditLog) {
    log.verify().expect("audit chain intact");
    let entries = log.entries();
    for (i, e) in entries.iter().enumerate() {
        if matches!(e.kind, AuditKind::EffectSucceeded | AuditKind::EffectFailed) {
            assert!(
                entries[..i].iter().any(|s| s.kind == AuditKind::EffectStarted && s.digest == e.digest),
                "outcome at {i} has no earlier EffectStarted"
            );
        }
    }
}
