//! Shared fixture for the executor suites, modeled on the gate's.
#![allow(dead_code, missing_docs)]

use fewshot_executor::host::{Quarantine, intern_literals};
use fewshot_executor::*;
use fewshot_gate::*;
use fewshot_host::{Clock, ManualClock};
use fewshot_labeld::{Handle, Ingress, Integrity, Label, Secrecy, SessionId, Tag, ValueTable};
use fewshot_plan::{Plan, Schema};

pub const S1: SessionId = SessionId(1);

pub const READ: ActionId = ActionId(1);
pub const NOTE: ActionId = ActionId(2);
pub const SEND: ActionId = ActionId(3);
pub const FILE: ActionId = ActionId(4);
pub const POST: ActionId = ActionId(5);
pub const POST_DRAFT: ActionId = ActionId(6);
pub const RECALL: ActionId = ActionId(7);
pub const PAY: ActionId = ActionId(8);

pub const WORK: Tag = match Tag::new(1) {
    Some(t) => t,
    None => unreachable!(),
};

pub fn registry() -> Registry {
    let mut r = Registry::new();
    let mk = |id, name: &str, effect, floor, params| ActionSpec {
        id,
        name: name.into(),
        effect,
        integrity_floor: floor,
        egress_clearance: Secrecy::EMPTY.with(WORK),
        params,
        draft_for: None,
        compensation: None,
        output: None,
    };
    let to_body = || vec![Param::open("to"), Param::open("body")];
    r.register(mk(READ, "doc.read", Effect::Read, Integrity::UntrustedWeb, vec![Param::open("doc")])).unwrap();
    r.register(mk(NOTE, "notes.append", Effect::LocalReversible, Integrity::ThirdParty, vec![Param::open("text")]))
        .unwrap();
    r.register(ActionSpec {
        compensation: Some(RECALL),
        ..mk(SEND, "mail.send", Effect::External, Integrity::User, to_body())
    })
    .unwrap();
    r.register(mk(
        FILE,
        "mail.file",
        Effect::LocalIrreversible,
        Integrity::SystemApp,
        vec![Param::choice("folder", [b"inbox".to_vec(), b"archive".to_vec()])],
    ))
    .unwrap();
    r.register(mk(POST, "web.post", Effect::External, Integrity::User, to_body())).unwrap();
    r.register(ActionSpec {
        draft_for: Some(POST),
        ..mk(POST_DRAFT, "web.post.draft", Effect::LocalReversible, Integrity::UntrustedWeb, to_body())
    })
    .unwrap();
    r.register(mk(RECALL, "mail.recall", Effect::External, Integrity::User, to_body())).unwrap();
    r.register(mk(PAY, "payment.send", Effect::External, Integrity::User, vec![Param::open("account")])).unwrap();
    r.validate().unwrap();
    r
}

pub fn all_caps() -> CapSet {
    CapSet::new([READ, NOTE, SEND, FILE, POST, POST_DRAFT, RECALL, PAY])
}

/// Records every effect it is asked to run.
#[derive(Default)]
pub struct Recorder {
    pub calls: Vec<(ActionId, Vec<Vec<u8>>)>,
    pub fail_on: Option<ActionId>,
}

impl Recorder {
    pub fn count(&self, action: ActionId) -> usize {
        self.calls.iter().filter(|(a, _)| *a == action).count()
    }
}

impl Effects for Recorder {
    fn run(&mut self, action: &ActionSpec, args: &[&[u8]], _record: &AuditEntry) -> Result<Vec<u8>, EffectError> {
        self.calls.push((action.id, args.iter().map(|a| a.to_vec()).collect()));
        if self.fail_on == Some(action.id) { Err(EffectError("boom".into())) } else { Ok(Vec::new()) }
    }
}

/// A reader that ignores its input and returns fixed bytes: a hijacked reader.
pub struct Fixed(pub &'static [u8]);

impl Reader for Fixed {
    fn extract(&mut self, _schema: &Schema, _input: &[u8]) -> Result<Vec<u8>, ReaderError> {
        Ok(self.0.to_vec())
    }
}

/// A reader for plans with no `Read` steps.
pub struct NoReader;

impl Reader for NoReader {
    fn extract(&mut self, _schema: &Schema, _input: &[u8]) -> Result<Vec<u8>, ReaderError> {
        panic!("this plan has no Read steps")
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

    pub fn value(&mut self, bytes: &[u8], integrity: Integrity) -> Handle {
        self.table.intern(&self.ingress, S1, bytes.to_vec(), Label::new(Secrecy::EMPTY, integrity), "test").unwrap()
    }

    pub fn user(&mut self, bytes: &[u8]) -> Handle {
        self.value(bytes, Integrity::User)
    }

    pub fn web(&mut self, bytes: &[u8]) -> Handle {
        self.value(bytes, Integrity::UntrustedWeb)
    }

    /// Interns the plan's literals as user input, binds `inputs` and builds an executor.
    pub fn start<'p>(&mut self, plan: &'p Plan, inputs: Vec<(&str, Binding)>) -> Executor<'p> {
        let mut env = intern_literals(&mut self.table, &self.ingress, S1, plan, Label::TOP).unwrap();
        for (name, binding) in inputs {
            env.bind(name, binding).unwrap();
        }
        Executor::new(plan, env, self.gate.registry(), S1).unwrap()
    }

    pub fn run(&mut self, exec: &mut Executor<'_>, reader: &mut dyn Reader) -> Outcome {
        let mut host = Quarantine::new(&self.ingress, reader);
        exec.run(&mut self.gate, &mut self.table, &mut self.fx, &mut host)
    }

    pub fn resume(&mut self, exec: &mut Executor<'_>, reader: &mut dyn Reader, approval: SignedApproval) -> Outcome {
        let mut host = Quarantine::new(&self.ingress, reader);
        exec.resume_with_approval(&mut self.gate, &mut self.table, &mut self.fx, &mut host, approval)
    }

    pub fn approve(&self, req: &ApprovalRequest) -> SignedApproval {
        self.approver.approve(req, self.clock.now_ms() + 60_000)
    }

    pub fn saga(&mut self, exec: &mut Executor<'_>) -> SagaReport {
        commit_with_saga(&mut self.gate, &self.table, &mut self.fx, exec).unwrap()
    }

    pub fn commit(&mut self) -> CommitReport {
        self.gate.commit(&self.table, S1, &mut self.fx).unwrap()
    }

    pub fn approvals_requested(&self) -> usize {
        self.gate.audit().entries().iter().filter(|e| matches!(e.kind, AuditKind::ApprovalRequested(_))).count()
    }
}

pub fn plan(json: &str) -> Plan {
    fewshot_plan::parse(json).unwrap()
}
