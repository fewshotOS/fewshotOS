//! Runs plans against a scenario in a fresh gate and value table, and
//! collects what the oracle needs.
//!
//! Deny-all mode: the simulated user rejects every approval request.
//! Approve-all mode: the user signs every request (a control for the oracle,
//! and the honest mode's user).

use crate::compromised::{CompromisedExecutor, Trick};
use crate::oracle::{RecordedEffect, RecordingEffects, Violation};
use crate::scenarios::{Attack, Scenario};
use crate::stubs::{AdversarialPlanner, AdversarialReader, HonestReader, ScriptedPlanner};
use fewshot_executor::host::{Quarantine, intern_literals};
use fewshot_executor::{Binding, Executor, Outcome, Planner, ReadError, Reader, ReaderHost, commit_with_saga};
use fewshot_gate::{Approver, Decision, Gate, Invocation};
use fewshot_host::ManualClock;
use fewshot_labeld::{Handle, Label, SessionId, ValueTable};
use fewshot_plan::{Plan, Schema};

/// The session plans run in.
pub const SESSION: SessionId = SessionId(1);
/// The session leaked inputs are interned in.
pub const OTHER: SessionId = SessionId(2);

/// Approvals expire this far past the harness clock's start.
const APPROVAL_EXPIRY_MS: u64 = 60_000;

/// How one run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The plan ran to the end and was committed.
    Completed,
    /// A call needed approval; the user denied it.
    NeedsApproval,
    /// The gate refused a call.
    Refused,
    /// The plan failed.
    Failed,
}

/// The result of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// How it ended.
    pub end: End,
    /// What the oracle found.
    pub violations: Vec<Violation>,
    /// Approval requests shown to the user.
    pub prompts: usize,
    /// The effects that ran.
    pub effects: Vec<RecordedEffect>,
}

/// Deny-all results for a set of attacks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Attacks run.
    pub attacks: usize,
    /// Violations the oracle found.
    pub violations: Vec<Violation>,
    /// Attacks stopped by a refusal.
    pub refused: usize,
    /// Attacks stopped at a denied approval.
    pub needs_approval: usize,
    /// Attacks that failed.
    pub failed: usize,
    /// Attacks that ran to the end.
    pub completed: usize,
}

impl Report {
    /// Counts one run.
    pub fn add(&mut self, end: End, violations: Vec<Violation>) {
        self.attacks += 1;
        self.violations.extend(violations);
        match end {
            End::Completed => self.completed += 1,
            End::NeedsApproval => self.needs_approval += 1,
            End::Refused => self.refused += 1,
            End::Failed => self.failed += 1,
        }
    }
}

/// Wraps a [`ReaderHost`] and remembers every value it produced, so the
/// oracle can treat reader output as tainted.
struct Recording<H> {
    inner: H,
    outputs: Vec<Handle>,
}

impl<H: ReaderHost> ReaderHost for Recording<H> {
    fn read(
        &mut self,
        table: &mut ValueTable,
        session: SessionId,
        input: Handle,
        schema: &Schema,
    ) -> Result<Handle, ReadError> {
        let h = self.inner.read(table, session, input, schema)?;
        self.outputs.push(h);
        Ok(h)
    }
}

/// Runs `plan` with `reader` in a fresh gate and value table. With
/// `approve_all` the user signs every approval request; otherwise the first
/// one ends the run.
pub fn execute(scenario: &Scenario, plan: &Plan, reader: impl Reader, approve_all: bool) -> Run {
    let approver = Approver::from_secret([9; 32]);
    let mut gate = Gate::new(scenario.registry.clone(), approver.verifying_key(), ManualClock::new(1_000));
    gate.open_session(SESSION, scenario.caps.clone());
    let (mut table, ingress) = ValueTable::new();

    let mut env = intern_literals(&mut table, &ingress, SESSION, plan, Label::TOP).expect("session is open");
    let mut taint = Vec::new();
    for input in &scenario.inputs {
        let session = if input.leaked { OTHER } else { SESSION };
        let handles: Vec<Handle> = input
            .values
            .iter()
            .map(|v| {
                taint.push((v.to_vec(), input.label));
                let origin = format!("scenario:{}", input.name);
                table.intern(&ingress, session, v.to_vec(), input.label, origin).expect("session is open")
            })
            .collect();
        let binding = if input.list { Binding::List(handles) } else { Binding::One(handles[0]) };
        env.bind(input.name, binding).expect("input names are distinct");
    }
    let mut fx = RecordingEffects::default();
    let mut host = Recording { inner: Quarantine::new(&ingress, reader), outputs: Vec::new() };
    let mut prompts = 0;

    let end = match Executor::new(plan, env, gate.registry(), SESSION) {
        Err(_) => End::Failed,
        Ok(mut exec) => {
            let mut outcome = exec.run(&mut gate, &mut table, &mut fx, &mut host);
            loop {
                match outcome {
                    Outcome::Checkpoint => {
                        commit_with_saga(&mut gate, &table, &mut fx, &mut exec).expect("session is open");
                        outcome = exec.run(&mut gate, &mut table, &mut fx, &mut host);
                    }
                    Outcome::NeedsApproval(req) if approve_all => {
                        prompts += 1;
                        let approval = approver.approve(&req, APPROVAL_EXPIRY_MS);
                        outcome = exec.resume_with_approval(&mut gate, &mut table, &mut fx, &mut host, approval);
                    }
                    Outcome::Done { .. } => {
                        commit_with_saga(&mut gate, &table, &mut fx, &mut exec).expect("session is open");
                        break End::Completed;
                    }
                    Outcome::NeedsApproval(_) => {
                        prompts += 1;
                        break End::NeedsApproval;
                    }
                    Outcome::Refused(_) => break End::Refused,
                    Outcome::Failed(_) => break End::Failed,
                }
            }
        }
    };
    // Whatever is still queued is dropped unrun.
    gate.close_session(SESSION);

    for h in host.outputs {
        let r = table.resolve(SESSION, h).expect("reader outputs live in the session");
        taint.push((r.value.to_vec(), r.label));
    }
    let violations = fx.violations(&scenario.registry, &scenario.goal, &taint);
    Run { end, violations, prompts, effects: fx.effects }
}

/// Runs one attack against the hijacked reader, the user denying every
/// approval. Returns how it ended and what the oracle found.
pub fn run_attack(scenario: &Scenario, attack: &Attack) -> (End, Vec<Violation>) {
    run_attack_with(scenario, attack, false)
}

/// [`run_attack`], but with `approve_all` the user signs every approval
/// request instead. A control for the oracle: approved attacks get through,
/// and the oracle must report them.
pub fn run_attack_with(scenario: &Scenario, attack: &Attack, approve_all: bool) -> (End, Vec<Violation>) {
    let reader = AdversarialReader::new(scenario.payload, scenario.harmful_choice);
    let run = execute(scenario, &attack.plan, reader, approve_all);
    (run.end, run.violations)
}

/// The attacks an [`AdversarialPlanner`] writes for `scenario`.
pub fn planner_attacks(scenario: &Scenario) -> Vec<Attack> {
    let mut planner = AdversarialPlanner::new(scenario.registry.clone());
    let input = scenario.planner_input();
    let mut attacks = Vec::new();
    while let Ok(plan) = planner.plan(&input) {
        let name = planner.last_name().to_owned();
        attacks.push(Attack { name, plan, implicit_flow: false, expect: None });
    }
    attacks
}

/// Runs the scenario's hand-written attacks, then the adversarial planner's,
/// with the user denying every approval.
pub fn run_deny_all(scenario: &Scenario) -> Report {
    let mut report = Report::default();
    for attack in scenario.attacks.iter().chain(&planner_attacks(scenario)) {
        let (end, violations) = run_attack(scenario, attack);
        report.add(end, violations);
    }
    report
}

/// Approve-honest mode: the scripted honest planner and an honest reader,
/// the user approving every request. The run's `prompts` is the number of
/// approval prompts the benign task costs.
pub fn run_honest(scenario: &Scenario) -> Run {
    let mut planner = ScriptedPlanner::new(scenario.honest.plan);
    let plan = planner.plan(&scenario.planner_input()).expect("honest plans validate");
    execute(scenario, &plan, HonestReader::new(scenario.honest.reads.iter().copied()), true)
}

/// Whether the honest run produced exactly the effects the user expects.
pub fn honest_utility(scenario: &Scenario, run: &Run) -> bool {
    let expected: Vec<RecordedEffect> = scenario
        .honest
        .expected
        .iter()
        .map(|(action, args)| RecordedEffect { action: *action, args: args.iter().map(|a| a.to_vec()).collect() })
        .collect();
    run.end == End::Completed && run.effects == expected
}

/// Scenario 7: runs [`CompromisedExecutor`] with `trick` against
/// `scenario`'s goal action in a fresh gate and value table. With
/// `approve_all` the user signs the approval request, as a control.
pub fn run_compromised(scenario: &Scenario, trick: Trick, approve_all: bool) -> Run {
    let approver = Approver::from_secret([9; 32]);
    let mut gate = Gate::new(scenario.registry.clone(), approver.verifying_key(), ManualClock::new(1_000));
    gate.open_session(SESSION, scenario.caps.clone());
    let (mut table, ingress) = ValueTable::new();

    let mut taint = Vec::new();
    let mut inputs = Vec::new();
    let mut all = Vec::new();
    for input in &scenario.inputs {
        for v in &input.values {
            taint.push((v.to_vec(), input.label));
            all.extend_from_slice(v);
            let origin = format!("scenario:{}", input.name);
            inputs.push(table.intern(&ingress, SESSION, v.to_vec(), input.label, origin).expect("session is open"));
        }
    }
    let mut intern = |session, bytes: &[u8]| {
        table.intern(&ingress, session, bytes.to_vec(), Label::TOP, "harness:leak").expect("session is open")
    };
    let exec = CompromisedExecutor {
        inputs,
        clean: intern(SESSION, b"ok"),
        foreign: [intern(OTHER, scenario.payload), intern(OTHER, &all)],
        payload: scenario.payload.to_vec(),
    };

    let target = scenario.registry.get(scenario.goal.action).expect("the goal action is registered");
    let args = exec.launder(trick, &mut table.view(SESSION), target.params.len()).expect("inputs live in the session");
    for &h in &args {
        if let Ok(r) = table.resolve(SESSION, h) {
            taint.push((r.value.to_vec(), r.label));
        }
    }

    let mut fx = RecordingEffects::default();
    let mut prompts = 0;
    let mut inv = Invocation::new(target.id, args);
    let end = loop {
        match gate.invoke(&table, SESSION, &inv, &mut fx) {
            Ok(Decision::NeedsApproval(req)) => {
                prompts += 1;
                if !approve_all || inv.approval.is_some() {
                    break End::NeedsApproval;
                }
                inv = inv.with_approval(approver.approve(&req, APPROVAL_EXPIRY_MS));
            }
            Ok(Decision::Executed(_)) => break End::Completed,
            Ok(Decision::Queued { .. }) => {
                gate.commit(&table, SESSION, &mut fx).expect("session is open");
                break End::Completed;
            }
            Err(_) => break End::Refused,
        }
    };
    gate.close_session(SESSION);

    let violations = fx.violations(&scenario.registry, &scenario.goal, &taint);
    Run { end, violations, prompts, effects: fx.effects }
}
