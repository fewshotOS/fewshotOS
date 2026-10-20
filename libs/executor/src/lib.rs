//! The plan interpreter (docs/ARCHITECTURE.md §5.1–5.3).
//!
//! An [`Executor`] runs a validated [`Plan`]. Variables hold [`Handle`]s, and
//! the executor touches values only through [`ValueTable::view`], so whatever
//! it computes carries the label of everything the session has read. Every
//! action goes through [`Gate::invoke`]; the executor never decides whether a
//! call is allowed. Untrusted bytes reach a model only through a
//! [`ReaderHost`] (see [`host`]) and never reach the [`Planner`].
//!
//! External actions that have a draft action are drafted rather than queued
//! ([`Draft`], [`Executor::release_draft`]). [`Step::Checkpoint`] pauses the
//! plan so the host can commit with [`commit_with_saga`], which compensates
//! committed effects in reverse when a later one fails.
#![no_std]

extern crate alloc;

pub mod host;
mod saga;

pub use host::{ReadError, ReaderHost};
pub use saga::{SagaReport, commit_with_saga};

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use fewshot_gate::{
    ActionId, ApprovalRequest, CapSet, Decision, Digest, Effect, EffectError, Effects, Gate, Invocation, Param,
    Refusal, Registry, SignedApproval,
};
use fewshot_host::Clock;
use fewshot_labeld::{Handle, SessionId, TableError, ValueTable};
use fewshot_plan::{Plan, PlanError, Schema, Step};

/// Extracts values from untrusted input. Agent side: it may be hijacked, so
/// the runtime assumes any output is possible.
pub trait Reader {
    /// Extract a value matching `schema` from untrusted `input`.
    fn extract(&mut self, schema: &Schema, input: &[u8]) -> Result<Vec<u8>, ReaderError>;
}

impl<R: Reader + ?Sized> Reader for &mut R {
    fn extract(&mut self, schema: &Schema, input: &[u8]) -> Result<Vec<u8>, ReaderError> {
        (**self).extract(schema, input)
    }
}

/// A reader failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderError(pub String);

/// Writes plans. Sees only a [`PlannerInput`], never untrusted bytes.
pub trait Planner {
    /// A plan for `input`.
    fn plan(&mut self, input: &PlannerInput) -> Result<Plan, PlannerError>;
}

/// A planner failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannerError {
    /// The model backend failed.
    Backend(String),
    /// The model's last plan did not parse or validate.
    Invalid(PlanError),
    /// The model's last plan parsed and validated, but the linter still
    /// rejected it (no call despite offered actions, or a let nobody reads).
    Lint(String),
}

/// An action as the planner sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionSummary {
    /// Id to use in `Call` steps.
    pub id: ActionId,
    /// Name, e.g. `"mail.send"`.
    pub name: String,
    /// Effect class.
    pub effect: Effect,
    /// Parameters, in order.
    pub params: Vec<Param>,
}

/// A pre-bound input as the planner sees it: a name and a host-written
/// description, never its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSummary {
    /// Variable name the plan uses.
    pub var: String,
    /// What it holds, written by the host.
    pub description: String,
    /// Whether it is a list (usable in `ForEach`).
    pub list: bool,
}

/// Everything a planner may see. Built only by [`PlannerInput::new`], which
/// takes no untrusted bytes: inputs appear by name and description only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerInput {
    request: String,
    actions: Vec<ActionSummary>,
    inputs: Vec<InputSummary>,
    feedback: Option<String>,
}

impl PlannerInput {
    /// `request` is the user's request, verbatim. Lists the actions in
    /// `registry` that the session holds in `caps`.
    pub fn new(request: impl Into<String>, registry: &Registry, caps: &CapSet, inputs: Vec<InputSummary>) -> Self {
        let actions = registry
            .iter()
            .filter(|a| caps.contains(a.id))
            .map(|a| ActionSummary { id: a.id, name: a.name.clone(), effect: a.effect, params: a.params.clone() })
            .collect();
        PlannerInput { request: request.into(), actions, inputs, feedback: None }
    }

    /// The same input with feedback on a previous attempt: a [`PlanError`]
    /// or [`Refusal`] rendered as text.
    pub fn with_feedback(mut self, feedback: impl Into<String>) -> Self {
        self.feedback = Some(feedback.into());
        self
    }

    /// The user's request.
    pub fn request(&self) -> &str {
        &self.request
    }

    /// Actions the plan may call.
    pub fn actions(&self) -> &[ActionSummary] {
        &self.actions
    }

    /// Pre-bound inputs.
    pub fn inputs(&self) -> &[InputSummary] {
        &self.inputs
    }

    /// Feedback on a previous attempt.
    pub fn feedback(&self) -> Option<&str> {
        self.feedback.as_deref()
    }
}

/// What a variable holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// One value.
    One(Handle),
    /// A list of values, bound by the host (the executor never builds one).
    List(Vec<Handle>),
}

/// Variable bindings: a stack of scopes, plus the handles of the plan's
/// literals (see [`host::intern_literals`]).
#[derive(Clone, Debug)]
pub struct Env {
    scopes: Vec<BTreeMap<String, Binding>>,
    literals: BTreeMap<String, Handle>,
}

impl Default for Env {
    fn default() -> Self {
        Env::new()
    }
}

impl Env {
    /// An environment with no bindings and no literals.
    pub fn new() -> Self {
        Env { scopes: vec![BTreeMap::new()], literals: BTreeMap::new() }
    }

    /// Binds `name` in the innermost scope. Names cannot be rebound or shadowed.
    pub fn bind(&mut self, name: impl Into<String>, binding: Binding) -> Result<(), ExecError> {
        let name = name.into();
        if self.get(&name).is_some() {
            return Err(ExecError::Rebound(name));
        }
        self.scopes.last_mut().expect("an environment always has a scope").insert(name, binding);
        Ok(())
    }

    /// Looks up a name, innermost scope first.
    pub fn get(&self, name: &str) -> Option<&Binding> {
        self.scopes.iter().rev().find_map(|s| s.get(name))
    }

    fn push(&mut self) {
        self.scopes.push(BTreeMap::new());
    }

    fn pop(&mut self) {
        self.scopes.pop();
    }
}

/// A local draft of an external action, made instead of queueing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// The draft action that ran.
    pub draft_action: ActionId,
    /// The external action [`Executor::release_draft`] invokes.
    pub release_action: ActionId,
    /// Arguments for both.
    pub args: Vec<Handle>,
}

/// Where a run stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The plan finished. External effects wait in the outbox for commit.
    Done {
        /// Drafts made in place of external actions.
        drafts: Vec<Draft>,
    },
    /// A call needs the user's approval. Continue with
    /// [`Executor::resume_with_approval`]; without one the plan stays paused.
    NeedsApproval(ApprovalRequest),
    /// A checkpoint: the host calls [`commit_with_saga`], then [`Executor::run`].
    Checkpoint,
    /// The gate refused a call. The plan stops; the host may re-plan with feedback.
    Refused(Refusal),
    /// The plan could not continue.
    Failed(ExecError),
}

/// Why a plan could not continue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// A step named a variable that is not bound.
    UnknownVariable(String),
    /// A variable used as one value holds a list.
    NotAValue(String),
    /// A `ForEach` list variable holds one value.
    NotAList(String),
    /// A name was bound twice.
    Rebound(String),
    /// A `Let` literal was not interned before the run.
    MissingLiteral(String),
    /// The value table rejected an operation.
    Table(TableError),
    /// A `Read` step failed.
    Read(ReadError),
    /// An effect that runs at once failed.
    Effect(EffectError),
    /// The plan already finished, failed or was refused.
    Finished,
    /// The plan is paused for an approval; call [`Executor::resume_with_approval`].
    AwaitingApproval,
    /// [`Executor::resume_with_approval`] was called with nothing awaiting approval.
    NoPendingApproval,
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::UnknownVariable(v) => write!(f, "unknown variable \"{v}\""),
            ExecError::NotAValue(v) => write!(f, "\"{v}\" is a list; use it in a ForEach"),
            ExecError::NotAList(v) => write!(f, "\"{v}\" is not a list"),
            ExecError::Rebound(v) => write!(f, "\"{v}\" is already bound"),
            ExecError::MissingLiteral(v) => write!(f, "literal for \"{v}\" was not interned"),
            ExecError::Table(e) => write!(f, "{e}"),
            ExecError::Read(e) => write!(f, "read failed: {e}"),
            ExecError::Effect(e) => write!(f, "effect failed: {}", e.0),
            ExecError::Finished => write!(f, "the plan has already stopped"),
            ExecError::AwaitingApproval => write!(f, "the plan is waiting for an approval"),
            ExecError::NoPendingApproval => write!(f, "nothing is waiting for an approval"),
        }
    }
}

/// One block being run: the top level, an `If` branch or a `ForEach` body.
/// Each frame has its own scope in the [`Env`].
struct Frame<'p> {
    steps: &'p [Step],
    next: usize,
    each: Option<Each<'p>>,
}

/// Loop state of a `ForEach` frame.
struct Each<'p> {
    var: &'p str,
    items: Vec<Handle>,
    index: usize,
}

/// A call waiting for approval.
struct Pending {
    inv: Invocation,
    release: Option<ActionId>,
}

/// Runs one plan for one session.
pub struct Executor<'p> {
    session: SessionId,
    frames: Vec<Frame<'p>>,
    env: Env,
    pending: Option<Pending>,
    queued: BTreeMap<Digest, (ActionId, Vec<Handle>)>,
    drafts: Vec<Draft>,
    finished: bool,
}

impl<'p> Executor<'p> {
    /// An executor for `plan` in `session`. `env` holds the host's inputs and
    /// the plan's literals. The plan is validated against `registry`, with the
    /// names bound in `env` as its inputs.
    pub fn new(plan: &'p Plan, env: Env, registry: &Registry, session: SessionId) -> Result<Self, PlanError> {
        {
            let inputs: Vec<&str> = env.scopes[0].keys().map(String::as_str).collect();
            fewshot_plan::validate(plan, registry, &inputs)?;
        }
        Ok(Executor {
            session,
            frames: vec![Frame { steps: &plan.steps, next: 0, each: None }],
            env,
            pending: None,
            queued: BTreeMap::new(),
            drafts: Vec::new(),
            finished: false,
        })
    }

    /// The session this executor acts for.
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// Runs until the plan finishes, pauses or stops. After a checkpoint, call
    /// it again to continue.
    pub fn run<C: Clock, E: Effects>(
        &mut self,
        gate: &mut Gate<C>,
        table: &mut ValueTable,
        effects: &mut E,
        reader: &mut dyn ReaderHost,
    ) -> Outcome {
        if self.finished {
            return Outcome::Failed(ExecError::Finished);
        }
        if self.pending.is_some() {
            return Outcome::Failed(ExecError::AwaitingApproval);
        }
        loop {
            let Some(frame) = self.frames.last_mut() else {
                self.finished = true;
                return Outcome::Done { drafts: core::mem::take(&mut self.drafts) };
            };
            if frame.next == frame.steps.len() {
                // End of a block: drop its scope, then start the next loop
                // iteration in a fresh scope, or leave the block.
                self.env.pop();
                let next_item = match &mut frame.each {
                    Some(each) if each.index + 1 < each.items.len() => {
                        each.index += 1;
                        Some((each.var, each.items[each.index]))
                    }
                    _ => None,
                };
                match next_item {
                    Some((var, item)) => {
                        frame.next = 0;
                        self.env.push();
                        if let Err(e) = self.env.bind(var, Binding::One(item)) {
                            return self.fail(e);
                        }
                    }
                    None => {
                        self.frames.pop();
                    }
                }
                continue;
            }
            let steps = frame.steps;
            let step = &steps[frame.next];
            frame.next += 1;
            match self.step(step, gate, table, effects, reader) {
                Ok(None) => {}
                Ok(Some(outcome)) => return outcome,
                Err(e) => return self.fail(e),
            }
        }
    }

    /// Retries the call that returned [`Outcome::NeedsApproval`] with the
    /// user's signed approval, then continues the plan.
    pub fn resume_with_approval<C: Clock, E: Effects>(
        &mut self,
        gate: &mut Gate<C>,
        table: &mut ValueTable,
        effects: &mut E,
        reader: &mut dyn ReaderHost,
        approval: SignedApproval,
    ) -> Outcome {
        let Some(Pending { inv, release }) = self.pending.take() else {
            return Outcome::Failed(ExecError::NoPendingApproval);
        };
        let inv = inv.with_approval(approval);
        let result = gate.invoke(table, self.session, &inv, effects);
        let inv = Invocation { approval: None, ..inv };
        if let Some(outcome) = self.settle(inv, release, result) {
            return outcome;
        }
        self.run(gate, table, effects, reader)
    }

    /// Invokes the external action a draft stands for, with the draft's
    /// arguments. Tainted arguments need approval here: call again with the
    /// signed approval for the returned request.
    pub fn release_draft<C: Clock, E: Effects>(
        &mut self,
        gate: &mut Gate<C>,
        table: &ValueTable,
        effects: &mut E,
        draft: &Draft,
        approval: Option<SignedApproval>,
    ) -> Result<Decision, Refusal> {
        let inv = Invocation { approval, ..Invocation::new(draft.release_action, draft.args.iter().copied()) };
        let decision = gate.invoke(table, self.session, &inv, effects)?;
        if let Decision::Queued { digest, .. } = decision {
            self.queued.insert(digest, (inv.action, inv.args));
        }
        Ok(decision)
    }

    fn step<C: Clock, E: Effects>(
        &mut self,
        step: &'p Step,
        gate: &mut Gate<C>,
        table: &mut ValueTable,
        effects: &mut E,
        reader: &mut dyn ReaderHost,
    ) -> Result<Option<Outcome>, ExecError> {
        match step {
            Step::Let { var, text } => {
                // Re-derive the literal so it carries the principal label:
                // a `Let` inside a branch on tainted data is itself tainted.
                let literal = *self.env.literals.get(text).ok_or_else(|| ExecError::MissingLiteral(var.clone()))?;
                let mut view = table.view(self.session);
                let bytes = view.read(literal).map_err(ExecError::Table)?.to_vec();
                let h = view.derive("plan:let", &[literal], bytes).map_err(ExecError::Table)?;
                self.env.bind(var.as_str(), Binding::One(h))?;
                Ok(None)
            }
            Step::Call { action, args } => {
                let handles = args.iter().map(|a| self.one(a)).collect::<Result<Vec<_>, _>>()?;
                let action = ActionId(*action);
                let registry = gate.registry();
                let draft = match registry.get(action) {
                    Some(spec) if spec.effect == Effect::External => registry.draft_of(action).map(|d| d.id),
                    _ => None,
                };
                let (inv, release) = match draft {
                    Some(d) => (Invocation::new(d, handles), Some(action)),
                    None => (Invocation::new(action, handles), None),
                };
                let result = gate.invoke(table, self.session, &inv, effects);
                Ok(self.settle(inv, release, result))
            }
            Step::Read { var, input, schema } => {
                let input = self.one(input)?;
                let h = reader.read(table, self.session, input, schema).map_err(ExecError::Read)?;
                self.env.bind(var.as_str(), Binding::One(h))?;
                Ok(None)
            }
            Step::ForEach { var, list, max, body } => {
                let mut items = match self.env.get(list) {
                    Some(Binding::List(items)) => items.clone(),
                    Some(Binding::One(_)) => return Err(ExecError::NotAList(list.clone())),
                    None => return Err(ExecError::UnknownVariable(list.clone())),
                };
                items.truncate(*max as usize);
                if let Some(&first) = items.first() {
                    self.frames.push(Frame { steps: body, next: 0, each: Some(Each { var, items, index: 0 }) });
                    self.env.push();
                    self.env.bind(var.as_str(), Binding::One(first))?;
                }
                Ok(None)
            }
            Step::If { var, equals, then, otherwise } => {
                // A session read: raises the principal label, so everything
                // derived from here on carries the condition's label.
                let h = self.one(var)?;
                let taken = table.view(self.session).read(h).map_err(ExecError::Table)? == equals.as_bytes();
                let steps = if taken { then } else { otherwise };
                self.frames.push(Frame { steps, next: 0, each: None });
                self.env.push();
                Ok(None)
            }
            Step::Checkpoint => Ok(Some(Outcome::Checkpoint)),
        }
    }

    /// Records what the gate did with `inv`. Returns an outcome if the run stops.
    fn settle(
        &mut self,
        inv: Invocation,
        release: Option<ActionId>,
        result: Result<Decision, Refusal>,
    ) -> Option<Outcome> {
        match result {
            // `Call` binds no result, so an output is not kept.
            Ok(Decision::Executed(Ok(_))) => {
                if let Some(release_action) = release {
                    self.drafts.push(Draft { draft_action: inv.action, release_action, args: inv.args });
                }
                None
            }
            Ok(Decision::Executed(Err(e))) => Some(self.fail(ExecError::Effect(e))),
            Ok(Decision::Queued { digest, .. }) => {
                if let Some(release_action) = release {
                    self.drafts.push(Draft { draft_action: inv.action, release_action, args: inv.args.clone() });
                }
                self.queued.insert(digest, (inv.action, inv.args));
                None
            }
            Ok(Decision::NeedsApproval(req)) => {
                self.pending = Some(Pending { inv, release });
                Some(Outcome::NeedsApproval(req))
            }
            Err(refusal) => {
                self.finished = true;
                Some(Outcome::Refused(refusal))
            }
        }
    }

    fn one(&self, name: &str) -> Result<Handle, ExecError> {
        match self.env.get(name) {
            Some(Binding::One(h)) => Ok(*h),
            Some(Binding::List(_)) => Err(ExecError::NotAValue(name.into())),
            None => Err(ExecError::UnknownVariable(name.into())),
        }
    }

    fn fail(&mut self, e: ExecError) -> Outcome {
        self.finished = true;
        Outcome::Failed(e)
    }
}
