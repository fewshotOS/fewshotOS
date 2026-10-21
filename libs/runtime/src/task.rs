//! `run_task` (T4): the R2 planner and executor over a runtime session.
//!
//! This is the CaMeL path for an MCP client. The planner sees only the
//! request and host-written descriptions of the inputs; the executor runs the
//! plan through the gate; untrusted bytes reach only the quarantined reader.
//! The client's model never sees the content. The request still came from
//! the client, so the plan's literals are interned at the client's literal
//! label joined with the session's principal label, never at `User`.

use crate::{Runtime, RuntimeError};
use fewshot_executor::host::{Quarantine, intern_literals};
use fewshot_executor::{Binding, InputSummary, Outcome, Planner, PlannerInput, Reader, commit_with_saga};
use fewshot_gate::{ApprovalRequest, Effects, Refusal, SignedApproval};
use fewshot_labeld::{Handle, Label, Provenance, SessionId};

/// A value the client hands to a task, bound to a plan variable.
#[derive(Clone, Debug)]
pub struct TaskInput {
    /// The variable name the plan uses.
    pub var: String,
    /// The value, a handle in the task's session.
    pub value: Handle,
}

/// How a task ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskOutcome {
    /// The plan finished. Queued effects wait in the outbox for commit.
    Done {
        /// Effects waiting in the session's outbox.
        queued: usize,
    },
    /// A call needed approval and did not get it; the text says why.
    NotApproved(String),
    /// The gate refused a call.
    Refused(Refusal),
    /// The planner could not produce a valid plan, or the plan failed.
    Failed(String),
}

/// What a value is, without its bytes: for a client that holds only a handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueInfo {
    /// Its label.
    pub label: Label,
    /// Its length in bytes.
    pub bytes: usize,
    /// Where it came from: an ingress origin or the operation that derived it.
    pub origin: String,
}

impl<E: Effects> Runtime<E> {
    /// The label, length and origin of a value, without reading it.
    pub fn describe(&self, session: SessionId, h: Handle) -> Result<ValueInfo, RuntimeError> {
        self.client_cfg(session)?;
        let r = self.table.resolve(session, h).map_err(|e| RuntimeError::Table(e.to_string()))?;
        let origin = match r.provenance {
            Provenance::Ingress { origin } => origin.clone(),
            Provenance::Derived { op, .. } => op.clone(),
        };
        Ok(ValueInfo { label: r.label, bytes: r.value.len(), origin })
    }

    /// Plans `request` with `planner` and runs the plan in `session`.
    /// `approve` is asked for each approval the plan needs; `Err` carries why
    /// there is none (declined, timed out, no approval app) and stops the task.
    /// Checkpoints commit the outbox with compensation on failure.
    pub fn run_task<R: Reader>(
        &mut self,
        session: SessionId,
        request: &str,
        inputs: &[TaskInput],
        planner: &mut dyn Planner,
        reader: R,
        mut approve: impl FnMut(&ApprovalRequest) -> Result<SignedApproval, String>,
    ) -> Result<TaskOutcome, RuntimeError> {
        let literal_label = self.client_cfg(session)?.literal_label().join(self.table.principal_label(session));
        let caps = self.caps_for(&self.sessions[&session].clone())?;
        let mut summaries = Vec::with_capacity(inputs.len());
        for input in inputs {
            let info = self.describe(session, input.value)?;
            // Host-written: a length and an origin, never the bytes.
            let description = format!("{} bytes from {}", info.bytes, info.origin);
            summaries.push(InputSummary { var: input.var.clone(), description, list: false });
        }
        let planner_input = PlannerInput::new(request, self.gate.registry(), &caps, summaries);
        let plan = match planner.plan(&planner_input) {
            Ok(p) => p,
            Err(e) => return Ok(TaskOutcome::Failed(format!("planning failed: {e:?}"))),
        };

        let mut env = intern_literals(&mut self.table, &self.ingress, session, &plan, literal_label)
            .map_err(|e| RuntimeError::Table(e.to_string()))?;
        for input in inputs {
            if let Err(e) = env.bind(input.var.clone(), Binding::One(input.value)) {
                return Ok(TaskOutcome::Failed(e.to_string()));
            }
        }
        let mut exec = match fewshot_executor::Executor::new(&plan, env, self.gate.registry(), session) {
            Ok(x) => x,
            Err(e) => return Ok(TaskOutcome::Failed(format!("the plan is invalid: {e:?}"))),
        };
        let mut host = Quarantine::new(&self.ingress, reader);
        let mut outcome = exec.run(&mut self.gate, &mut self.table, &mut self.effects, &mut host);
        loop {
            outcome = match outcome {
                Outcome::Done { .. } => return Ok(TaskOutcome::Done { queued: self.gate.outbox_len(session) }),
                Outcome::NeedsApproval(req) => match approve(&req) {
                    Ok(a) => {
                        exec.resume_with_approval(&mut self.gate, &mut self.table, &mut self.effects, &mut host, a)
                    }
                    Err(why) => return Ok(TaskOutcome::NotApproved(why)),
                },
                Outcome::Checkpoint => {
                    let report = commit_with_saga(&mut self.gate, &self.table, &mut self.effects, &mut exec)
                        .map_err(RuntimeError::Refused)?;
                    if let Some((_, e)) = report.failed {
                        return Ok(TaskOutcome::Failed(format!(
                            "an effect failed at a checkpoint ({}); {} undone, {} could not be undone",
                            e.0,
                            report.compensated.len(),
                            report.not_compensated.len()
                        )));
                    }
                    exec.run(&mut self.gate, &mut self.table, &mut self.effects, &mut host)
                }
                Outcome::Refused(r) => return Ok(TaskOutcome::Refused(r)),
                Outcome::Failed(e) => return Ok(TaskOutcome::Failed(e.to_string())),
            };
        }
    }
}
