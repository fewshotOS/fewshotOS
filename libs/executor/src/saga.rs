//! Checkpoint commits with compensation (docs/ARCHITECTURE.md §4.3).

use crate::Executor;
use alloc::vec::Vec;
use fewshot_gate::{ActionId, Decision, Digest, EffectError, Effects, Gate, Invocation, Refusal};
use fewshot_host::Clock;
use fewshot_labeld::{Handle, SessionId, ValueTable};

/// Result of [`commit_with_saga`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SagaReport {
    /// Effects that ran, in order.
    pub committed: Vec<Digest>,
    /// The effect that failed, if any.
    pub failed: Option<(Digest, EffectError)>,
    /// Committed effects that were undone, latest first.
    pub compensated: Vec<Digest>,
    /// Committed effects that could not be undone: no compensation is
    /// declared, or it needed approval, was refused or failed. Latest first.
    pub not_compensated: Vec<Digest>,
    /// Effects dropped without running after the failure.
    pub not_run: Vec<Digest>,
}

/// Commits the session's outbox. If an effect fails, undoes the ones that
/// already ran, latest first, by invoking each one's declared compensation
/// with the same arguments. Compensations go through the gate like any other
/// call. A failure ends the plan: the executor will not run further.
pub fn commit_with_saga<C: Clock, E: Effects>(
    gate: &mut Gate<C>,
    table: &ValueTable,
    effects: &mut E,
    exec: &mut Executor<'_>,
) -> Result<SagaReport, Refusal> {
    let session = exec.session;
    let commit = gate.commit(table, session, effects)?;
    let mut report = SagaReport {
        committed: commit.executed,
        failed: commit.failed,
        not_run: commit.not_run,
        ..SagaReport::default()
    };
    for d in report.failed.iter().map(|(d, _)| d).chain(&report.not_run) {
        exec.queued.remove(d);
    }
    let failed = report.failed.is_some();
    if failed {
        exec.finished = true;
    }
    for &d in report.committed.iter().rev() {
        let call = exec.queued.remove(&d);
        if !failed {
            continue;
        }
        let undone = call.is_some_and(|(action, args)| compensate(gate, table, effects, session, action, args));
        if undone {
            report.compensated.push(d);
        } else {
            report.not_compensated.push(d);
        }
    }
    Ok(report)
}

/// Runs `action`'s compensation with `args`. True if it ran and succeeded.
fn compensate<C: Clock, E: Effects>(
    gate: &mut Gate<C>,
    table: &ValueTable,
    effects: &mut E,
    session: SessionId,
    action: ActionId,
    args: Vec<Handle>,
) -> bool {
    let Some(comp) = gate.registry().get(action).and_then(|s| s.compensation) else {
        return false;
    };
    match gate.invoke(table, session, &Invocation::new(comp, args), effects) {
        Ok(Decision::Executed(result)) => result.is_ok(),
        Ok(Decision::Queued { digest, .. }) => {
            matches!(gate.commit(table, session, effects), Ok(r) if r.failed.is_none() && r.executed.contains(&digest))
        }
        Ok(Decision::NeedsApproval(_)) | Err(_) => false,
    }
}
