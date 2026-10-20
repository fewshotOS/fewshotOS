//! The gate's decision procedure and audit ordering
//! (docs/ARCHITECTURE.md §4.5, ADR-0005, ADR-0006).
use crate::labels::*;
use vstd::prelude::*;

verus! {

pub enum Effect {
    Read,
    LocalReversible,
    LocalIrreversible,
    External,
    /// Reads from off the device: runs at once, but its arguments leave the device.
    Fetch,
}

pub struct ActionMeta {
    pub id: u32,
    pub effect: Effect,
    pub integrity_floor: u8,
    /// Secrecy tags this action may send off-device
    /// (its egressTags intersected with the destination's clearance).
    pub egress_clearance: u64,
}

/// labeld's value table (ADR-0005): handle `h` names `labels[h]`.
pub struct ValueTable {
    pub labels: Vec<Label>,
}

/// An invocation carries value handles, never labels.
pub struct Invocation {
    pub action: u32,
    pub args: Vec<usize>,
}

pub enum Refusal {
    MissingCapability,
    UnknownHandle,
    EgressNotCleared,
}

pub enum Decision {
    /// read / localReversible: runs on the session's txn branch now.
    Execute,
    /// localIrreversible / external: goes to the outbox.
    Queue,
    /// Arguments are below the action's integrity floor: ask the user.
    NeedsApproval,
    Denied(Refusal),
}

pub open spec fn holds(caps: Seq<u32>, action: u32) -> bool {
    caps.contains(action)
}

pub open spec fn valid_handles(labels: Seq<Label>, args: Seq<usize>) -> bool {
    forall|i: int| 0 <= i < args.len() ==> (args[i] as int) < labels.len()
}

/// Join of every argument's label, resolved in the value table.
pub open spec fn args_label(labels: Seq<Label>, args: Seq<usize>) -> Label
    decreases args.len(),
{
    if args.len() == 0 {
        top()
    } else {
        join(args_label(labels, args.drop_last()), labels[args.last() as int])
    }
}

pub open spec fn is_immediate(e: Effect) -> bool {
    e is Read || e is LocalReversible || e is Fetch
}

/// Arguments of these effects leave the device, so egress clearance applies (I3).
pub open spec fn leaves_device(e: Effect) -> bool {
    e is External || e is Fetch
}

/// Gate steps 1–4. `approval_valid` means a signed approval matching this
/// invocation's digest was presented (ADR-0006; digest binding is model-checked
/// in specs/tla/Txn.tla).
///
/// Labels are read only from `table`: the caller cannot influence them (ADR-0005).
pub fn decide(
    caps: &Vec<u32>,
    table: &ValueTable,
    inv: &Invocation,
    meta: &ActionMeta,
    approval_valid: bool,
) -> (d: Decision)
    requires
        meta.id == inv.action,
    ensures
        !holds(caps@, inv.action) ==> d == Decision::Denied(Refusal::MissingCapability),
        (d is Execute || d is Queue) ==> {
            &&& holds(caps@, inv.action)
            &&& valid_handles(table.labels@, inv.args@)
            &&& (args_label(table.labels@, inv.args@).integrity >= meta.integrity_floor
                || approval_valid)
            &&& (leaves_device(meta.effect) ==> subset(
                args_label(table.labels@, inv.args@).secrecy,
                meta.egress_clearance,
            ))
        },
        d is Execute ==> is_immediate(meta.effect),
        d is Queue ==> !is_immediate(meta.effect),
{
    // 1. Capability.
    let mut held = false;
    let mut i: usize = 0;
    while i < caps.len()
        invariant
            0 <= i <= caps.len(),
            held == (exists|j: int| 0 <= j < i && caps@[j] == inv.action),
        decreases caps.len() - i,
    {
        if caps[i] == inv.action {
            held = true;
        }
        i += 1;
    }
    if !held {
        return Decision::Denied(Refusal::MissingCapability);
    }
    assert(holds(caps@, inv.action));

    // 2. Labels, resolved from the value table.
    let mut acc = Label { secrecy: 0, integrity: USER };
    let mut k: usize = 0;
    assert(inv.args@.take(0) =~= Seq::<usize>::empty());
    while k < inv.args.len()
        invariant
            0 <= k <= inv.args.len(),
            holds(caps@, inv.action),
            valid_handles(table.labels@, inv.args@.take(k as int)),
            acc == args_label(table.labels@, inv.args@.take(k as int)),
        decreases inv.args.len() - k,
    {
        let h = inv.args[k];
        if h >= table.labels.len() {
            return Decision::Denied(Refusal::UnknownHandle);
        }
        acc = join_exec(&acc, &table.labels[h]);
        proof {
            let next = inv.args@.take(k + 1);
            assert(next.drop_last() =~= inv.args@.take(k as int));
            assert(next.last() == h);
            assert forall|j: int| 0 <= j < next.len() implies (next[j] as int)
                < table.labels@.len() by {
                if j < k {
                    assert(next[j] == inv.args@.take(k as int)[j]);
                }
            }
        }
        k += 1;
    }
    assert(inv.args@.take(k as int) =~= inv.args@);

    // 3. Egress clearance for anything leaving the device.
    let leaves = match meta.effect {
        Effect::External | Effect::Fetch => true,
        _ => false,
    };
    if leaves && (acc.secrecy & meta.egress_clearance) != acc.secrecy {
        return Decision::Denied(Refusal::EgressNotCleared);
    }

    // 4. Integrity floor, unless a matching approval was presented.
    if acc.integrity < meta.integrity_floor && !approval_valid {
        return Decision::NeedsApproval;
    }

    match meta.effect {
        Effect::Read | Effect::LocalReversible | Effect::Fetch => Decision::Execute,
        _ => Decision::Queue,
    }
}

// ---------------------------------------------------------------------------
// I4: audit before effect.

pub enum Event {
    Audit(u64),
    Exec(u64),
}

pub open spec fn audited_before(log: Seq<Event>, i: int) -> bool {
    match log[i] {
        Event::Exec(e) => exists|j: int| 0 <= j < i && log[j] == Event::Audit(e),
        Event::Audit(_) => true,
    }
}

pub open spec fn audit_before_effect(log: Seq<Event>) -> bool {
    forall|i: int| 0 <= i < log.len() ==> #[trigger] audited_before(log, i)
}

pub struct Gate {
    pub log: Vec<Event>,
}

impl Gate {
    pub fn new() -> (g: Self)
        ensures
            audit_before_effect(g.log@),
    {
        Gate { log: Vec::new() }
    }

    /// Gate step 5, then the effect. The only way to record an effect.
    pub fn run_effect(&mut self, eid: u64)
        requires
            audit_before_effect(old(self).log@),
        ensures
            audit_before_effect(final(self).log@),
            final(self).log@ == old(self).log@.push(Event::Audit(eid)).push(Event::Exec(eid)),
    {
        let ghost old_log = self.log@;
        self.log.push(Event::Audit(eid));
        self.log.push(Event::Exec(eid));
        proof {
            let l = self.log@;
            assert forall|i: int| 0 <= i < l.len() implies #[trigger] audited_before(l, i) by {
                if i < old_log.len() {
                    assert(audited_before(old_log, i));
                    assert(l[i] == old_log[i]);
                    if let Event::Exec(e) = old_log[i] {
                        let j = choose|j: int| 0 <= j < i && old_log[j] == Event::Audit(e);
                        assert(l[j] == old_log[j]);
                    }
                } else if i == old_log.len() + 1 {
                    assert(l[i - 1] == Event::Audit(eid));
                }
            }
        }
    }
}

} // verus!
