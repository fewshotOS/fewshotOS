//! Hash-chained audit log (docs/ARCHITECTURE.md §4.6, I4).

use crate::action::ActionId;
use crate::approval::{Digest, Nonce};
use crate::refusal::Reason;
use alloc::string::String;
use alloc::vec::Vec;
use fewshot_labeld::SessionId;
use sha2::{Digest as _, Sha256};

/// What an entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// A session was opened.
    SessionOpened,
    /// The gate refused a call.
    Refused(Reason),
    /// Approval was requested from the user.
    ApprovalRequested(Nonce),
    /// The call was allowed and the effect is about to run now.
    EffectStarted,
    /// The call was allowed and the effect was queued in the outbox.
    Queued,
    /// The effect completed.
    EffectSucceeded,
    /// The effect completed and returned an output; SHA-256 of its bytes.
    EffectReturned([u8; 32]),
    /// The effect failed.
    EffectFailed,
    /// Queued effects were dropped without running (abort, or a failed commit).
    OutboxDropped(u32),
    /// A session was closed.
    SessionClosed,
}

/// One audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// Position in the log, from 0.
    pub seq: u64,
    /// Time of the entry.
    pub at_ms: u64,
    /// Session concerned.
    pub session: SessionId,
    /// Action concerned, if any.
    pub action: Option<ActionId>,
    /// Invocation digest, if any. Doubles as the effect's idempotency key.
    pub digest: Option<Digest>,
    /// What happened.
    pub kind: AuditKind,
    /// Hash of the previous entry (zeros for the first).
    pub prev: [u8; 32],
    /// Hash of this entry.
    pub hash: [u8; 32],
}

/// Durable storage for audit entries, such as an append-only file. The gate
/// runs an effect only once every entry up to and including its
/// [`AuditKind::EffectStarted`] has been stored (I4).
pub trait AuditSink {
    /// Stores `entry`, which follows the last entry stored.
    fn append(&mut self, entry: &AuditEntry) -> Result<(), SinkError>;
}

/// An [`AuditSink`] could not store an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkError(pub String);

/// The audit log. Append-only; each entry hashes the previous one.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// All entries, oldest first.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Checks the hash chain; returns the first broken position.
    pub fn verify(&self) -> Result<(), u64> {
        verify_chain(&self.entries)
    }

    pub(crate) fn append(
        &mut self,
        at_ms: u64,
        session: SessionId,
        action: Option<ActionId>,
        digest: Option<Digest>,
        kind: AuditKind,
    ) -> &AuditEntry {
        let prev = self.entries.last().map_or([0u8; 32], |e| e.hash);
        let mut e =
            AuditEntry { seq: self.entries.len() as u64, at_ms, session, action, digest, kind, prev, hash: [0; 32] };
        e.hash = entry_hash(&e);
        self.entries.push(e);
        self.entries.last().expect("just pushed")
    }

    #[cfg(test)]
    pub(crate) fn entries_mut(&mut self) -> &mut Vec<AuditEntry> {
        &mut self.entries
    }
}

/// Checks a whole log read back from storage: it starts at `seq` 0 with a
/// zero `prev`, numbers entries consecutively, and every hash matches.
/// Returns the `seq` of the first broken entry (or its position, if `seq`
/// is wrong).
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), u64> {
    let mut prev = [0u8; 32];
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(i as u64);
        }
        if e.prev != prev || e.hash != entry_hash(e) {
            return Err(e.seq);
        }
        prev = e.hash;
    }
    Ok(())
}

fn entry_hash(e: &AuditEntry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"fewshot-audit-v1");
    h.update(e.prev);
    h.update(e.seq.to_le_bytes());
    h.update(e.at_ms.to_le_bytes());
    h.update(e.session.0.to_le_bytes());
    match e.action {
        Some(a) => h.update([[1u8].as_slice(), &a.0.to_le_bytes()].concat()),
        None => h.update([0u8]),
    }
    match e.digest {
        Some(d) => h.update([[1u8].as_slice(), &d.0].concat()),
        None => h.update([0u8]),
    }
    let (code, payload): (u8, u64) = match e.kind {
        AuditKind::SessionOpened => (0, 0),
        AuditKind::Refused(r) => (1, reason_code(r)),
        AuditKind::ApprovalRequested(n) => (2, n.0),
        AuditKind::EffectStarted => (3, 0),
        AuditKind::Queued => (4, 0),
        AuditKind::EffectSucceeded => (5, 0),
        AuditKind::EffectFailed => (6, 0),
        AuditKind::OutboxDropped(n) => (7, u64::from(n)),
        AuditKind::SessionClosed => (8, 0),
        AuditKind::EffectReturned(_) => (9, 0),
    };
    h.update([code]);
    h.update(payload.to_le_bytes());
    if let AuditKind::EffectReturned(output) = e.kind {
        h.update(output);
    }
    h.finalize().into()
}

fn reason_code(r: Reason) -> u64 {
    use crate::refusal::ApprovalError as A;
    match r {
        Reason::UnknownSession => 0,
        Reason::UnknownAction => 1,
        Reason::MissingCapability => 2,
        Reason::WrongArity => 3,
        Reason::UnknownHandle => 4,
        Reason::EgressNotCleared => 5,
        Reason::ApprovalInvalid(a) => {
            16 + match a {
                A::UnknownNonce => 0,
                A::Reused => 1,
                A::Expired => 2,
                A::BadSignature => 3,
                A::DigestMismatch => 4,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tampering_breaks_the_chain() {
        let mut log = AuditLog::default();
        for i in 0..3 {
            log.append(i, SessionId(1), Some(ActionId(7)), None, AuditKind::Queued);
        }
        assert_eq!(log.verify(), Ok(()));
        log.entries_mut()[1].kind = AuditKind::EffectSucceeded;
        assert_eq!(log.verify(), Err(1));
    }

    #[test]
    fn verify_chain_rejects_dropped_or_reordered_entries() {
        let mut log = AuditLog::default();
        for i in 0..3 {
            log.append(i, SessionId(1), None, None, AuditKind::SessionOpened);
        }
        let all = log.entries();
        assert_eq!(verify_chain(all), Ok(()));
        assert_eq!(verify_chain(&all[1..]), Err(0), "a log must start at seq 0");
        assert_eq!(verify_chain(&[all[0], all[2]]), Err(1), "no gaps");
        assert_eq!(verify_chain(&[all[0], all[2], all[1]]), Err(1));
    }

    #[test]
    fn output_hash_is_chained() {
        let mut log = AuditLog::default();
        log.append(0, SessionId(1), Some(ActionId(7)), None, AuditKind::EffectReturned([1; 32]));
        assert_eq!(log.verify(), Ok(()));
        log.entries_mut()[0].kind = AuditKind::EffectReturned([2; 32]);
        assert_eq!(log.verify(), Err(0));
    }
}
