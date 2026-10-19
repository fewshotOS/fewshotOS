//! Digest-bound, signed, single-use approvals (ADR-0006).
//!
//! The gate computes an invocation digest over the action, the resolved
//! argument values and labels, the session and a fresh nonce. The trusted
//! approval surface shows the request and signs `(digest, nonce, expiry)` with
//! a key no agent holds. On re-invocation the gate recomputes the digest; any
//! changed argument produces a different digest and the approval is refused.

use crate::action::ActionId;
use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fewshot_labeld::{Label, Resolved, SessionId};
use sha2::{Digest as _, Sha256};

/// SHA-256 of an invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

/// A gate-issued, never-repeated number binding one approval request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce(pub u64);

/// What the trusted surface shows for one argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgSummary {
    /// Parameter name.
    pub param: String,
    /// The value's label.
    pub label: Label,
    /// Where the value came from.
    pub origin: String,
    /// Whether this argument is why approval is needed.
    pub below_floor: bool,
}

/// A request for the user's approval, built from gate data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The invocation digest to sign.
    pub digest: Digest,
    /// The nonce it was computed with.
    pub nonce: Nonce,
    /// Requesting session.
    pub session: SessionId,
    /// Action to run.
    pub action: ActionId,
    /// Per-argument facts.
    pub args: Vec<ArgSummary>,
    /// The session's principal label: everything it read before the call.
    pub context: Label,
    /// Whether the context is why approval is needed: the call depends on
    /// data below the floor even if every argument is clean.
    pub context_below_floor: bool,
}

/// The user's signed consent to exactly one invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedApproval {
    /// Approved digest.
    pub digest: Digest,
    /// Nonce from the request.
    pub nonce: Nonce,
    /// Not valid after this time.
    pub expires_at_ms: u64,
    /// Ed25519 signature over [`signed_message`].
    pub signature: [u8; 64],
}

/// Holds the approval signing key. Lives only in the trusted UI path.
pub struct Approver {
    key: SigningKey,
}

impl Approver {
    /// From a 32-byte secret key.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Approver { key: SigningKey::from_bytes(&secret) }
    }

    /// The key the gate verifies against.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Signs a request the user approved.
    pub fn approve(&self, request: &ApprovalRequest, expires_at_ms: u64) -> SignedApproval {
        let msg = signed_message(request.digest, request.nonce, expires_at_ms);
        SignedApproval {
            digest: request.digest,
            nonce: request.nonce,
            expires_at_ms,
            signature: self.key.sign(&msg).to_bytes(),
        }
    }
}

/// The exact bytes an approval signs: domain tag, digest, nonce, expiry.
pub fn signed_message(digest: Digest, nonce: Nonce, expires_at_ms: u64) -> [u8; 67] {
    let mut m = [0u8; 67];
    m[..19].copy_from_slice(b"fewshot-approval-v1");
    m[19..51].copy_from_slice(&digest.0);
    m[51..59].copy_from_slice(&nonce.0.to_le_bytes());
    m[59..67].copy_from_slice(&expires_at_ms.to_le_bytes());
    m
}

pub(crate) fn verify(key: &VerifyingKey, a: &SignedApproval) -> bool {
    let msg = signed_message(a.digest, a.nonce, a.expires_at_ms);
    key.verify_strict(&msg, &Signature::from_bytes(&a.signature)).is_ok()
}

/// Digest of an invocation over resolved values and their labels.
pub(crate) fn invocation_digest(session: SessionId, action: ActionId, nonce: Nonce, args: &[Resolved<'_>]) -> Digest {
    let mut h = Sha256::new();
    h.update(b"fewshot-invocation-v1");
    h.update(session.0.to_le_bytes());
    h.update(action.0.to_le_bytes());
    h.update(nonce.0.to_le_bytes());
    h.update((args.len() as u64).to_le_bytes());
    for a in args {
        h.update((a.value.len() as u64).to_le_bytes());
        h.update(a.value);
        h.update(a.label.secrecy.bits().to_le_bytes());
        h.update([a.label.integrity as u8]);
    }
    Digest(h.finalize().into())
}
