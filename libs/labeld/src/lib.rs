//! The value table (ADR-0005).
//!
//! Every runtime value in an agent session lives here with its label and
//! provenance. Agents hold only [`Handle`]s. Deriving a value goes through
//! [`ValueTable::derive`], which computes the new label as the join of its
//! inputs and everything the session has read, so no agent component can
//! choose or misstate a label. Agents get a [`SessionView`]; only holders of an
//! [`Ingress`] capability can bring new labeled data in.
#![no_std]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use fewshot_labels::{Integrity, Label, Secrecy, Tag};

/// An agent session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);

/// An opaque reference to a value, valid only in the session that created it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle {
    session: SessionId,
    index: u32,
}

impl Handle {
    /// The session this handle belongs to.
    pub fn session(self) -> SessionId {
        self.session
    }
}

/// Where a value came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Brought in by a trusted component, e.g. `"store:email/123"`, `"user:input"`.
    Ingress {
        /// Origin description.
        origin: String,
    },
    /// Computed from other values in the same session.
    Derived {
        /// Operation name, e.g. `"reader:extract_date"`.
        op: String,
        /// The values it was computed from.
        inputs: Vec<Handle>,
    },
}

/// A resolved value.
#[derive(Clone, Copy, Debug)]
pub struct Resolved<'a> {
    /// The bytes.
    pub value: &'a [u8],
    /// Its label.
    pub label: Label,
    /// Where it came from.
    pub provenance: &'a Provenance,
}

/// Value table errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    /// The handle does not name a live value in the given session.
    UnknownHandle(Handle),
    /// The session has ended; its id cannot be reused.
    SessionEnded(SessionId),
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TableError::UnknownHandle(h) => write!(f, "handle {h:?} does not name a value in this session"),
            TableError::SessionEnded(s) => write!(f, "session {s:?} has ended"),
        }
    }
}

/// Capability to bring labeled data into the table. Held by trusted
/// components (store, user input path, certified transformers), never by agents.
///
/// It can only be obtained from [`ValueTable::new`]:
///
/// ```compile_fail
/// let forged = fewshot_labeld::Ingress { _private: () };
/// ```
#[derive(Debug)]
pub struct Ingress {
    _private: (),
}

struct Entry {
    value: Vec<u8>,
    label: Label,
    provenance: Provenance,
}

#[derive(Default)]
struct SessionValues {
    entries: Vec<Entry>,
    /// The session's own label: raised by every read.
    principal: Option<Label>,
}

/// Labeled values for every session.
#[derive(Default)]
pub struct ValueTable {
    sessions: BTreeMap<SessionId, SessionValues>,
    ended: BTreeSet<SessionId>,
}

impl ValueTable {
    /// Creates an empty table and the one [`Ingress`] capability for it.
    pub fn new() -> (Self, Ingress) {
        (ValueTable::default(), Ingress { _private: () })
    }

    /// Brings a value into `session` with a label chosen by a trusted component.
    pub fn intern(
        &mut self,
        _cap: &Ingress,
        session: SessionId,
        value: Vec<u8>,
        label: Label,
        origin: impl Into<String>,
    ) -> Result<Handle, TableError> {
        self.push(session, value, label, Provenance::Ingress { origin: origin.into() })
    }

    /// An agent session's view of the table: derive and read only.
    pub fn view(&mut self, session: SessionId) -> SessionView<'_> {
        SessionView { table: self, session }
    }

    /// Computes a new value from `inputs`. Its label is the join of their labels
    /// and the session's principal label; the caller cannot set it. Joining the
    /// principal label means bytes the session has read cannot come back out
    /// with a better label by being passed as a new value with fewer inputs.
    pub fn derive(
        &mut self,
        session: SessionId,
        op: impl Into<String>,
        inputs: &[Handle],
        value: Vec<u8>,
    ) -> Result<Handle, TableError> {
        let mut label = self.principal_label(session);
        for &h in inputs {
            label = label.join(self.entry(session, h)?.label);
        }
        let provenance = Provenance::Derived { op: op.into(), inputs: inputs.to_vec() };
        self.push(session, value, label, provenance)
    }

    /// Reads a value's bytes on behalf of the session. Raises the session's
    /// principal label to include the value's label.
    pub fn read(&mut self, session: SessionId, h: Handle) -> Result<&[u8], TableError> {
        let label = self.entry(session, h)?.label;
        let s = self.sessions.get_mut(&session).ok_or(TableError::UnknownHandle(h))?;
        s.principal = Some(s.principal.unwrap_or(Label::TOP).after_read(label));
        Ok(&s.entries[h.index as usize].value)
    }

    /// The session's principal label: the join of everything it has read.
    pub fn principal_label(&self, session: SessionId) -> Label {
        self.sessions.get(&session).and_then(|s| s.principal).unwrap_or(Label::TOP)
    }

    /// Looks up a value, its label and provenance. Trusted callers only (gate,
    /// host); does not count as a read by the session. Agents use [`SessionView`].
    pub fn resolve(&self, session: SessionId, h: Handle) -> Result<Resolved<'_>, TableError> {
        let e = self.entry(session, h)?;
        Ok(Resolved { value: &e.value, label: e.label, provenance: &e.provenance })
    }

    /// Drops every value of a session. Its handles stop resolving and the
    /// session id cannot be used again.
    pub fn end_session(&mut self, session: SessionId) {
        self.sessions.remove(&session);
        self.ended.insert(session);
    }

    fn entry(&self, session: SessionId, h: Handle) -> Result<&Entry, TableError> {
        if h.session != session {
            return Err(TableError::UnknownHandle(h));
        }
        self.sessions.get(&session).and_then(|s| s.entries.get(h.index as usize)).ok_or(TableError::UnknownHandle(h))
    }

    fn push(
        &mut self,
        session: SessionId,
        value: Vec<u8>,
        label: Label,
        provenance: Provenance,
    ) -> Result<Handle, TableError> {
        if self.ended.contains(&session) {
            return Err(TableError::SessionEnded(session));
        }
        let s = self.sessions.entry(session).or_default();
        let index = u32::try_from(s.entries.len()).expect("value table full");
        s.entries.push(Entry { value, label, provenance });
        Ok(Handle { session, index })
    }
}

/// What an agent session may do with the table: no ingress, no resolve.
/// Every read raises the session's principal label, and every derived value
/// carries it.
pub struct SessionView<'a> {
    table: &'a mut ValueTable,
    session: SessionId,
}

impl SessionView<'_> {
    /// The session this view acts for.
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// See [`ValueTable::derive`].
    pub fn derive(&mut self, op: impl Into<String>, inputs: &[Handle], value: Vec<u8>) -> Result<Handle, TableError> {
        self.table.derive(self.session, op, inputs, value)
    }

    /// See [`ValueTable::read`].
    pub fn read(&mut self, h: Handle) -> Result<&[u8], TableError> {
        self.table.read(self.session, h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const S1: SessionId = SessionId(1);
    const S2: SessionId = SessionId(2);

    fn web() -> Label {
        Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb)
    }

    fn user_secret() -> Label {
        Label::new(Secrecy::EMPTY.with(Tag::new(1).unwrap()), Integrity::User)
    }

    #[test]
    fn derive_joins_input_labels() {
        let (mut t, cap) = ValueTable::new();
        let a = t.intern(&cap, S1, b"page".to_vec(), web(), "web:example.com").unwrap();
        let b = t.intern(&cap, S1, b"note".to_vec(), user_secret(), "user:input").unwrap();
        let c = t.derive(S1, "concat", &[a, b], b"pagenote".to_vec()).unwrap();
        let r = t.resolve(S1, c).unwrap();
        assert_eq!(r.label, web().join(user_secret()));
        assert_eq!(r.provenance, &Provenance::Derived { op: "concat".into(), inputs: vec![a, b] });
    }

    #[test]
    fn handles_are_session_scoped() {
        let (mut t, cap) = ValueTable::new();
        let a = t.intern(&cap, S1, b"x".to_vec(), web(), "web").unwrap();
        t.intern(&cap, S2, b"y".to_vec(), web(), "web").unwrap();
        assert_eq!(t.resolve(S2, a).unwrap_err(), TableError::UnknownHandle(a));
        assert!(t.derive(S2, "copy", &[a], vec![]).is_err());
    }

    #[test]
    fn reads_raise_principal_label() {
        let (mut t, cap) = ValueTable::new();
        assert_eq!(t.principal_label(S1), Label::TOP);
        let a = t.intern(&cap, S1, b"x".to_vec(), web(), "web").unwrap();
        t.resolve(S1, a).unwrap();
        assert_eq!(t.principal_label(S1), Label::TOP, "resolve is not a read");
        t.read(S1, a).unwrap();
        assert_eq!(t.principal_label(S1).integrity, Integrity::UntrustedWeb);
    }

    #[test]
    fn derive_after_read_carries_principal_taint() {
        let (mut t, cap) = ValueTable::new();
        let page = t.intern(&cap, S1, b"attacker@evil.example".to_vec(), web(), "web").unwrap();
        let mut v = t.view(S1);
        let bytes = v.read(page).unwrap().to_vec();
        let laundered = v.derive("copy", &[], bytes).unwrap();
        assert_eq!(t.resolve(S1, laundered).unwrap().label.integrity, Integrity::UntrustedWeb);
    }

    #[test]
    fn derive_carries_secrecy_of_reads() {
        let (mut t, cap) = ValueTable::new();
        let note = t.intern(&cap, S1, b"diagnosis".to_vec(), user_secret(), "user:input").unwrap();
        let mut v = t.view(S1);
        v.read(note).unwrap();
        let out = v.derive("summary", &[], b"fine".to_vec()).unwrap();
        assert_eq!(t.resolve(S1, out).unwrap().label, user_secret());
    }

    #[test]
    fn derive_without_reads_is_clean() {
        let (mut t, cap) = ValueTable::new();
        let a = t.intern(&cap, S1, b"hi".to_vec(), Label::TOP, "user:input").unwrap();
        t.intern(&cap, S2, b"x".to_vec(), web(), "web").unwrap();
        t.view(S2).read(Handle { session: S2, index: 0 }).unwrap();
        let b = t.view(S1).derive("upper", &[a], b"HI".to_vec()).unwrap();
        assert_eq!(t.resolve(S1, b).unwrap().label, Label::TOP, "another session's reads do not taint S1");
    }

    #[test]
    fn ended_sessions_stop_resolving() {
        let (mut t, cap) = ValueTable::new();
        let a = t.intern(&cap, S1, b"x".to_vec(), web(), "web").unwrap();
        t.end_session(S1);
        assert!(t.resolve(S1, a).is_err());
        assert_eq!(t.intern(&cap, S1, b"y".to_vec(), web(), "web"), Err(TableError::SessionEnded(S1)));
    }
}
