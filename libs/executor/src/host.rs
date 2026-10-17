//! Trusted host helpers. This is the only module in the crate that brings
//! values into the table or looks at them without a session read; it needs
//! the [`Ingress`] capability, which the executor never holds.

use crate::{Env, Reader, ReaderError};
use alloc::collections::BTreeSet;
use alloc::string::String;
use core::fmt;
use fewshot_labeld::{Handle, Ingress, Integrity, Label, SessionId, TableError, ValueTable};
use fewshot_plan::{Plan, Schema, Step};

/// Runs `Read` steps for the executor, so it never sees the [`Ingress`].
pub trait ReaderHost {
    /// Extracts a value matching `schema` from `input` and returns its handle.
    fn read(
        &mut self,
        table: &mut ValueTable,
        session: SessionId,
        input: Handle,
        schema: &Schema,
    ) -> Result<Handle, ReadError>;
}

/// Why a `Read` step failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The reader failed.
    Reader(ReaderError),
    /// A certified reader's output is not one of the options.
    NotAnOption,
    /// The value table rejected an operation.
    Table(TableError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Reader(e) => write!(f, "reader failed: {}", e.0),
            ReadError::NotAnOption => write!(f, "reader output is not one of the options"),
            ReadError::Table(e) => write!(f, "{e}"),
        }
    }
}

/// The standard [`ReaderHost`]: `Text` schemas go to [`quarantined_extract`],
/// `Choice` schemas to [`certified_extract`].
pub struct Quarantine<'i, R> {
    ingress: &'i Ingress,
    reader: R,
}

impl<'i, R: Reader> Quarantine<'i, R> {
    /// Wraps `reader`. `ingress` is used only to intern certified outputs.
    pub fn new(ingress: &'i Ingress, reader: R) -> Self {
        Quarantine { ingress, reader }
    }

    /// The wrapped reader.
    pub fn reader(&mut self) -> &mut R {
        &mut self.reader
    }
}

impl<R: Reader> ReaderHost for Quarantine<'_, R> {
    fn read(
        &mut self,
        table: &mut ValueTable,
        session: SessionId,
        input: Handle,
        schema: &Schema,
    ) -> Result<Handle, ReadError> {
        match schema {
            Schema::Text { max_len } => quarantined_extract(table, session, input, *max_len, &mut self.reader),
            Schema::Choice { options } => {
                certified_extract(table, self.ingress, session, input, options, &mut self.reader)
            }
        }
    }
}

/// Interns every distinct `Let` text in `plan` with the planner's input
/// `label` (normally `User`: the planner saw only the user's request) and
/// returns an [`Env`] holding them. The host then binds its inputs.
pub fn intern_literals(
    table: &mut ValueTable,
    ingress: &Ingress,
    session: SessionId,
    plan: &Plan,
    label: Label,
) -> Result<Env, TableError> {
    fn collect<'a>(steps: &'a [Step], out: &mut BTreeSet<&'a str>) {
        for s in steps {
            match s {
                Step::Let { text, .. } => {
                    out.insert(text);
                }
                Step::ForEach { body, .. } => collect(body, out),
                Step::If { then, otherwise, .. } => {
                    collect(then, out);
                    collect(otherwise, out);
                }
                Step::Call { .. } | Step::Read { .. } | Step::Checkpoint => {}
            }
        }
    }
    let mut texts = BTreeSet::new();
    collect(&plan.steps, &mut texts);
    let mut env = Env::new();
    for text in texts {
        let h = table.intern(ingress, session, text.as_bytes().into(), label, "plan:literal")?;
        env.literals.insert(String::from(text), h);
    }
    Ok(env)
}

/// Asks `reader` to pick one of `options` from `input`. Accepts the output
/// only if it is byte-equal to an option, and interns it with the input's
/// secrecy and integrity raised to at least `Bounded`. This is the only place
/// integrity can rise, and only to `Bounded`. On any error nothing is interned.
pub fn certified_extract(
    table: &mut ValueTable,
    ingress: &Ingress,
    session: SessionId,
    input: Handle,
    options: &[String],
    reader: &mut (impl Reader + ?Sized),
) -> Result<Handle, ReadError> {
    let r = table.resolve(session, input).map_err(ReadError::Table)?;
    let label = Label::new(r.label.secrecy, r.label.integrity.max(Integrity::Bounded));
    let schema = Schema::Choice { options: options.into() };
    let out = reader.extract(&schema, r.value).map_err(ReadError::Reader)?;
    if !options.iter().any(|o| o.as_bytes() == out.as_slice()) {
        return Err(ReadError::NotAnOption);
    }
    table.intern(ingress, session, out, label, "certified:choice").map_err(ReadError::Table)
}

/// Asks `reader` for free text from `input`, truncated to `max_len` bytes. The
/// result is derived from `input`, so it keeps the input's label (and the
/// session's principal label).
pub fn quarantined_extract(
    table: &mut ValueTable,
    session: SessionId,
    input: Handle,
    max_len: u32,
    reader: &mut (impl Reader + ?Sized),
) -> Result<Handle, ReadError> {
    let r = table.resolve(session, input).map_err(ReadError::Table)?;
    let mut out = reader.extract(&Schema::Text { max_len }, r.value).map_err(ReadError::Reader)?;
    out.truncate(max_len as usize);
    table.derive(session, "reader:text", &[input], out).map_err(ReadError::Table)
}
