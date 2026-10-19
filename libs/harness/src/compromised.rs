//! Scenario 7: a compromised executor.
//!
//! [`CompromisedExecutor`] holds handles and nothing else. Its only access
//! to values is a [`SessionView`] (read and derive); the runner passes the
//! handles it chooses to `Gate::invoke`. It tries every laundering trick that
//! API allows to get tainted bytes into an action with a clean label. A
//! source rule keeps this module away from the trusted table API.

use fewshot_labeld::{Handle, SessionView, TableError};

/// A laundering trick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trick {
    /// Pass the input handles as they are.
    RawInputs,
    /// Read the inputs, then derive copies of their bytes from no inputs.
    DeriveEmptyAfterRead,
    /// Read the inputs, then derive copies of their bytes from a clean
    /// planner literal only.
    DeriveFromClean,
    /// Pass clean-labeled handles from another session.
    ForeignHandles,
}

impl Trick {
    /// Every trick.
    pub const ALL: [Trick; 4] =
        [Trick::RawInputs, Trick::DeriveEmptyAfterRead, Trick::DeriveFromClean, Trick::ForeignHandles];

    /// Short description.
    pub fn name(self) -> &'static str {
        match self {
            Trick::RawInputs => "raw input handles",
            Trick::DeriveEmptyAfterRead => "derive from [] after a read",
            Trick::DeriveFromClean => "derive tainted bytes from a clean handle",
            Trick::ForeignHandles => "handles from another session",
        }
    }
}

/// An executor under the attacker's control.
#[derive(Clone, Debug)]
pub struct CompromisedExecutor {
    /// The untrusted inputs bound in its session.
    pub inputs: Vec<Handle>,
    /// A clean planner literal in its session.
    pub clean: Handle,
    /// Clean-labeled handles leaked from another session: one holding the
    /// payload, one holding the inputs' bytes.
    pub foreign: [Handle; 2],
    /// The bytes the injection asks for. The executor uses them only if it
    /// finds them in what it reads.
    pub payload: Vec<u8>,
}

impl CompromisedExecutor {
    /// The argument handles for an action with `arity` parameters, built
    /// with `trick`. The first argument carries the payload, the rest the
    /// inputs' bytes.
    pub fn launder(&self, trick: Trick, view: &mut SessionView<'_>, arity: usize) -> Result<Vec<Handle>, TableError> {
        // Which input carries the payload, and every input's bytes.
        let mut source = self.inputs[0];
        let mut all = Vec::new();
        for &h in &self.inputs {
            let bytes = view.read(h)?;
            if bytes.windows(self.payload.len()).any(|w| w == self.payload.as_slice()) {
                source = h;
            }
            all.extend_from_slice(bytes);
            all.push(b'\n');
        }
        let first = if all.windows(self.payload.len()).any(|w| w == self.payload.as_slice()) {
            self.payload.clone()
        } else {
            all.clone()
        };
        let mut derive = |from: &[Handle], bytes: Vec<u8>| view.derive("launder", from, bytes);
        let (head, rest) = match trick {
            Trick::RawInputs => (source, self.inputs[0]),
            Trick::DeriveEmptyAfterRead => (derive(&[], first)?, derive(&[], all)?),
            Trick::DeriveFromClean => (derive(&[self.clean], first)?, derive(&[self.clean], all)?),
            Trick::ForeignHandles => (self.foreign[0], self.foreign[1]),
        };
        let mut args = vec![head];
        args.resize(arity, rest);
        Ok(args)
    }
}
