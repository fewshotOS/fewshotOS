//! Adversarial stubs, standing in for the agent-side (untrusted) components.
//!
//! The harness does not need a realistic model to test the security property:
//! it assumes the agent side is fully hijacked and asks whether anything bad
//! still happens. The stubs produce exactly the worst outputs a hijacked
//! component can produce.

use fewshot_executor::{Reader, ReaderError};
use fewshot_plan::Schema;

/// A reader that ignores its input and schema and always returns the
/// attacker's choice. For `Text` schemas that is `payload`; for `Choice`
/// schemas it is `choice`, even if that option is not in the schema's list —
/// a hijacked reader may return any bytes.
#[derive(Clone, Debug)]
pub struct AdversarialReader {
    /// The attacker's bytes for `Text` schemas.
    payload: Vec<u8>,
    /// The most harmful option for `Choice` schemas.
    choice: String,
}

impl AdversarialReader {
    /// A hijacked reader answering `Text` extracts with `payload` and `Choice`
    /// extracts with `choice`.
    pub fn new(payload: impl Into<Vec<u8>>, choice: impl Into<String>) -> Self {
        AdversarialReader { payload: payload.into(), choice: choice.into() }
    }
}

impl Reader for AdversarialReader {
    fn extract(&mut self, schema: &Schema, _input: &[u8]) -> Result<Vec<u8>, ReaderError> {
        Ok(match schema {
            Schema::Text { .. } => self.payload.clone(),
            Schema::Choice { .. } => self.choice.clone().into_bytes(),
        })
    }
}
