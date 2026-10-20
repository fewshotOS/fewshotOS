//! `notes.append`: append a line to `data_dir/notes.md`, the one plain-notes
//! file the runtime keeps.

use crate::actions::HostEffects;
use fewshot_gate::EffectError;
use std::io::Write as _;

/// The most one appended note may hold, in bytes.
const MAX_TEXT: usize = 64 * 1024;

/// `notes.append text`: appends `text` plus a newline to `notes.md`.
pub(crate) fn append(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let text = std::str::from_utf8(args.first().copied().expect("arity is checked by the gate"))
        .map_err(|_| EffectError("text must be valid UTF-8".into()))?;
    if text.len() > MAX_TEXT {
        return Err(EffectError("note text exceeds 64 KiB".into()));
    }
    let notes = host.data_dir().join("notes.md");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&notes)
        .map_err(|e| EffectError(format!("cannot open the notes file: {e}")))?;
    file.write_all(text.as_bytes()).map_err(|e| EffectError(format!("cannot write the notes file: {e}")))?;
    file.write_all(b"\n").map_err(|e| EffectError(format!("cannot write the notes file: {e}")))?;
    Ok(Vec::new())
}
