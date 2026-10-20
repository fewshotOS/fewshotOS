//! The built-in actions (T3): the registry the gate checks and the one
//! [`HostEffects`] that runs them. The two stay in lockstep through the name
//! constants below; anything else a host could run is refused as unknown.
//!
//! All the `fs.*` reads share one output label: the join of every root's
//! contents label. An [`ActionSpec`] carries exactly one output label, so put
//! roots of different trust in separate runtimes until per-root actions exist.

use crate::config::Config;
use fewshot_gate::{ActionId, ActionSpec, AuditEntry, Effect, EffectError, Effects, Param, Registry};
use fewshot_labeld::{Integrity, Label, Secrecy};
use std::path::PathBuf;

mod fs;
mod http;
mod notes;

/// The `fs.list` action: list a directory inside a root.
pub const FS_LIST: ActionId = ActionId(1);
/// The `fs.read` action: read a file inside a root.
pub const FS_READ: ActionId = ActionId(2);
/// The `fs.write` action: write a file, backing up the old content first.
pub const FS_WRITE: ActionId = ActionId(3);
/// The `fs.restore` action: compensation for `fs.write`.
pub const FS_RESTORE: ActionId = ActionId(4);
/// The `fs.delete` action: move a file from a root into the trash.
pub const FS_DELETE: ActionId = ActionId(5);
/// The `notes.append` action: append a line to the notes file.
pub const NOTES_APPEND: ActionId = ActionId(6);
/// The `http.get` action: fetch an `https` URL.
pub const HTTP_GET: ActionId = ActionId(7);

/// Name of the `fs.list` action.
pub const FS_LIST_NAME: &str = "fs.list";
/// Name of the `fs.read` action.
pub const FS_READ_NAME: &str = "fs.read";
/// Name of the `fs.write` action.
pub const FS_WRITE_NAME: &str = "fs.write";
/// Name of the `fs.restore` action.
pub const FS_RESTORE_NAME: &str = "fs.restore";
/// Name of the `fs.delete` action.
pub const FS_DELETE_NAME: &str = "fs.delete";
/// Name of the `notes.append` action.
pub const NOTES_APPEND_NAME: &str = "notes.append";
/// Name of the `http.get` action.
pub const HTTP_GET_NAME: &str = "http.get";

/// One spec, with the shared defaults: no egress tags allowed, no draft.
fn spec(
    id: ActionId,
    name: &str,
    effect: Effect,
    floor: Integrity,
    params: &[&str],
    output: Option<Label>,
    compensation: Option<ActionId>,
) -> ActionSpec {
    ActionSpec {
        id,
        name: name.into(),
        effect,
        integrity_floor: floor,
        egress_clearance: Secrecy::EMPTY,
        params: params.iter().copied().map(Param::open).collect(),
        draft_for: None,
        compensation,
        output,
    }
}

/// The registry of built-in actions for `config`: the `fs.*` actions when it
/// has roots, and always `notes.append` and `http.get`.
pub fn builtin_registry(config: &Config) -> Registry {
    let mut registry = Registry::new();
    if !config.root.is_empty() {
        // One label covers every root; see the module docs.
        let roots_label = Label::join_all(config.root.iter().map(|r| r.label(&config.tags)));
        registry
            .register(spec(
                FS_LIST,
                FS_LIST_NAME,
                Effect::Read,
                Integrity::UntrustedWeb,
                &["dir"],
                Some(roots_label),
                None,
            ))
            .expect("builtin ids are unique");
        registry
            .register(spec(
                FS_READ,
                FS_READ_NAME,
                Effect::Read,
                Integrity::UntrustedWeb,
                &["path"],
                Some(roots_label),
                None,
            ))
            .expect("builtin ids are unique");
        registry
            .register(spec(
                FS_WRITE,
                FS_WRITE_NAME,
                Effect::LocalReversible,
                Integrity::SystemApp,
                &["path", "content"],
                None,
                Some(FS_RESTORE),
            ))
            .expect("builtin ids are unique");
        registry
            .register(spec(
                FS_RESTORE,
                FS_RESTORE_NAME,
                Effect::LocalReversible,
                Integrity::SystemApp,
                &["path", "content"],
                None,
                None,
            ))
            .expect("builtin ids are unique");
        registry
            .register(spec(
                FS_DELETE,
                FS_DELETE_NAME,
                Effect::LocalIrreversible,
                Integrity::SystemApp,
                &["path"],
                None,
                None,
            ))
            .expect("builtin ids are unique");
    }
    registry
        .register(spec(
            NOTES_APPEND,
            NOTES_APPEND_NAME,
            Effect::LocalReversible,
            Integrity::ThirdParty,
            &["text"],
            None,
            None,
        ))
        .expect("builtin ids are unique");
    registry
        .register(spec(
            HTTP_GET,
            HTTP_GET_NAME,
            Effect::Fetch,
            Integrity::UntrustedWeb,
            &["url"],
            Some(Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb)),
            None,
        ))
        .expect("builtin ids are unique");
    registry
}

/// The host effects: runs the built-in actions against this machine's files
/// (inside the roots) and the network. It is trusted code, not model code.
pub struct HostEffects {
    /// Canonical paths of the configured roots.
    roots: Vec<PathBuf>,
    /// Where undo copies, the trash and the notes file live.
    data_dir: PathBuf,
    /// The `http.get` agent.
    http: http::Http,
}

impl HostEffects {
    /// Creates the effects host, making sure `data_dir/undo` and
    /// `data_dir/trash` exist.
    pub fn new(config: &Config) -> Result<Self, std::io::Error> {
        let data_dir = config.data_dir();
        std::fs::create_dir_all(data_dir.join("undo"))?;
        std::fs::create_dir_all(data_dir.join("trash"))?;
        Ok(HostEffects {
            roots: config.root.iter().map(|r| r.path.clone()).collect(),
            data_dir,
            http: http::Http::new(),
        })
    }

    /// The canonical roots, or `[]`.
    pub(crate) fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The data directory.
    pub(crate) fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// The `http.get` agent.
    pub(crate) fn http(&self) -> &http::Http {
        &self.http
    }
}

impl Effects for HostEffects {
    fn run(&mut self, action: &ActionSpec, args: &[&[u8]], _record: &AuditEntry) -> Result<Vec<u8>, EffectError> {
        match action.name.as_str() {
            FS_LIST_NAME => fs::list(self, args),
            FS_READ_NAME => fs::read(self, args),
            FS_WRITE_NAME => fs::write(self, args),
            FS_RESTORE_NAME => fs::restore(self, args),
            FS_DELETE_NAME => fs::delete(self, args),
            NOTES_APPEND_NAME => notes::append(self, args),
            HTTP_GET_NAME => http::get(self, args),
            name => Err(EffectError(format!("unknown action {name}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_action_is_refused() {
        let data = tempfile::tempdir().unwrap();
        let config =
            Config::parse(&format!("[runtime]\ndata_dir = '{}'\n\n[[client]]\nname = \"c\"\n", data.path().display()))
                .unwrap();
        let mut host = HostEffects::new(&config).unwrap();
        let spec = ActionSpec {
            id: ActionId(99),
            name: "fs.nuke".into(),
            effect: Effect::Read,
            integrity_floor: Integrity::UntrustedWeb,
            egress_clearance: Secrecy::EMPTY,
            params: Vec::new(),
            draft_for: None,
            compensation: None,
            output: None,
        };
        let record = fewshot_gate::AuditEntry {
            seq: 0,
            at_ms: 0,
            session: fewshot_labeld::SessionId(1),
            action: None,
            digest: None,
            kind: fewshot_gate::AuditKind::EffectStarted,
            prev: [0; 32],
            hash: [0; 32],
        };
        let err = host.run(&spec, &[], &record).unwrap_err();
        assert!(err.0.contains("unknown action"));
    }
}
