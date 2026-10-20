//! The `fewshot.toml` config: clients, their literal integrity, allowed
//! actions, file system roots and secrecy tag names (T2).
//!
//! Clients are MCP connections: one LLM whose context may hold content Fewshot
//! never saw. A client's *literal integrity* is the best integrity we can
//! honestly assign to arguments the model passes in; `User` and `Bounded` are
//! rejected because a model is neither the user's trusted input path nor a
//! certified transformer.
//!
//! Every struct rejects unknown keys, and validation runs on every
//! [`parse`](Config::parse) / [`load`](Config::load), so a field can reach the
//! runtime only if it is a name this file would accept.

use fewshot_labeld::{Integrity, Label, Secrecy, Tag};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// Placeholder for the parsed integrity fields until validation sets them.
fn default_integrity() -> Integrity {
    Integrity::ThirdParty
}

/// The default integrity name for clients and roots.
fn default_literal_integrity() -> String {
    "third_party".into()
}

/// The default approval timeout, in seconds.
fn default_timeout() -> u64 {
    300
}

/// The parsed config.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Runtime-wide settings.
    #[serde(default)]
    pub runtime: RuntimeSection,
    /// Local Ollama settings, if any. Stored; nothing reads it yet.
    #[serde(default)]
    pub ollama: Option<OllamaSection>,
    /// MCP clients.
    #[serde(default)]
    pub client: Vec<ClientConfig>,
    /// Directories the file actions may touch.
    #[serde(default)]
    pub root: Vec<RootConfig>,
    /// Secrecy tag names to tag indices.
    #[serde(default)]
    pub tags: BTreeMap<String, u8>,
}

impl Config {
    /// Where the config file lives: `$FEWSHOT_CONFIG`, else
    /// `config_dir()/fewshot/fewshot.toml`.
    pub fn default_path() -> PathBuf {
        match std::env::var_os("FEWSHOT_CONFIG") {
            Some(p) => PathBuf::from(p),
            None => dirs::config_dir()
                .map(|c| c.join("fewshot").join("fewshot.toml"))
                .unwrap_or_else(|| PathBuf::from("fewshot.toml")),
        }
    }

    /// Reads and parses the file at `path`, then validates.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Parse(e.to_string()))?;
        Self::parse(&text)
    }

    /// Parses `text`, then validates. Does not touch the file system.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        validate(&mut cfg)?;
        Ok(cfg)
    }

    /// Where runtime data (audit files, notes, undo copies) lives:
    /// `runtime.data_dir`, else `data_dir()/fewshot`.
    pub fn data_dir(&self) -> PathBuf {
        if let Some(d) = &self.runtime.data_dir {
            return d.clone();
        }
        dirs::data_dir().map(|d| d.join("fewshot")).unwrap_or_else(|| PathBuf::from("fewshot"))
    }
}

/// The `[runtime]` section.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    /// Where runtime data lives. Default: `data_dir()/fewshot`.
    pub data_dir: Option<PathBuf>,
    /// How long to wait for the approval app, in seconds.
    #[serde(default = "default_timeout")]
    pub approval_timeout_s: u64,
    /// Whether to record the local approval-rate telemetry. Never sends data.
    #[serde(default)]
    pub telemetry: bool,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        RuntimeSection { data_dir: None, approval_timeout_s: default_timeout(), telemetry: false }
    }
}

/// The `[ollama]` section. Stored as-is; nothing reads it yet.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OllamaSection {
    /// Base URL of the local Ollama server.
    pub base_url: Option<String>,
    /// Model to run the planner under.
    pub planner_model: Option<String>,
    /// Model to run the quarantined reader under.
    pub reader_model: Option<String>,
}

/// A `[[client]]` entry: an MCP connection and its label policy.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Client name, e.g. `"claude-code"`.
    pub name: String,
    /// The integrity literal arguments from this client are interned at.
    /// One of `untrusted_web`, `untrusted_legacy`, `third_party`, `system_app`.
    #[serde(default = "default_literal_integrity")]
    pub literal_integrity: String,
    /// Action names this client may call.
    #[serde(default)]
    pub actions: Vec<String>,
    /// `literal_integrity` parsed; set by validation.
    #[serde(skip, default = "default_integrity")]
    literal: Integrity,
}

impl ClientConfig {
    /// The label a literal argument from this client is interned at
    /// (empty secrecy, the client's literal integrity).
    pub fn literal_label(&self) -> Label {
        Label::new(Secrecy::EMPTY, self.literal)
    }
}

/// A `[[root]]` entry: a directory the file actions may touch, and the label
/// of contents read from it.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    /// The directory, canonicalized at load.
    pub path: PathBuf,
    /// The integrity of file contents read from this root.
    /// One of `untrusted_web`, `untrusted_legacy`, `third_party`, `system_app`.
    #[serde(default = "default_literal_integrity")]
    pub integrity: String,
    /// Secrecy tag names (from `[tags]`) the contents here carry.
    #[serde(default)]
    pub secrecy: Vec<String>,
    /// `integrity` parsed; set by validation.
    #[serde(skip, default = "default_integrity")]
    parsed: Integrity,
}

impl RootConfig {
    /// The label of contents read from this root: the named secrecy tags and
    /// the root's integrity.
    pub fn label(&self, tags: &BTreeMap<String, u8>) -> Label {
        let mut secrecy = Secrecy::EMPTY;
        for name in &self.secrecy {
            // Validation guarantees the name is in `tags` and its index is
            // below `Tag::COUNT`, so both lookups succeed.
            let index = tags.get(name).expect("validated");
            secrecy = secrecy.with(Tag::new(*index).expect("validated"));
        }
        Label::new(secrecy, self.parsed)
    }
}

/// Why the config rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The file could not be read, or the TOML did not parse / was rejected
    /// by serde (an unknown key, a bad type, …).
    Parse(String),
    /// An integrity name is not one the config may assign to literals or roots.
    IntegrityNotAllowed {
        /// The name as written.
        name: String,
    },
    /// An integrity name is not a known integrity level.
    UnknownIntegrity {
        /// The name as written.
        name: String,
    },
    /// Two clients share a name.
    DuplicateClient {
        /// The duplicated name.
        name: String,
    },
    /// A tag index is not below `Tag::COUNT`.
    TagIndexOutOfRange {
        /// The tag name.
        name: String,
        /// The offending index.
        index: u8,
    },
    /// Two tags claim the same index.
    DuplicateTagIndex {
        /// The duplicated index.
        index: u8,
        /// First tag claiming it.
        first: String,
        /// Second tag claiming it.
        second: String,
    },
    /// A root names a secrecy tag that is not defined in `[tags]`.
    UnknownSecrecyTag {
        /// The root naming it.
        root: PathBuf,
        /// The undefined tag name.
        tag: String,
    },
    /// A root path does not exist or cannot be canonicalized.
    BadRootPath {
        /// The offending path.
        path: PathBuf,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(m) => write!(f, "config: {m}"),
            ConfigError::IntegrityNotAllowed { name } => write!(
                f,
                "config: integrity {name:?} is not allowed for literals or roots (use untrusted_web, untrusted_legacy, third_party or system_app)"
            ),
            ConfigError::UnknownIntegrity { name } => {
                write!(f, "config: unknown integrity {name:?}")
            }
            ConfigError::DuplicateClient { name } => write!(f, "config: client {name:?} is defined twice"),
            ConfigError::TagIndexOutOfRange { name, index } => {
                write!(f, "config: tag {name:?} has index {index}, which is not below {}", Tag::COUNT)
            }
            ConfigError::DuplicateTagIndex { index, first, second } => {
                write!(f, "config: tags {first:?} and {second:?} both claim index {index}")
            }
            ConfigError::UnknownSecrecyTag { root, tag } => {
                write!(f, "config: {} names secrecy tag {tag:?}, which is not in [tags]", root.display())
            }
            ConfigError::BadRootPath { path } => {
                write!(f, "config: root {} does not exist or cannot be canonicalized", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Maps an integrity name to a level, rejecting names the config may not use.
fn map_integrity(name: &str) -> Result<Integrity, ConfigError> {
    match name {
        "untrusted_web" => Ok(Integrity::UntrustedWeb),
        "untrusted_legacy" => Ok(Integrity::UntrustedLegacy),
        "third_party" => Ok(Integrity::ThirdParty),
        "system_app" => Ok(Integrity::SystemApp),
        "user" | "bounded" => Err(ConfigError::IntegrityNotAllowed { name: name.into() }),
        other => Err(ConfigError::UnknownIntegrity { name: other.into() }),
    }
}

/// Checks the parsed config and fills in the parsed helpers.
fn validate(cfg: &mut Config) -> Result<(), ConfigError> {
    // Clients: unique names; literal integrity names must be allowed.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for c in &mut cfg.client {
        if !seen.insert(c.name.clone()) {
            return Err(ConfigError::DuplicateClient { name: c.name.clone() });
        }
        c.literal = map_integrity(&c.literal_integrity)?;
    }

    // Tags: indices must be in range and unique.
    let mut first_by_index: BTreeMap<u8, String> = BTreeMap::new();
    for (name, index) in &cfg.tags {
        if Tag::new(*index).is_none() {
            return Err(ConfigError::TagIndexOutOfRange { name: name.clone(), index: *index });
        }
        if let Some(first) = first_by_index.get(index) {
            return Err(ConfigError::DuplicateTagIndex { index: *index, first: first.clone(), second: name.clone() });
        }
        first_by_index.insert(*index, name.clone());
    }

    // Roots: integrity names allowed, secrecy names defined, path canonical.
    for r in &mut cfg.root {
        r.parsed = map_integrity(&r.integrity)?;
        for tag in &r.secrecy {
            if !cfg.tags.contains_key(tag) {
                return Err(ConfigError::UnknownSecrecyTag { root: r.path.clone(), tag: tag.clone() });
            }
        }
        let canonical =
            std::fs::canonicalize(&r.path).map_err(|_| ConfigError::BadRootPath { path: r.path.clone() })?;
        r.path = canonical;
    }

    Ok(())
}
