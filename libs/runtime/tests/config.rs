//! Config parsing and every rejection.

use fewshot_labeld::{Integrity, Label, Secrecy, Tag};
use fewshot_runtime::{Config, ConfigError};

fn root_toml(path: &std::path::Path, extra: &str) -> String {
    format!("[tags]\npersonal = 1\n\n[[root]]\npath = '{}'\n{extra}\n", path.display())
}

#[test]
fn a_full_example_parses() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        r#"
[runtime]
data_dir = '{data}'
approval_timeout_s = 120
telemetry = true

[ollama]
base_url = "http://localhost:11434"

[[client]]
name = "claude-code"
literal_integrity = "untrusted_web"
actions = ["fs.read"]

[[client]]
name = "desktop"
actions = []

[[root]]
path = '{root}'
integrity = "system_app"
secrecy = ["personal"]

[tags]
personal = 1
"#,
        data = dir.path().join("data").display(),
        root = dir.path().display()
    );
    let cfg = Config::parse(&text).unwrap();
    assert_eq!(cfg.runtime.approval_timeout_s, 120);
    assert!(cfg.runtime.telemetry);
    assert_eq!(cfg.data_dir(), dir.path().join("data"));
    assert_eq!(cfg.client[0].literal_label(), Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb));
    assert_eq!(cfg.client[1].literal_label().integrity, Integrity::ThirdParty, "default literal integrity");
    let personal = Secrecy::EMPTY.with(Tag::new(1).unwrap());
    assert_eq!(cfg.root[0].label(&cfg.tags), Label::new(personal, Integrity::SystemApp));
    assert_eq!(cfg.root[0].path, std::fs::canonicalize(dir.path()).unwrap());
}

#[test]
fn defaults_apply_to_an_empty_file() {
    let cfg = Config::parse("").unwrap();
    assert_eq!(cfg.runtime.approval_timeout_s, 300);
    assert!(!cfg.runtime.telemetry);
    assert!(cfg.client.is_empty());
}

fn client_err(integrity: &str) -> ConfigError {
    Config::parse(&format!("[[client]]\nname = \"c\"\nliteral_integrity = \"{integrity}\"\n")).unwrap_err()
}

#[test]
fn user_literal_integrity_is_rejected() {
    assert_eq!(client_err("user"), ConfigError::IntegrityNotAllowed { name: "user".into() });
}

#[test]
fn bounded_literal_integrity_is_rejected() {
    assert_eq!(client_err("bounded"), ConfigError::IntegrityNotAllowed { name: "bounded".into() });
}

#[test]
fn unknown_integrity_is_rejected() {
    assert_eq!(client_err("trusted"), ConfigError::UnknownIntegrity { name: "trusted".into() });
}

#[test]
fn user_root_integrity_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::parse(&root_toml(dir.path(), "integrity = \"user\"")).unwrap_err();
    assert_eq!(err, ConfigError::IntegrityNotAllowed { name: "user".into() });
}

#[test]
fn duplicate_client_is_rejected() {
    let err = Config::parse("[[client]]\nname = \"c\"\n[[client]]\nname = \"c\"\n").unwrap_err();
    assert_eq!(err, ConfigError::DuplicateClient { name: "c".into() });
}

#[test]
fn tag_index_out_of_range_is_rejected() {
    let err = Config::parse("[tags]\nhuge = 64\n").unwrap_err();
    assert_eq!(err, ConfigError::TagIndexOutOfRange { name: "huge".into(), index: 64 });
}

#[test]
fn duplicate_tag_index_is_rejected() {
    let err = Config::parse("[tags]\na = 3\nb = 3\n").unwrap_err();
    assert_eq!(err, ConfigError::DuplicateTagIndex { index: 3, first: "a".into(), second: "b".into() });
}

#[test]
fn unknown_secrecy_tag_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::parse(&root_toml(dir.path(), "secrecy = [\"medical\"]")).unwrap_err();
    assert!(matches!(err, ConfigError::UnknownSecrecyTag { tag, .. } if tag == "medical"));
}

#[test]
fn missing_root_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let err = Config::parse(&root_toml(&missing, "")).unwrap_err();
    assert_eq!(err, ConfigError::BadRootPath { path: missing });
}

#[test]
fn unknown_keys_are_rejected() {
    assert!(matches!(Config::parse("[runtime]\nverbose = true\n"), Err(ConfigError::Parse(_))));
    assert!(matches!(Config::parse("[network]\n"), Err(ConfigError::Parse(_))));
    assert!(matches!(Config::parse("[[client]]\nname = \"c\"\ntrust = \"all\"\n"), Err(ConfigError::Parse(_))));
}
