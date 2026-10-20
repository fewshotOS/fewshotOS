//! The built-in actions: registry, path rules, undo, trash and notes.

use fewshot_gate::{AuditEntry, AuditKind, Effects, Registry};
use fewshot_labeld::{Integrity, SessionId};
use fewshot_runtime::actions::{HostEffects, builtin_registry};
use fewshot_runtime::{CallResult, Config, builtin_runtime};
use std::path::{Path, PathBuf};

struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
    config: Config,
}

/// A system_app root with a file, and a data dir beside it.
fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"old").unwrap();
    std::fs::create_dir_all(tmp.path().join("outside")).unwrap();
    std::fs::write(tmp.path().join("outside").join("secret.txt"), b"secret").unwrap();
    let config = Config::parse(&format!(
        r#"
[runtime]
data_dir = '{data}'

[[client]]
name = "claude-code"
actions = ["fs.list", "fs.read", "fs.write", "fs.restore", "fs.delete", "notes.append", "http.get"]

[[root]]
path = '{root}'
integrity = "system_app"
"#,
        data = data.display(),
        root = root.display()
    ))
    .unwrap();
    World { _tmp: tmp, root, data, config }
}

fn record() -> AuditEntry {
    AuditEntry {
        seq: 0,
        at_ms: 0,
        session: SessionId(1),
        action: None,
        digest: None,
        kind: AuditKind::EffectStarted,
        prev: [0; 32],
        hash: [0; 32],
    }
}

fn run(host: &mut HostEffects, registry: &Registry, name: &str, args: &[&[u8]]) -> Result<Vec<u8>, String> {
    let spec = registry.iter().find(|a| a.name == name).unwrap();
    host.run(spec, args, &record()).map_err(|e| e.0)
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

#[test]
fn the_registry_validates_and_depends_on_roots() {
    let w = world();
    let r = builtin_registry(&w.config);
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.iter().count(), 7);
    let none = Config::parse("").unwrap();
    let names: Vec<_> = builtin_registry(&none).iter().map(|a| a.name.clone()).collect();
    assert_eq!(names, ["notes.append", "http.get"]);
}

#[test]
fn fs_reads_share_the_join_of_root_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let cfg = Config::parse(&format!(
        "[tags]\nwork = 1\nhome = 2\n[[root]]\npath = '{}'\nintegrity = \"system_app\"\nsecrecy = [\"work\"]\n[[root]]\npath = '{}'\nintegrity = \"untrusted_web\"\nsecrecy = [\"home\"]\n",
        a.display(),
        b.display()
    ))
    .unwrap();
    let r = builtin_registry(&cfg);
    let out = r.iter().find(|x| x.name == "fs.read").unwrap().output.unwrap();
    assert_eq!(out.integrity, Integrity::UntrustedWeb);
    assert_eq!(out.secrecy.bits(), 0b110);
}

#[test]
fn reads_and_lists_inside_a_root() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    assert_eq!(run(&mut host, &r, "fs.read", &[s(&w.root.join("a.txt")).as_bytes()]).unwrap(), b"old");
    assert_eq!(run(&mut host, &r, "fs.list", &[s(&w.root).as_bytes()]).unwrap(), b"a.txt\nsub/");
}

#[test]
fn paths_outside_every_root_are_refused() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    let escape = format!(
        "{}{}..{}outside{}secret.txt",
        s(&w.root),
        std::path::MAIN_SEPARATOR,
        std::path::MAIN_SEPARATOR,
        std::path::MAIN_SEPARATOR
    );
    let sibling = s(&w.root.parent().unwrap().join("outside").join("secret.txt"));
    for bad in [escape.as_str(), sibling.as_str(), "a.txt", ""] {
        let err = run(&mut host, &r, "fs.read", &[bad.as_bytes()]).unwrap_err();
        assert!(err.contains("outside") || err.contains("absolute") || err.contains("empty"), "{bad}: {err}");
    }
    let new_outside = s(&w.root.parent().unwrap().join("outside").join("new.txt"));
    assert!(run(&mut host, &r, "fs.write", &[new_outside.as_bytes(), b"x"]).unwrap_err().contains("outside"));
}

#[test]
fn device_names_and_raw_prefixes_are_refused() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    for name in ["CON", "nul.txt", "COM1", "lpt9.log"] {
        let p = s(&w.root.join(name));
        let err = run(&mut host, &r, "fs.write", &[p.as_bytes(), b"x"]).unwrap_err();
        assert!(err.contains("device"), "{name}: {err}");
    }
    let raw = format!(r"\\?\{}", s(&w.root.join("a.txt")));
    assert!(run(&mut host, &r, "fs.read", &[raw.as_bytes()]).unwrap_err().contains("prefix"));
    #[cfg(windows)]
    {
        let ads = format!("{}:stream", s(&w.root.join("a.txt")));
        assert!(run(&mut host, &r, "fs.write", &[ads.as_bytes(), b"x"]).unwrap_err().contains("stream"));
    }
}

#[test]
fn symlinks_out_of_a_root_are_refused() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    let link = w.root.join("link.txt");
    let target = w.root.parent().unwrap().join("outside").join("secret.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    if let Err(e) = std::os::windows::fs::symlink_file(&target, &link) {
        eprintln!("skipped: cannot create symlinks here ({e})");
        return;
    }
    assert!(run(&mut host, &r, "fs.read", &[s(&link).as_bytes()]).unwrap_err().contains("outside"));
    assert!(run(&mut host, &r, "fs.write", &[s(&link).as_bytes(), b"x"]).unwrap_err().contains("outside"));
}

#[test]
fn restore_undoes_a_write() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    let old = s(&w.root.join("a.txt"));
    run(&mut host, &r, "fs.write", &[old.as_bytes(), b"new"]).unwrap();
    assert_eq!(std::fs::read(&old).unwrap(), b"new");
    run(&mut host, &r, "fs.restore", &[old.as_bytes(), b"new"]).unwrap();
    assert_eq!(std::fs::read(&old).unwrap(), b"old");
    assert!(run(&mut host, &r, "fs.restore", &[old.as_bytes(), b"new"]).unwrap_err().contains("nothing to restore"));

    let fresh = s(&w.root.join("sub").join("fresh.txt"));
    run(&mut host, &r, "fs.write", &[fresh.as_bytes(), b"hi"]).unwrap();
    run(&mut host, &r, "fs.restore", &[fresh.as_bytes(), b"hi"]).unwrap();
    assert!(!Path::new(&fresh).exists(), "a file the write created is removed");
}

#[test]
fn delete_moves_to_the_trash() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    run(&mut host, &r, "fs.delete", &[s(&w.root.join("a.txt")).as_bytes()]).unwrap();
    assert!(!w.root.join("a.txt").exists());
    let trashed: Vec<_> = std::fs::read_dir(w.data.join("trash")).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(trashed.len(), 1);
    assert!(trashed[0].to_string_lossy().ends_with("-a.txt"));
}

#[test]
fn notes_append_lines() {
    let w = world();
    let (mut host, r) = (HostEffects::new(&w.config).unwrap(), builtin_registry(&w.config));
    run(&mut host, &r, "notes.append", &[b"one"]).unwrap();
    run(&mut host, &r, "notes.append", &[b"two"]).unwrap();
    assert_eq!(std::fs::read_to_string(w.data.join("notes.md")).unwrap(), "one\ntwo\n");
}

#[test]
fn through_the_runtime_reads_are_labeled_and_writes_need_approval() {
    let w = world();
    let key = fewshot_gate::Approver::from_secret([7; 32]).verifying_key();
    let mut rt = builtin_runtime(w.config, key).unwrap();
    let session = rt.open_session("claude-code").unwrap();
    let path = rt.literal(session, s(&w.root.join("a.txt")).into_bytes()).unwrap();
    let CallResult::Done { output: Some(out) } = rt.call(session, "fs.read", vec![path], None).unwrap() else {
        panic!("expected an output")
    };
    // A system_app root, read with a third_party literal path.
    assert_eq!(rt.label_of(session, out).unwrap().integrity, Integrity::ThirdParty);
    let content = rt.literal(session, b"new".to_vec()).unwrap();
    assert!(matches!(rt.call(session, "fs.write", vec![path, content], None).unwrap(), CallResult::NeedsApproval(_)));
}
