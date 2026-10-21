//! The timeline over a real run's audit file: it reads the JSONL back,
//! renders it with a lookup over the same registry, and shows the readable
//! text the `fewshot audit` command would print.

mod common;

use common::*;
use fewshot_gate::Registry;
use fewshot_runtime::{load_dir, timeline};

/// A name lookup over the fixture registry, in the form callers pass to
/// [`timeline::render`].
fn name_for(reg: &Registry) -> impl Fn(u32) -> Option<String> + '_ {
    move |id: u32| reg.iter().find(|a| a.id.0 == id).map(|a| a.name.clone())
}

#[test]
fn a_run_renders_a_readable_timeline() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    let s = rt.open_session("claude-code").unwrap();
    let doc = rt.literal(s, b"doc".to_vec()).unwrap();
    rt.call(s, "doc.fetch", vec![doc], None).unwrap();
    rt.close_session(s).unwrap();
    drop(rt);

    let reg = registry();
    let lookup = name_for(&reg);
    let mut files = load_dir(&dir.path().join("audit")).unwrap();
    assert_eq!(files.len(), 1, "one audit file per run");
    let (_, entries) = files.pop().unwrap();
    let text = timeline::to_text(&timeline::render(&entries, lookup));

    assert!(text.contains("session opened"), "{text}");
    assert!(text.contains("done doc.fetch"), "{text}");
}
