//! The JSONL audit file: exact round trip, one verifiable file per run,
//! and tampering detected on load.

mod common;

use common::*;
use fewshot_gate::{ActionId, ApprovalError, AuditEntry, AuditKind, Digest, Nonce, Reason};
use fewshot_labeld::SessionId;
use fewshot_runtime::{AuditFileError, entry_from_json, entry_to_json, load_dir, load_file};
use std::path::PathBuf;

fn entry(kind: AuditKind, action: Option<ActionId>, digest: Option<Digest>) -> AuditEntry {
    AuditEntry { seq: 7, at_ms: 1_234, session: SessionId(3), action, digest, kind, prev: [0xab; 32], hash: [0x01; 32] }
}

#[test]
fn every_kind_and_reason_round_trips() {
    let approval_errors = [
        ApprovalError::UnknownNonce,
        ApprovalError::Reused,
        ApprovalError::Expired,
        ApprovalError::BadSignature,
        ApprovalError::DigestMismatch,
    ];
    let mut reasons = vec![
        Reason::UnknownSession,
        Reason::UnknownAction,
        Reason::MissingCapability,
        Reason::WrongArity,
        Reason::UnknownHandle,
        Reason::EgressNotCleared,
    ];
    reasons.extend(approval_errors.map(Reason::ApprovalInvalid));
    let mut kinds = vec![
        AuditKind::SessionOpened,
        AuditKind::ApprovalRequested(Nonce(42)),
        AuditKind::EffectStarted,
        AuditKind::Queued,
        AuditKind::EffectSucceeded,
        AuditKind::EffectReturned([0x5c; 32]),
        AuditKind::EffectFailed,
        AuditKind::OutboxDropped(u32::MAX),
        AuditKind::SessionClosed,
    ];
    kinds.extend(reasons.into_iter().map(AuditKind::Refused));
    for kind in kinds {
        for (action, digest) in [(None, None), (Some(ActionId(u32::MAX)), Some(Digest([0xfe; 32])))] {
            let e = entry(kind, action, digest);
            assert_eq!(entry_from_json(&entry_to_json(&e)).unwrap(), e, "{kind:?}");
        }
    }
}

#[test]
fn malformed_values_are_errors_not_panics() {
    let good = entry_to_json(&entry(AuditKind::Queued, Some(ActionId(1)), None));
    for bad in [
        good.replace("\"action\":1", "\"action\":4294967296"),
        good.replace(&"ab".repeat(32), &"é".repeat(32)),
        good.replace("\"queued\"", "\"teleported\""),
        "not json".to_string(),
    ] {
        assert!(entry_from_json(&bad).is_err(), "{bad}");
    }
}

/// Runs a short session, drops the runtime, and returns the one audit file.
fn one_run(dir: &std::path::Path) -> (PathBuf, Vec<AuditEntry>) {
    let mut rt = runtime(dir);
    let s = rt.open_session("claude-code").unwrap();
    let doc = rt.literal(s, b"doc".to_vec()).unwrap();
    rt.call(s, "doc.fetch", vec![doc], None).unwrap();
    rt.call(s, "notes.append", vec![doc], None).unwrap();
    rt.close_session(s).unwrap();
    let expected = rt.gate().audit().entries().to_vec();
    drop(rt);
    let mut files = load_dir(&dir.join("audit")).unwrap();
    assert_eq!(files.len(), 1, "one file per run");
    let (path, entries) = files.pop().unwrap();
    assert_eq!(entries, expected);
    (path, entries)
}

#[test]
fn a_run_writes_one_file_matching_the_gates_log() {
    let dir = tempfile::tempdir().unwrap();
    let (_, entries) = one_run(dir.path());
    assert!(entries.len() >= 6);
}

fn rewrite(path: &std::path::Path, f: impl FnOnce(&mut Vec<String>)) {
    let mut lines: Vec<String> = std::fs::read_to_string(path).unwrap().lines().map(String::from).collect();
    f(&mut lines);
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn an_edited_line_breaks_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (path, entries) = one_run(dir.path());
    let k = 2;
    rewrite(&path, |lines| {
        let at = format!("\"at_ms\":{}", entries[k].at_ms);
        lines[k] = lines[k].replace(&at, &format!("\"at_ms\":{}", entries[k].at_ms + 1));
    });
    assert!(matches!(load_file(&path), Err(AuditFileError::BrokenChain { seq, .. }) if seq == k as u64));
}

#[test]
fn a_deleted_line_breaks_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = one_run(dir.path());
    rewrite(&path, |lines| {
        lines.remove(2);
    });
    assert!(matches!(load_file(&path), Err(AuditFileError::BrokenChain { seq: 2, .. })));
}

#[test]
fn a_bad_line_reports_its_line_number() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = one_run(dir.path());
    rewrite(&path, |lines| lines[3] = "{\"seq\":".into());
    assert!(matches!(load_file(&path), Err(AuditFileError::BadLine { line: 4, .. })));
}
