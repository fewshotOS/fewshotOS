//! Sessions, literal labels, outputs, approvals and quarantined reads.

mod common;

use common::*;
use fewshot_executor::{Reader, ReaderError};
use fewshot_gate::AuditKind;
use fewshot_labeld::{Integrity, Label, SessionId};
use fewshot_plan::Schema;
use fewshot_runtime::{CallResult, Config, Runtime, RuntimeError};

fn output(r: CallResult) -> fewshot_labeld::Handle {
    match r {
        CallResult::Done { output: Some(h) } => h,
        other => panic!("expected an output, got {other:?}"),
    }
}

#[test]
fn a_client_naming_an_unregistered_action_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse("[[client]]\nname = \"c\"\nactions = [\"fs.nuke\"]\n").unwrap();
    let err = Runtime::new(cfg, registry(), approver().verifying_key(), Fx::default()).err().unwrap();
    assert!(matches!(err, RuntimeError::UnknownAction { action, .. } if action == "fs.nuke"));
    drop(dir);
}

#[test]
fn open_session_rejects_an_unknown_client() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    assert!(matches!(rt.open_session("mallory"), Err(RuntimeError::UnknownClient { .. })));
}

#[test]
fn literals_carry_the_clients_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    let s = rt.open_session("claude-code").unwrap();
    let h = rt.literal(s, b"hello".to_vec()).unwrap();
    assert_eq!(rt.label_of(s, h).unwrap().integrity, Integrity::ThirdParty);
}

#[test]
fn outputs_keep_the_gates_label() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    let s = rt.open_session("claude-code").unwrap();
    let doc = rt.literal(s, b"doc-1".to_vec()).unwrap();
    let h = output(rt.call(s, "doc.fetch", vec![doc], None).unwrap());
    // Declared SystemApp, joined with the ThirdParty literal argument.
    assert_eq!(rt.label_of(s, h).unwrap(), Label::new(fewshot_labeld::Secrecy::EMPTY, Integrity::ThirdParty));
    assert!(rt.gate().audit().entries().iter().any(|e| matches!(e.kind, AuditKind::EffectReturned(_))));
}

#[test]
fn revealing_untrusted_content_taints_later_literals() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    let s = rt.open_session("claude-code").unwrap();
    let url = rt.literal(s, b"https://x.example/".to_vec()).unwrap();
    let page = output(rt.call(s, "web.fetch", vec![url], None).unwrap());
    assert_eq!(rt.label_of(s, page).unwrap().integrity, Integrity::UntrustedWeb);
    assert_eq!(
        rt.literal(s, b"a".to_vec()).map(|h| rt.label_of(s, h).unwrap().integrity).unwrap(),
        Integrity::ThirdParty
    );

    let bytes = rt.reveal(s, page).unwrap();
    assert!(bytes.starts_with(b"<html>"));
    assert_eq!(rt.principal_label(s).integrity, Integrity::UntrustedWeb);
    let after = rt.literal(s, b"b".to_vec()).unwrap();
    assert_eq!(
        rt.label_of(s, after).unwrap().integrity,
        Integrity::UntrustedWeb,
        "the client has now seen web content"
    );
}

#[test]
fn third_party_sends_need_approval_then_queue_and_commit() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    let s = rt.open_session("claude-code").unwrap();
    let to = rt.literal(s, b"a@b.example".to_vec()).unwrap();
    let body = rt.literal(s, b"hi".to_vec()).unwrap();
    let CallResult::NeedsApproval(req) = rt.call(s, "mail.send", vec![to, body], None).unwrap() else {
        panic!("expected an approval request")
    };
    let approval = approver().approve(&req, u64::MAX);
    assert!(matches!(rt.call(s, "mail.send", vec![to, body], Some(approval)).unwrap(), CallResult::Queued { .. }));
    let report = rt.commit(s).unwrap();
    assert_eq!(report.executed.len(), 1);
}

struct Says(&'static [u8]);

impl Reader for Says {
    fn extract(&mut self, _schema: &Schema, _input: &[u8]) -> Result<Vec<u8>, ReaderError> {
        Ok(self.0.to_vec())
    }
}

#[test]
fn certified_choices_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    let s = rt.open_session("claude-code").unwrap();
    let url = rt.literal(s, b"https://x.example/".to_vec()).unwrap();
    let page = output(rt.call(s, "web.fetch", vec![url], None).unwrap());
    let schema = Schema::Choice { options: vec!["inbox".into(), "archive".into()] };
    let folder = rt.extract(s, page, &schema, Says(b"archive")).unwrap();
    assert_eq!(rt.label_of(s, folder).unwrap().integrity, Integrity::Bounded);
    assert!(rt.extract(s, page, &schema, Says(b"trash")).is_err(), "outside the options");
}

#[test]
fn unknown_and_closed_sessions_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = runtime(dir.path());
    assert!(matches!(rt.literal(SessionId(99), vec![]), Err(RuntimeError::UnknownSession { .. })));
    let s = rt.open_session("claude-code").unwrap();
    let h = rt.literal(s, b"x".to_vec()).unwrap();
    rt.close_session(s).unwrap();
    assert!(matches!(rt.label_of(s, h), Err(RuntimeError::UnknownSession { .. })));
    assert_eq!(rt.client_of(s), None);
}
