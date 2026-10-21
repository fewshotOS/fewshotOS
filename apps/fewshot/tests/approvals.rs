//! `SocketApprovals` against a stand-in approval app on a real local socket,
//! and the source rule that nothing on the agent side can sign approvals.

use fewshot::{Answer, Approvals, SocketApprovals};
use fewshot_approval::{Message, Server, WireAnswer, WireDecision, WireItem, approve_item};
use fewshot_gate::{ActionId, ApprovalRequest, Approver, Digest, Nonce};
use fewshot_labeld::{Integrity, Label, Secrecy, SessionId};
use std::path::Path;
use std::time::Duration;

fn item() -> WireItem {
    let req = ApprovalRequest {
        digest: Digest([0xab; 32]),
        nonce: Nonce(3),
        session: SessionId(1),
        action: ActionId(3),
        args: vec![],
        context: Label::new(Secrecy::EMPTY, Integrity::ThirdParty),
        context_below_floor: true,
    };
    WireItem::from_request(&req, "fs.write", "Overwrite a file".into())
}

fn name(tag: &str) -> String {
    format!("fewshot-approval-test-{}-{tag}", std::process::id())
}

/// A one-connection approval app that answers with `decide`, or never.
fn app(name: &str, decide: Option<fn(&WireItem) -> WireDecision>) -> std::thread::JoinHandle<()> {
    let server = Server::bind(name).unwrap();
    std::thread::spawn(move || {
        let mut conn = server.accept().unwrap();
        conn.send(&Message::Hello { version: 1 }).unwrap();
        loop {
            match conn.recv() {
                Ok(Message::Request(req)) => {
                    let Some(decide) = decide else {
                        // Hold the request unanswered past the timeout.
                        std::thread::sleep(Duration::from_millis(600));
                        return;
                    };
                    let decisions = req.items.iter().map(decide).collect();
                    conn.send(&Message::Answer(WireAnswer { id: req.id, decisions })).unwrap();
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    })
}

fn approve(item: &WireItem) -> WireDecision {
    approve_item(&Approver::from_secret([7; 32]), item, u64::MAX).unwrap()
}

fn deny(item: &WireItem) -> WireDecision {
    WireDecision::Denied { digest: item.digest.clone(), nonce: item.nonce }
}

fn other_digest(item: &WireItem) -> WireDecision {
    WireDecision::Denied { digest: "00".repeat(32), nonce: item.nonce }
}

#[test]
fn an_approval_comes_back_signed() {
    let n = name("approve");
    let t = app(&n, Some(approve));
    let answer = SocketApprovals::with_name(&n, Duration::from_secs(10)).ask("claude-code", item());
    let Answer::Approved(a) = answer else { panic!("expected an approval, got {answer:?}") };
    assert_eq!(a.digest, Digest([0xab; 32]));
    assert_eq!(a.nonce, Nonce(3));
    t.join().unwrap();
}

#[test]
fn a_denial_comes_back_denied() {
    let n = name("deny");
    let t = app(&n, Some(deny));
    assert_eq!(SocketApprovals::with_name(&n, Duration::from_secs(10)).ask("c", item()), Answer::Denied);
    t.join().unwrap();
}

#[test]
fn an_answer_about_another_call_is_not_used() {
    let n = name("other");
    let t = app(&n, Some(other_digest));
    let answer = SocketApprovals::with_name(&n, Duration::from_secs(10)).ask("c", item());
    assert!(matches!(answer, Answer::Unavailable(_)), "{answer:?}");
    t.join().unwrap();
}

#[test]
fn no_answer_in_time_is_a_timeout() {
    let n = name("timeout");
    let t = app(&n, None);
    assert_eq!(SocketApprovals::with_name(&n, Duration::from_millis(200)).ask("c", item()), Answer::Timeout);
    t.join().unwrap();
}

#[test]
fn no_approval_app_says_how_to_start_it() {
    let answer = SocketApprovals::with_name(name("absent"), Duration::from_secs(5)).ask("c", item());
    let Answer::Unavailable(why) = answer else { panic!("expected unavailable, got {answer:?}") };
    assert!(why.contains("fewshot-approve"), "{why}");
}

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push((path.display().to_string(), std::fs::read_to_string(&path).unwrap()));
        }
    }
}

#[test]
fn nothing_on_the_agent_side_can_sign_an_approval() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&here.join("src"), &mut files);
    sources(&here.join("../../libs/runtime/src"), &mut files);
    assert!(files.len() > 5, "found the sources");
    for (path, text) in files {
        for word in ["Approver", "approve_item", "load_or_create", "from_secret"] {
            assert!(!text.contains(word), "{path} mentions {word}");
        }
    }
}
