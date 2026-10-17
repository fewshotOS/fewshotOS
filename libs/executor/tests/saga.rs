//! Checkpoints commit what came before them; a failed commit undoes what
//! already ran, latest first.

mod common;

use common::*;
use fewshot_executor::*;

#[test]
fn checkpoint_commits_only_effects_before_it() {
    let mut w = World::new();
    let p = plan(
        r#"{"steps":[
            {"op":"let","var":"to","text":"bob@example.com"},
            {"op":"let","var":"first","text":"first"},
            {"op":"let","var":"second","text":"second"},
            {"op":"call","action":3,"args":["to","first"]},
            {"op":"checkpoint"},
            {"op":"call","action":3,"args":["to","second"]}
        ]}"#,
    );
    let mut exec = w.start(&p, vec![]);
    assert_eq!(w.run(&mut exec, &mut NoReader), Outcome::Checkpoint);
    assert_eq!(w.fx.count(SEND), 0, "nothing runs before the checkpoint commit");

    let report = w.saga(&mut exec);
    assert_eq!(report.committed.len(), 1);
    assert_eq!(report.failed, None);
    assert_eq!(w.fx.calls, vec![(SEND, vec![b"bob@example.com".to_vec(), b"first".to_vec()])]);

    assert_eq!(w.run(&mut exec, &mut NoReader), Outcome::Done { drafts: vec![] });
    assert_eq!(w.fx.count(SEND), 1, "the second send waits for the final commit");
    w.saga(&mut exec);
    assert_eq!(w.fx.calls[1], (SEND, vec![b"bob@example.com".to_vec(), b"second".to_vec()]));
}

const THREE_EFFECTS: &str = r#"{"steps":[
    {"op":"let","var":"to","text":"bob@example.com"},
    {"op":"let","var":"body","text":"hi"},
    {"op":"let","var":"acct","text":"acct-1"},
    {"op":"let","var":"folder","text":"archive"},
    FIRST,
    {"op":"call","action":8,"args":["acct"]},
    THIRD,
    {"op":"checkpoint"},
    {"op":"call","action":2,"args":["body"]}
]}"#;
const SEND_STEP: &str = r#"{"op":"call","action":3,"args":["to","body"]}"#;
const FILE_STEP: &str = r#"{"op":"call","action":4,"args":["folder"]}"#;

#[test]
fn failed_commit_compensates_earlier_effects_and_reports_the_rest() {
    let mut w = World::new();
    w.fx.fail_on = Some(PAY);
    let p = plan(&THREE_EFFECTS.replace("FIRST", SEND_STEP).replace("THIRD", FILE_STEP));
    let mut exec = w.start(&p, vec![]);
    assert_eq!(w.run(&mut exec, &mut NoReader), Outcome::Checkpoint);

    let report = w.saga(&mut exec);
    assert_eq!(report.committed.len(), 1);
    assert!(report.failed.is_some());
    assert_eq!(report.compensated, report.committed, "the send was recalled");
    assert!(report.not_compensated.is_empty());
    assert_eq!(report.not_run.len(), 1, "the filing never ran");
    let actions: Vec<_> = w.fx.calls.iter().map(|(a, _)| *a).collect();
    assert_eq!(actions, vec![SEND, PAY, RECALL]);
    assert_eq!(w.fx.calls[2].1, w.fx.calls[0].1, "the recall gets the send's arguments");

    assert_eq!(
        w.run(&mut exec, &mut NoReader),
        Outcome::Failed(ExecError::Finished),
        "a failed checkpoint ends the plan"
    );
    assert_eq!(w.fx.count(NOTE), 0);
}

#[test]
fn effects_without_compensation_are_reported_not_compensated() {
    let mut w = World::new();
    w.fx.fail_on = Some(PAY);
    let p = plan(&THREE_EFFECTS.replace("FIRST", FILE_STEP).replace("THIRD", SEND_STEP));
    let mut exec = w.start(&p, vec![]);
    assert_eq!(w.run(&mut exec, &mut NoReader), Outcome::Checkpoint);

    let report = w.saga(&mut exec);
    assert_eq!(report.committed.len(), 1);
    assert!(report.compensated.is_empty());
    assert_eq!(report.not_compensated, report.committed, "filing has no compensation");
    assert_eq!(report.not_run.len(), 1);
    assert_eq!(w.fx.calls.iter().map(|(a, _)| *a).collect::<Vec<_>>(), vec![FILE, PAY]);
}

#[test]
fn compensations_run_latest_first() {
    let mut w = World::new();
    w.fx.fail_on = Some(PAY);
    let p = plan(
        r#"{"steps":[
            {"op":"let","var":"to","text":"bob@example.com"},
            {"op":"let","var":"a","text":"a"},
            {"op":"let","var":"b","text":"b"},
            {"op":"let","var":"acct","text":"acct-1"},
            {"op":"call","action":3,"args":["to","a"]},
            {"op":"call","action":3,"args":["to","b"]},
            {"op":"call","action":8,"args":["acct"]}
        ]}"#,
    );
    let mut exec = w.start(&p, vec![]);
    assert_eq!(w.run(&mut exec, &mut NoReader), Outcome::Done { drafts: vec![] });
    let report = w.saga(&mut exec);
    assert_eq!(report.compensated, report.committed.iter().rev().copied().collect::<Vec<_>>());
    let recalls: Vec<_> = w.fx.calls.iter().filter(|(a, _)| *a == RECALL).map(|(_, args)| args[1].clone()).collect();
    assert_eq!(recalls, vec![b"b".to_vec(), b"a".to_vec()]);
}
