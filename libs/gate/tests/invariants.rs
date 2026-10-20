//! Invariant suites I1–I5 and ADR-0005/0006 for the policy core.

mod common;

use common::*;
use fewshot_gate::*;
use fewshot_labeld::{Integrity, Label, Secrecy};

mod i1_no_ambient_authority {
    use super::*;

    #[test]
    fn no_capability_no_effect() {
        let mut w = World::with_caps(CapSet::new([READ]));
        let note = w.user(b"hi");
        let err = w.invoke(&Invocation::new(NOTE, [note])).unwrap_err();
        assert_eq!(err.reason, Reason::MissingCapability);
        assert_eq!(err.grantor, Grantor::User);
        assert!(w.fx.calls.is_empty());
        assert!(w.gate.audit().entries().iter().any(|e| e.kind == AuditKind::Refused(Reason::MissingCapability)));
    }

    #[test]
    fn attenuated_delegation_cannot_widen() {
        let child = CapSet::new([READ, SEND]).attenuate([READ, NOTE]);
        let mut w = World::with_caps(child);
        let doc = w.user(b"doc");
        assert!(w.invoke(&Invocation::new(READ, [doc])).is_ok());
        assert_eq!(w.invoke(&Invocation::new(NOTE, [doc])).unwrap_err().reason, Reason::MissingCapability);
        assert_eq!(w.invoke(&Invocation::new(SEND, [doc, doc])).unwrap_err().reason, Reason::MissingCapability);
    }

    #[test]
    fn unknown_session_is_refused() {
        let mut w = World::new();
        let doc = w.user(b"doc");
        let err = w.gate.invoke(&w.table, S2, &Invocation::new(READ, [doc]), &mut w.fx).unwrap_err();
        assert_eq!(err.reason, Reason::UnknownSession);
    }
}

mod i2_untrusted_data_cannot_steer {
    use super::*;

    #[test]
    fn tainted_argument_needs_approval_and_does_nothing() {
        let mut w = World::new();
        let to = w.web(b"attacker@evil.example");
        let body = w.user(b"hello");
        let Ok(Decision::NeedsApproval(req)) = w.invoke(&Invocation::new(SEND, [to, body])) else { panic!() };
        assert_eq!(req.args.iter().map(|a| a.below_floor).collect::<Vec<_>>(), [true, false]);
        assert_eq!(w.gate.outbox_len(S1), 0);
        assert!(w.fx.calls.is_empty());
    }

    #[test]
    fn approved_call_proceeds() {
        let mut w = World::new();
        let inv = Invocation::new(SEND, [w.web(b"a@b.example"), w.user(b"hi")]);
        let (_, approval) = w.request(&inv);
        let d = w.invoke(&inv.with_approval(approval)).unwrap();
        assert!(matches!(d, Decision::Queued { .. }));
    }

    #[test]
    fn calls_after_reading_tainted_data_need_approval() {
        // An implicit flow: the arguments are clean, but the session read
        // untrusted data first, so that data may have decided the call.
        let mut w = World::new();
        let cond = w.web(b"reply");
        let inv = Invocation::new(SEND, [w.user(b"a@b.example"), w.user(b"hi")]);
        w.table.view(S1).read(cond).unwrap();
        let Ok(Decision::NeedsApproval(req)) = w.invoke(&inv) else { panic!() };
        assert!(req.context_below_floor);
        assert_eq!(req.context.integrity, Integrity::UntrustedWeb);
        assert_eq!(req.args.iter().map(|a| a.below_floor).collect::<Vec<_>>(), [false, false]);
        assert_eq!(w.gate.outbox_len(S1), 0);
        let (_, approval) = w.request(&inv);
        assert!(matches!(w.invoke(&inv.with_approval(approval)), Ok(Decision::Queued { .. })));
    }

    #[test]
    fn context_at_or_above_the_floor_needs_no_approval() {
        let mut w = World::new();
        let cond = w.value(S1, b"x", Label::new(Secrecy::EMPTY, Integrity::ThirdParty));
        w.table.view(S1).read(cond).unwrap();
        let text = w.user(b"note");
        assert!(matches!(w.invoke(&Invocation::new(NOTE, [text])), Ok(Decision::Executed(Ok(None)))));
    }

    #[test]
    fn taint_survives_derivation() {
        // Labels come from the value table, so laundering a value through
        // derive cannot raise its integrity (ADR-0005).
        let mut w = World::new();
        let page = w.web(b"page with an address");
        let extracted = w.table.derive(S1, "reader:extract_email", &[page], b"x@y.example".to_vec()).unwrap();
        let body = w.user(b"hi");
        assert!(matches!(w.invoke(&Invocation::new(SEND, [extracted, body])), Ok(Decision::NeedsApproval(_))));
    }

    #[test]
    fn bounded_values_may_only_pick_approved_options() {
        let mut w = World::new();
        let bounded = Label::new(Secrecy::EMPTY, Integrity::Bounded);
        let archive = w.value(S1, b"archive", bounded);
        let other = w.value(S1, b"spam", bounded);
        let web_archive = w.web(b"archive");

        assert!(matches!(w.invoke(&Invocation::new(FILE, [archive])), Ok(Decision::Queued { .. })));
        assert!(matches!(w.invoke(&Invocation::new(FILE, [other])), Ok(Decision::NeedsApproval(_))));
        assert!(matches!(w.invoke(&Invocation::new(FILE, [web_archive])), Ok(Decision::NeedsApproval(_))));
    }

    #[test]
    fn bounded_values_cannot_fill_open_parameters() {
        let mut w = World::new();
        let to = w.value(S1, b"a@b.example", Label::new(Secrecy::EMPTY, Integrity::Bounded));
        let body = w.user(b"hi");
        assert!(matches!(w.invoke(&Invocation::new(SEND, [to, body])), Ok(Decision::NeedsApproval(_))));
    }
}

mod i3_no_uncleared_egress {
    use super::*;

    #[test]
    fn uncleared_secrecy_cannot_leave() {
        let mut w = World::new();
        let to = w.user(b"a@b.example");
        let body = w.value(S1, b"diagnosis", Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::User));
        let err = w.invoke(&Invocation::new(SEND, [to, body])).unwrap_err();
        assert_eq!(err.reason, Reason::EgressNotCleared);
        assert_eq!(w.gate.outbox_len(S1), 0);
    }

    #[test]
    fn cleared_secrecy_may_leave() {
        let mut w = World::new();
        let to = w.user(b"a@b.example");
        let body = w.value(S1, b"report", Label::new(Secrecy::EMPTY.with(WORK), Integrity::User));
        assert!(matches!(w.invoke(&Invocation::new(SEND, [to, body])), Ok(Decision::Queued { .. })));
    }

    #[test]
    fn approval_does_not_declassify() {
        let mut w = World::new();
        let to = w.web(b"a@b.example");
        let body = w.value(S1, b"diagnosis", Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::User));
        assert_eq!(w.invoke(&Invocation::new(SEND, [to, body])).unwrap_err().reason, Reason::EgressNotCleared);
    }

    #[test]
    fn secrets_read_before_a_call_cannot_leave_through_it() {
        // Whether the send happens may encode the secret, even with clean
        // arguments.
        let mut w = World::new();
        let secret = w.value(S1, b"diagnosis", Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::User));
        let inv = Invocation::new(SEND, [w.user(b"a@b.example"), w.user(b"hi")]);
        w.table.view(S1).read(secret).unwrap();
        assert_eq!(w.invoke(&inv).unwrap_err().reason, Reason::EgressNotCleared);
    }

    #[test]
    fn local_effects_are_not_egress() {
        let mut w = World::new();
        let text = w.value(S1, b"diagnosis", Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::User));
        assert!(matches!(w.invoke(&Invocation::new(NOTE, [text])), Ok(Decision::Executed(Ok(None)))));
    }

    const GET: ActionId = ActionId(6);

    /// The fixture plus `GET`, a remote read (`Fetch`) cleared for `WORK` that returns web data.
    fn with_get() -> World {
        let mut r = registry();
        r.register(ActionSpec {
            id: GET,
            name: "http.get".into(),
            effect: Effect::Fetch,
            integrity_floor: Integrity::UntrustedWeb,
            egress_clearance: Secrecy::EMPTY.with(WORK),
            params: vec![Param::open("url")],
            draft_for: None,
            compensation: None,
            output: Some(Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb)),
        })
        .unwrap();
        World::with_registry(r, CapSet::new([READ, NOTE, SEND, GET]))
    }

    #[test]
    fn fetch_arguments_are_egress() {
        let mut w = with_get();
        let url =
            w.value(S1, b"https://x.example/?q=diagnosis", Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::User));
        assert_eq!(w.invoke(&Invocation::new(GET, [url])).unwrap_err().reason, Reason::EgressNotCleared);
        assert!(w.fx.calls.is_empty());
    }

    #[test]
    fn secrets_read_before_a_fetch_cannot_leave_through_it() {
        let mut w = with_get();
        let secret = w.value(S1, b"diagnosis", Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::User));
        let url = w.user(b"https://x.example/");
        w.table.view(S1).read(secret).unwrap();
        assert_eq!(w.invoke(&Invocation::new(GET, [url])).unwrap_err().reason, Reason::EgressNotCleared);
    }

    #[test]
    fn cleared_fetch_runs_at_once_and_returns_output() {
        let mut w = with_get();
        w.fx.returns = b"<html>".to_vec();
        let url = w.value(S1, b"https://x.example/", Label::new(Secrecy::EMPTY.with(WORK), Integrity::User));
        let Ok(Decision::Executed(Ok(Some(out)))) = w.invoke(&Invocation::new(GET, [url])) else {
            panic!("expected the fetch to run now")
        };
        assert_eq!(out.label, Label::new(Secrecy::EMPTY.with(WORK), Integrity::UntrustedWeb));
    }
}

mod i4_audit_before_effect {
    use super::*;

    #[test]
    fn effects_receive_their_start_entry() {
        let mut w = World::new();
        let doc = w.user(b"doc");
        w.invoke(&Invocation::new(READ, [doc])).unwrap();
        let note = w.user(b"note");
        w.invoke(&Invocation::new(NOTE, [note])).unwrap();
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        w.commit();

        assert_eq!(w.fx.calls.len(), 3);
        let log = w.gate.audit().entries();
        for (action, _, record) in &w.fx.calls {
            assert_eq!(record.kind, AuditKind::EffectStarted);
            assert_eq!(record.action, Some(*action));
            assert_eq!(&log[record.seq as usize], record, "entry was in the log when the effect ran");
        }
        assert_audit_before_effect(w.gate.audit());
    }

    #[test]
    fn refusals_and_requests_are_audited() {
        let mut w = World::with_caps(CapSet::new([SEND]));
        let doc = w.user(b"doc");
        let _ = w.invoke(&Invocation::new(READ, [doc]));
        let to = w.web(b"x");
        let _ = w.invoke(&Invocation::new(SEND, [to, doc]));
        let kinds: Vec<_> = w.gate.audit().entries().iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&AuditKind::Refused(Reason::MissingCapability)));
        assert!(kinds.iter().any(|k| matches!(k, AuditKind::ApprovalRequested(_))));
        assert_audit_before_effect(w.gate.audit());
    }

    #[test]
    fn sink_stores_every_entry_in_order() {
        let mut w = World::new();
        let sink = SharedSink::default();
        w.gate.set_audit_sink(Box::new(sink.clone()));
        let note = w.user(b"note");
        w.invoke(&Invocation::new(NOTE, [note])).unwrap();
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        w.commit();
        assert_eq!(sink.0.borrow().stored, w.gate.audit().entries(), "including entries from before the sink");
        assert!(w.gate.audit_stored());
    }

    #[test]
    fn failing_sink_stops_the_effect() {
        let mut w = World::new();
        let sink = SharedSink::default();
        w.gate.set_audit_sink(Box::new(sink.clone()));
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        sink.0.borrow_mut().failing = true;

        let note = w.user(b"note");
        let Ok(Decision::Executed(Err(_))) = w.invoke(&Invocation::new(NOTE, [note])) else {
            panic!("expected the immediate effect to fail")
        };
        let report = w.commit();
        assert!(report.failed.is_some());
        assert!(report.executed.is_empty());
        assert!(w.fx.calls.is_empty(), "no effect ran without a stored start entry");
        assert!(!w.gate.audit_stored());
        assert_audit_before_effect(w.gate.audit());
    }

    #[test]
    fn sink_catches_up_after_a_failure() {
        let mut w = World::new();
        let sink = SharedSink::default();
        w.gate.set_audit_sink(Box::new(sink.clone()));
        sink.0.borrow_mut().failing = true;
        let note = w.user(b"note");
        let _ = w.invoke(&Invocation::new(NOTE, [note]));
        sink.0.borrow_mut().failing = false;

        assert_eq!(w.invoke(&Invocation::new(NOTE, [note])), Ok(Decision::Executed(Ok(None))));
        assert_eq!(w.fx.calls.len(), 1);
        assert_eq!(sink.0.borrow().stored, w.gate.audit().entries(), "the backlog is stored, in order, once");
    }
}

mod outputs {
    use super::*;
    use fewshot_labeld::Handle;
    use sha2::{Digest as _, Sha256};

    const FETCH: ActionId = ActionId(5);

    /// The fixture registry plus `FETCH`, a read returning `SystemApp` data tagged `HEALTH`.
    fn world() -> World {
        let mut r = registry();
        r.register(ActionSpec {
            id: FETCH,
            name: "doc.fetch".into(),
            effect: Effect::Read,
            integrity_floor: Integrity::UntrustedWeb,
            egress_clearance: Secrecy::EMPTY,
            params: vec![Param::open("doc")],
            draft_for: None,
            compensation: None,
            output: Some(Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::SystemApp)),
        })
        .unwrap();
        r.validate().unwrap();
        let mut w = World::with_registry(r, CapSet::new([READ, NOTE, SEND, FETCH]));
        w.fx.returns = b"contents".to_vec();
        w
    }

    fn fetch(w: &mut World, arg: Handle) -> Output {
        match w.invoke(&Invocation::new(FETCH, [arg])) {
            Ok(Decision::Executed(Ok(Some(out)))) => out,
            other => panic!("expected an output, got {other:?}"),
        }
    }

    #[test]
    fn output_carries_the_declared_label() {
        let mut w = world();
        let doc = w.user(b"doc");
        let out = fetch(&mut w, doc);
        assert_eq!(out.value, b"contents");
        assert_eq!(out.label, Label::new(Secrecy::EMPTY.with(HEALTH), Integrity::SystemApp));
    }

    #[test]
    fn output_joins_the_arguments_labels() {
        let mut w = world();
        let doc = w.value(S1, b"doc", Label::new(Secrecy::EMPTY.with(WORK), Integrity::UntrustedWeb));
        let out = fetch(&mut w, doc);
        assert_eq!(out.label, Label::new(Secrecy::EMPTY.with(WORK).with(HEALTH), Integrity::UntrustedWeb));
    }

    #[test]
    fn output_joins_the_sessions_principal_label() {
        let mut w = world();
        let page = w.web(b"page");
        w.table.view(S1).read(page).unwrap();
        let doc = w.user(b"doc");
        let out = fetch(&mut w, doc);
        assert_eq!(out.label.integrity, Integrity::UntrustedWeb, "a read steered by tainted context is tainted");
    }

    #[test]
    fn returned_output_is_audited_by_hash() {
        let mut w = world();
        let doc = w.user(b"doc");
        fetch(&mut w, doc);
        let hash: [u8; 32] = Sha256::digest(b"contents").into();
        assert!(w.gate.audit().entries().iter().any(|e| e.kind == AuditKind::EffectReturned(hash)));
        assert_audit_before_effect(w.gate.audit());
    }

    #[test]
    fn undeclared_output_fails_the_effect() {
        let mut w = world();
        let note = w.user(b"note");
        let Ok(Decision::Executed(Err(_))) = w.invoke(&Invocation::new(NOTE, [note])) else {
            panic!("expected the effect to fail")
        };
        assert_eq!(w.gate.audit().entries().last().unwrap().kind, AuditKind::EffectFailed);
    }

    #[test]
    fn queued_effects_return_nothing() {
        let mut w = world();
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        let report = w.commit();
        assert!(report.failed.is_some(), "an outbox effect returning bytes fails");
    }
}

mod i5_reversible_until_commit {
    use super::*;

    #[test]
    fn external_effects_wait_for_commit() {
        let mut w = World::new();
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        assert!(w.fx.calls.is_empty());
        assert_eq!(w.gate.outbox_len(S1), 1);
        let report = w.commit();
        assert_eq!(report.executed.len(), 1);
        assert_eq!(w.fx.calls[0].1, [b"a@b.example".to_vec(), b"hi".to_vec()]);
    }

    #[test]
    fn abort_drops_the_outbox_unrun() {
        let mut w = World::new();
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        assert_eq!(w.gate.abort(S1).unwrap(), 2);
        assert_eq!(w.commit(), CommitReport::default());
        assert!(w.fx.calls.is_empty());
    }

    #[test]
    fn commit_runs_in_order_and_stops_at_failure() {
        let mut w = World::new();
        let archive = w.user(b"archive");
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(FILE, [archive])).unwrap();
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        w.invoke(&Invocation::new(FILE, [archive])).unwrap();
        w.fx.fail_on = Some(SEND);
        let report = w.commit();
        assert_eq!(report.executed.len(), 1);
        assert!(report.failed.is_some());
        assert_eq!(report.not_run.len(), 1);
        assert_eq!(w.fx.calls.iter().map(|c| c.0).collect::<Vec<_>>(), [FILE, SEND]);
        assert!(w.gate.audit().entries().iter().any(|e| e.kind == AuditKind::OutboxDropped(1)));
        assert_audit_before_effect(w.gate.audit());
    }

    #[test]
    fn closing_a_session_drops_its_outbox() {
        let mut w = World::new();
        let (to, body) = (w.user(b"a@b.example"), w.user(b"hi"));
        w.invoke(&Invocation::new(SEND, [to, body])).unwrap();
        assert_eq!(w.gate.close_session(S1), 1);
        assert!(w.gate.commit(&w.table, S1, &mut w.fx).is_err());
        assert!(w.fx.calls.is_empty());
    }
}

mod adr_0005_labels_from_the_table {
    use super::*;

    #[test]
    fn handles_from_another_session_do_not_resolve() {
        let mut w = World::new();
        let foreign = w.value(S2, b"x", Label::new(Secrecy::EMPTY, Integrity::User));
        assert_eq!(w.invoke(&Invocation::new(READ, [foreign])).unwrap_err().reason, Reason::UnknownHandle);
    }
}

mod adr_0006_approvals {
    use super::*;

    fn send(w: &mut World) -> Invocation {
        Invocation::new(SEND, [w.web(b"a@b.example"), w.user(b"hi")])
    }

    fn rejected(r: Result<Decision, Refusal>) -> ApprovalError {
        match r.unwrap_err().reason {
            Reason::ApprovalInvalid(e) => e,
            other => panic!("expected approval rejection, got {other:?}"),
        }
    }

    #[test]
    fn modified_argument_invalidates_approval() {
        let mut w = World::new();
        let inv = send(&mut w);
        let (_, approval) = w.request(&inv);
        let swapped = Invocation::new(SEND, [w.web(b"attacker@evil.example"), inv.args[1]]);
        assert_eq!(rejected(w.invoke(&swapped.with_approval(approval))), ApprovalError::DigestMismatch);
        assert_eq!(w.gate.outbox_len(S1), 0);
    }

    #[test]
    fn forged_digest_fails_signature() {
        let mut w = World::new();
        let inv = send(&mut w);
        let (_, mut approval) = w.request(&inv);
        approval.digest = Digest([0; 32]);
        assert_eq!(rejected(w.invoke(&inv.with_approval(approval))), ApprovalError::BadSignature);
    }

    #[test]
    fn approvals_are_single_use() {
        let mut w = World::new();
        let inv = send(&mut w);
        let (_, approval) = w.request(&inv);
        assert!(w.invoke(&inv.clone().with_approval(approval)).is_ok());
        assert_eq!(rejected(w.invoke(&inv.with_approval(approval))), ApprovalError::Reused);
        assert_eq!(w.gate.outbox_len(S1), 1);
    }

    #[test]
    fn approvals_expire() {
        let mut w = World::new();
        let inv = send(&mut w);
        let (_, approval) = w.request(&inv);
        w.clock.advance(60_001);
        assert_eq!(rejected(w.invoke(&inv.with_approval(approval))), ApprovalError::Expired);
    }

    #[test]
    fn approvals_need_the_trusted_key() {
        let mut w = World::new();
        let inv = send(&mut w);
        let Ok(Decision::NeedsApproval(req)) = w.invoke(&inv) else { panic!() };
        let impostor = Approver::from_secret([9; 32]).approve(&req, u64::MAX);
        assert_eq!(rejected(w.invoke(&inv.with_approval(impostor))), ApprovalError::BadSignature);
    }

    #[test]
    fn approvals_are_session_bound() {
        let mut w = World::new();
        let inv = send(&mut w);
        let (_, approval) = w.request(&inv);
        w.gate.open_session(S2, all_caps());
        let other = Invocation::new(
            SEND,
            [
                w.value(S2, b"a@b.example", Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb)),
                w.value(S2, b"hi", Label::new(Secrecy::EMPTY, Integrity::User)),
            ],
        );
        let r = w.gate.invoke(&w.table, S2, &other.with_approval(approval), &mut w.fx);
        assert_eq!(rejected(r), ApprovalError::UnknownNonce);
    }

    #[test]
    fn request_shows_provenance() {
        let mut w = World::new();
        let page = w.web(b"page");
        let to = w.table.derive(S1, "reader:extract_email", &[page], b"a@b.example".to_vec()).unwrap();
        let body = w.user(b"hi");
        let Ok(Decision::NeedsApproval(req)) = w.invoke(&Invocation::new(SEND, [to, body])) else { panic!() };
        assert_eq!(req.args[0].origin, "derived:reader:extract_email");
        assert_eq!(req.args[0].param, "to");
    }
}

/// The gate agrees with a direct statement of its rules (the postconditions of
/// `decide` in specs/verus/gate.rs) on random argument labels.
mod oracle {
    use super::*;
    use proptest::prelude::*;

    fn integrity() -> impl Strategy<Value = Integrity> {
        prop_oneof![
            Just(Integrity::UntrustedWeb),
            Just(Integrity::UntrustedLegacy),
            Just(Integrity::ThirdParty),
            Just(Integrity::Bounded),
            Just(Integrity::SystemApp),
            Just(Integrity::User),
        ]
    }

    #[derive(Debug, PartialEq)]
    enum Expected {
        Run,
        Approval,
        Egress,
    }

    proptest! {
        #[test]
        fn send_matches_rules(i0 in integrity(), i1 in integrity(), s0 in 0u64..8, s1 in 0u64..8) {
            let mut w = World::new();
            let a = w.value(S1, b"to", Label::new(Secrecy::from_bits(s0), i0));
            let b = w.value(S1, b"body", Label::new(Secrecy::from_bits(s1), i1));
            let joined = Label::new(Secrecy::from_bits(s0 | s1), i0.min(i1));

            let expected = if !joined.secrecy.is_subset(Secrecy::EMPTY.with(WORK)) {
                Expected::Egress
            } else if joined.integrity < Integrity::User {
                Expected::Approval
            } else {
                Expected::Run
            };
            let actual = match w.invoke(&Invocation::new(SEND, [a, b])) {
                Ok(Decision::Queued { .. }) => Expected::Run,
                Ok(Decision::NeedsApproval(_)) => Expected::Approval,
                Err(r) if r.reason == Reason::EgressNotCleared => Expected::Egress,
                other => panic!("unexpected {other:?}"),
            };
            prop_assert_eq!(actual, expected);
            prop_assert!(w.fx.calls.is_empty(), "external effects never run before commit");
        }

        #[test]
        fn send_matches_rules_with_context(i0 in integrity(), ic in integrity(), s0 in 0u64..8, sc in 0u64..8) {
            // The session's principal label counts as an input to the call.
            let mut w = World::new();
            let a = w.value(S1, b"to", Label::new(Secrecy::from_bits(s0), i0));
            let b = w.user(b"body");
            let read = w.value(S1, b"cond", Label::new(Secrecy::from_bits(sc), ic));
            w.table.view(S1).read(read).unwrap();
            let joined = Label::new(Secrecy::from_bits(s0 | sc), i0.min(ic));

            let expected = if !joined.secrecy.is_subset(Secrecy::EMPTY.with(WORK)) {
                Expected::Egress
            } else if joined.integrity < Integrity::User {
                Expected::Approval
            } else {
                Expected::Run
            };
            let actual = match w.invoke(&Invocation::new(SEND, [a, b])) {
                Ok(Decision::Queued { .. }) => Expected::Run,
                Ok(Decision::NeedsApproval(_)) => Expected::Approval,
                Err(r) if r.reason == Reason::EgressNotCleared => Expected::Egress,
                other => panic!("unexpected {other:?}"),
            };
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn note_matches_rules(i in integrity(), s in any::<u64>()) {
            let mut w = World::new();
            let h = w.value(S1, b"text", Label::new(Secrecy::from_bits(s), i));
            let d = w.invoke(&Invocation::new(NOTE, [h])).unwrap();
            if i >= Integrity::ThirdParty {
                prop_assert_eq!(d, Decision::Executed(Ok(None)));
                prop_assert_eq!(w.fx.calls.len(), 1);
            } else {
                prop_assert!(matches!(d, Decision::NeedsApproval(_)));
                prop_assert!(w.fx.calls.is_empty());
            }
        }
    }
}
