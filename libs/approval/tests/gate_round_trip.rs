//! A gate approval request, rendered, sent as a wire item, signed by the
//! app's key and checked by a real gate.

use fewshot_approval::{WireDecision, WireItem, approve_item, load_or_create, load_public, render_request};
use fewshot_gate::{ActionId, ActionSpec, CapSet, Decision, Effect, Effects, Gate, Invocation, Param, Registry};
use fewshot_host::ManualClock;
use fewshot_labeld::{Integrity, Label, Secrecy, SessionId, ValueTable};

const NOTE: ActionId = ActionId(1);
const S: SessionId = SessionId(1);

struct Ok;

impl Effects for Ok {
    fn run(
        &mut self,
        _: &ActionSpec,
        _: &[&[u8]],
        _: &fewshot_gate::AuditEntry,
    ) -> Result<Vec<u8>, fewshot_gate::EffectError> {
        Result::Ok(Vec::new())
    }
}

#[test]
fn an_item_signed_by_the_app_key_is_accepted_once() {
    let dir = tempfile::tempdir().unwrap();
    let approver = load_or_create(dir.path()).unwrap();
    let spec = ActionSpec {
        id: NOTE,
        name: "notes.append".into(),
        effect: Effect::LocalReversible,
        integrity_floor: Integrity::User,
        egress_clearance: Secrecy::EMPTY,
        params: vec![Param::open("text")],
        draft_for: None,
        compensation: None,
        output: None,
    };
    let mut registry = Registry::new();
    registry.register(spec.clone()).unwrap();
    let clock = ManualClock::new(1_000);
    let mut gate = Gate::new(registry, load_public(dir.path()).unwrap(), &clock);
    gate.open_session(S, CapSet::new([NOTE]));
    let (mut table, ingress) = ValueTable::new();
    let text = table
        .intern(&ingress, S, b"hi".to_vec(), Label::new(Secrecy::EMPTY, Integrity::ThirdParty), "literal:c")
        .unwrap();
    let inv = Invocation::new(NOTE, [text]);

    let Result::Ok(Decision::NeedsApproval(req)) = gate.invoke(&table, S, &inv, &mut Ok) else {
        panic!("expected an approval request")
    };
    let item = WireItem::from_request(&req, &spec.name, render_request(&req, &spec));
    assert!(item.text.starts_with("Add text (text from literal:c — untrusted)"));

    let decision = approve_item(&approver, &item, 60_000).unwrap();
    let json = serde_json::to_string(&decision).unwrap();
    let signed = serde_json::from_str::<WireDecision>(&json).unwrap().to_signed().unwrap().unwrap();

    let approved = inv.clone().with_approval(signed);
    assert_eq!(gate.invoke(&table, S, &approved, &mut Ok), Result::Ok(Decision::Executed(Result::Ok(None))));
    assert!(gate.invoke(&table, S, &approved, &mut Ok).is_err(), "single use");
}
