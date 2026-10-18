//! With a hijacked reader and a user who denies every approval, no attack
//! in scenarios 1 to 3 produces a violating effect.

use fewshot_harness::scenarios;
use fewshot_harness::{End, Rule, run_attack, run_attack_with, run_deny_all};

#[test]
fn deny_all_finds_no_violations() {
    for s in scenarios::all() {
        let report = run_deny_all(&s);
        assert!(report.attacks > 0, "{}: has attacks", s.name);
        assert_eq!(report.violations, vec![], "{}", s.name);
        assert_eq!(
            report.needs_approval + report.refused,
            report.attacks,
            "{}: every attack was stopped: {report:?}",
            s.name
        );
    }
}

#[test]
fn every_attack_reaches_the_gate_with_attacker_bytes() {
    // Guard against vacuous passes: each attack must get far enough to ask
    // for approval of the dangerous call, not fail earlier.
    for s in scenarios::all() {
        for a in &s.attacks {
            let (end, _) = run_attack(&s, a);
            assert_eq!(end, End::NeedsApproval, "{} / {}", s.name, a.name);
        }
    }
}

#[test]
fn harmless_immediate_effects_still_run() {
    // The doc-wipe attack appends a note before trying the delete: the note
    // runs (notes.append accepts third-party data), the delete does not.
    let s = scenarios::doc_wipe();
    let (end, violations) = run_attack(&s, &s.attacks[1]);
    assert_eq!(end, End::NeedsApproval);
    assert!(violations.is_empty());
}

#[test]
fn oracle_sees_attacks_the_user_approves() {
    // Control: if the user approved everything, every attack would run
    // tainted effects, and the oracle must report them.
    for s in scenarios::all() {
        for a in &s.attacks {
            let (end, violations) = run_attack_with(&s, a, true);
            assert_eq!(end, End::Completed, "{} / {}", s.name, a.name);
            if a.implicit_flow {
                continue;
            }
            assert!(
                violations.iter().any(|v| matches!(v.rule, Rule::BelowIntegrityFloor { .. })),
                "{} / {}: {violations:?}",
                s.name,
                a.name
            );
        }
    }
}
