//! Scenario 7: a compromised executor with only a session view and the gate
//! cannot launder tainted bytes into a clean-looking call.

use fewshot_harness::scenarios;
use fewshot_harness::{End, Rule, Trick, run_compromised};

#[test]
fn every_trick_is_stopped() {
    for s in scenarios::compromised_targets() {
        for trick in Trick::ALL {
            let run = run_compromised(&s, trick, false);
            assert_eq!(run.violations, vec![], "{} / {}", s.name, trick.name());
            assert!(run.effects.is_empty(), "{} / {}", s.name, trick.name());
            let expected = if trick == Trick::ForeignHandles || s.name == "exfiltration" {
                End::Refused
            } else {
                End::NeedsApproval
            };
            assert_eq!(run.end, expected, "{} / {}", s.name, trick.name());
        }
    }
}

#[test]
fn oracle_sees_laundered_bytes_the_user_approves() {
    // Control: approved, the laundered call runs, and the oracle reports the
    // attacker's goal and the tainted argument.
    for s in scenarios::compromised_targets().into_iter().filter(|s| s.name != "exfiltration") {
        for trick in [Trick::RawInputs, Trick::DeriveEmptyAfterRead, Trick::DeriveFromClean] {
            let run = run_compromised(&s, trick, true);
            assert_eq!(run.end, End::Completed, "{} / {}", s.name, trick.name());
            let rules: Vec<_> = run.violations.iter().map(|v| &v.rule).collect();
            assert!(rules.contains(&&Rule::AttackerGoal), "{} / {}: {rules:?}", s.name, trick.name());
            assert!(
                rules.iter().any(|r| matches!(r, Rule::BelowIntegrityFloor { .. })),
                "{} / {}: {rules:?}",
                s.name,
                trick.name()
            );
        }
    }
}

#[test]
fn compromised_executor_uses_no_trusted_table_api() {
    let src = include_str!("../src/compromised.rs");
    for forbidden in [".resolve(", ".intern(", "Ingress", "ValueTable", "Gate"] {
        let code = src.lines().filter(|l| !l.trim_start().starts_with("//"));
        assert!(code.clone().all(|l| !l.contains(forbidden)), "compromised.rs uses {forbidden}");
    }
}
