//! The injection benchmark behind the `injection-bench` binary.

use crate::compromised::Trick;
use crate::oracle::Violation;
use crate::run::{Report, honest_utility, run_compromised, run_deny_all, run_honest};
use crate::scenarios;
use std::fmt;

/// One row of the benchmark table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Scenario name.
    pub scenario: String,
    /// Deny-all results.
    pub report: Report,
    /// Approval prompts in approve-honest mode, if the scenario has one.
    pub honest_prompts: Option<usize>,
    /// Whether approve-honest mode produced the expected effects.
    pub honest_ok: Option<bool>,
}

/// Every row, plus each violation with the scenario it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bench {
    /// The table rows: scenarios 1 to 6, then the compromised executor.
    pub rows: Vec<Row>,
}

impl Bench {
    /// Every violation, with its scenario.
    pub fn violations(&self) -> impl Iterator<Item = (&str, &Violation)> {
        self.rows.iter().flat_map(|r| r.report.violations.iter().map(move |v| (r.scenario.as_str(), v)))
    }

    /// Scenarios whose honest run did not produce the expected effects.
    pub fn utility_failures(&self) -> impl Iterator<Item = &str> {
        self.rows.iter().filter(|r| r.honest_ok == Some(false)).map(|r| r.scenario.as_str())
    }
}

/// Runs every scenario in deny-all and approve-honest mode, then the
/// compromised executor against scenarios 1 to 4.
pub fn run() -> Bench {
    let mut rows = Vec::new();
    for s in scenarios::all() {
        let honest = run_honest(&s);
        rows.push(Row {
            scenario: s.name.into(),
            report: run_deny_all(&s),
            honest_prompts: Some(honest.prompts),
            honest_ok: Some(honest_utility(&s, &honest)),
        });
    }
    let mut report = Report::default();
    for s in scenarios::compromised_targets() {
        for trick in Trick::ALL {
            let run = run_compromised(&s, trick, false);
            report.add(run.end, run.violations);
        }
    }
    rows.push(Row { scenario: "compromised executor".into(), report, honest_prompts: None, honest_ok: None });
    Bench { rows }
}

impl fmt::Display for Bench {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "| scenario | attacks tried | violations | refused | needs-approval (denied) | failed | completed | honest-mode prompts |"
        )?;
        writeln!(f, "|---|---:|---:|---:|---:|---:|---:|---:|")?;
        for r in &self.rows {
            let honest = match (r.honest_prompts, r.honest_ok) {
                (Some(p), Some(true)) => p.to_string(),
                (Some(p), _) => format!("{p} (wrong effects)"),
                _ => "n/a".into(),
            };
            let x = &r.report;
            writeln!(
                f,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                r.scenario,
                x.attacks,
                x.violations.len(),
                x.refused,
                x.needs_approval,
                x.failed,
                x.completed,
                honest
            )?;
        }
        Ok(())
    }
}
