//! Prints the injection benchmark table. Exits 1 if any violation is found.

use std::process::ExitCode;

fn main() -> ExitCode {
    let bench = fewshot_harness::bench::run();
    print!("{bench}");
    let mut failed = false;
    for (scenario, v) in bench.violations() {
        eprintln!("VIOLATION in {scenario}: {v:?}");
        failed = true;
    }
    for scenario in bench.utility_failures() {
        eprintln!("note: the honest run of {scenario} did not produce the expected effects");
    }
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
