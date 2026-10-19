//! The `injection-bench` entry point finds no violations.

#[test]
fn injection_bench_finds_no_violations() {
    let bench = fewshot_harness::bench::run();
    assert_eq!(bench.rows.len(), 7, "scenarios 1 to 6 and the compromised executor");
    let violations: Vec<_> = bench.violations().collect();
    assert!(violations.is_empty(), "{violations:?}\n{bench}");
    assert_eq!(bench.utility_failures().count(), 0, "{bench}");
}
