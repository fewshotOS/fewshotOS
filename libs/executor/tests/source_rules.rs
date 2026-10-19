//! Only `src/host.rs` may bring values into the table or look at them
//! without a session read. Everything else goes through `SessionView`.

use std::fs;
use std::path::Path;

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn only_host_rs_calls_resolve_or_intern() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(files.iter().any(|f| f.ends_with("lib.rs")), "found the crate sources");
    let mut offenders = Vec::new();
    for file in files.iter().filter(|f| !f.ends_with("host.rs")) {
        for (n, line) in fs::read_to_string(file).unwrap().lines().enumerate() {
            if line.contains(".resolve(") || line.contains(".intern(") {
                offenders.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(offenders.is_empty(), "resolve/intern outside src/host.rs:\n{}", offenders.join("\n"));
}
