//! Local, opt-in telemetry (T7a): nothing when off, round trips when on,
//! rejects bad lines, and the module carries no network code.

use fewshot_runtime::Config;
use fewshot_runtime::telemetry::{Event, Outcome, Telemetry, TelemetryError, load};
use std::path::Path;

/// A config with `data_dir` set, and `[runtime] telemetry` as `value` —
/// `None` omits the key entirely, like the config file never had it.
fn config(data: &Path, value: Option<bool>) -> Config {
    let telemetry = value.map(|b| format!("telemetry = {b}\n")).unwrap_or_default();
    Config::parse(&format!("[runtime]\ndata_dir = '{}'\n{telemetry}", data.display())).unwrap()
}

#[test]
fn nothing_is_written_when_telemetry_is_off() {
    // telemetry = false, and the key absent.
    for value in [Some(false), None] {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let tel = Telemetry::from_config(&config(&data, value));
        assert!(tel.path().is_none(), "{value:?}: nothing to write, so no path");

        for ts in [1u64, 2, 3] {
            tel.record(&Event {
                ts_ms: ts,
                client: "claude-code".into(),
                action: "fs.write".into(),
                outcome: Outcome::Approved,
            })
            .unwrap();
        }

        if data.exists() {
            let names: Vec<_> =
                std::fs::read_dir(&data).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
            assert!(
                !names.iter().any(|n| n == "telemetry.jsonl"),
                "{value:?}: the data dir must not hold the log; contains {names:?}"
            );
        }
        assert!(!data.join("telemetry.jsonl").exists(), "{value:?}");
    }

    let tel = Telemetry::disabled();
    assert!(tel.path().is_none());
}

#[test]
fn events_round_trip_through_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let tel = Telemetry::from_config(&config(&data, Some(true)));
    let path = tel.path().expect("telemetry on: a path").to_path_buf();

    // A client name with a quote and a backslash must survive escaping.
    let client = "the \"quoted\" C:\\log";
    let event = |ts_ms: u64, action: &str, outcome: Outcome| Event {
        ts_ms,
        client: client.into(),
        action: action.into(),
        outcome,
    };
    let events = vec![
        event(1_000, "fs.write", Outcome::Approved),
        event(2_000, "fs.delete", Outcome::Denied),
        event(3_000, "notes.append", Outcome::Auto),
    ];
    for e in &events {
        tel.record(e).unwrap();
    }

    assert_eq!(load(&path).expect("the file we just wrote loads"), events, "load returns them, in order");

    let raw = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(lines.len(), 3, "exactly three lines in the file: {raw:?}");

    for (i, line) in lines.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is one JSON object");
        let obj = v.as_object().expect("each line is one JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        let want: std::collections::BTreeSet<&str> = ["action", "client", "outcome", "ts"].into_iter().collect();
        assert_eq!(keys, want, "line {}: exactly the four keys, no more, no less", i + 1);
        let e = &events[i];
        assert_eq!(obj.get("ts"), Some(&serde_json::json!(e.ts_ms)));
        assert_eq!(obj.get("client"), Some(&serde_json::json!(e.client)), "quotes and backslashes survive");
        assert_eq!(obj.get("action"), Some(&serde_json::json!(e.action)));
        assert_eq!(obj.get("outcome"), Some(&serde_json::json!(e.outcome.as_str())));
    }
    assert_eq!(load(&path).unwrap(), events);
}

#[test]
fn load_rejects_bad_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let good = serde_json::json!({ "ts": 5, "client": "c", "action": "fs.write", "outcome": "approved" });
    // An extra key "path": precisely the kind of thing the log must not carry.
    let bad = serde_json::json!({ "ts": 6, "client": "c", "action": "fs.write", "outcome": "auto", "path": "/x" });
    let path = tmp.path().join("telemetry.jsonl");
    std::fs::write(&path, format!("{good}\n{bad}\n")).unwrap();

    let err = load(&path).expect_err("a line with an extra key is a BadLine");
    match err {
        TelemetryError::BadLine { line, reason } => {
            assert_eq!(line, 2, "the second line is the bad one; reason: {reason:?}");
            assert!(reason.contains("path"), "the reason names the extra key; got {reason:?}");
        }
        other => panic!("expected BadLine, got {other:?}"),
    }

    // A missing file loads as empty, not as an error.
    let missing = tmp.path().join("never-recorded.jsonl");
    assert_eq!(load(&missing).expect("a missing file is empty, not an error"), Vec::<Event>::new());
}

/// The module must stay local: no transport code of any kind.
#[test]
fn the_telemetry_module_has_no_network_code() {
    let src = include_str!("../src/telemetry.rs");
    for word in ["std::net", "ureq", "TcpStream", "UdpSocket", "Socket", "http"] {
        assert!(!src.contains(word), "telemetry.rs mentions {word:?}");
    }
}
