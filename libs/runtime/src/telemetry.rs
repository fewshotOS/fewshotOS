//! Local, opt-in approval-rate telemetry (T7a).
//!
//! Records only when `[runtime] telemetry = true`. Each call is one line in
//! `data_dir/telemetry.jsonl`: exactly `ts` (Unix ms), `client`, `action` and
//! `outcome` (one of `approved`, `denied`, `timeout`, `auto`). Nothing else is
//! kept — no argument values, no paths, no URLs, no handles — and nothing is
//! ever sent anywhere; the file exists so the user can see their own approval
//! rates via the future `fewshot stats` command.
//!
//! [`Telemetry::record`] appends, [`load`] reads the file back, and [`stats`]
//! / [`to_text`] are the pure summary and its exact printable layout.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::Config;

/// What a call ended in, as far as the user's approval is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The user approved the call.
    Approved,
    /// The user declined the call.
    Denied,
    /// The user answered neither before the approval timeout.
    Timeout,
    /// The call ran without asking the user.
    Auto,
}

impl Outcome {
    /// The wire name, as written to the file.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Denied => "denied",
            Outcome::Timeout => "timeout",
            Outcome::Auto => "auto",
        }
    }

    /// The inverse of [`as_str`](Self::as_str); any other name is `None`.
    pub fn parse(s: &str) -> Option<Outcome> {
        match s {
            "approved" => Some(Outcome::Approved),
            "denied" => Some(Outcome::Denied),
            "timeout" => Some(Outcome::Timeout),
            "auto" => Some(Outcome::Auto),
            _ => None,
        }
    }

    /// Whether the user was asked about the call; false only for [`Auto`](Self::Auto).
    pub fn is_prompt(self) -> bool {
        self != Outcome::Auto
    }
}

/// One recorded call. These four fields are everything that is ever recorded:
/// no argument values, no paths, no URLs, no handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Unix time in milliseconds.
    pub ts_ms: u64,
    /// The client name, as configured.
    pub client: String,
    /// The action name.
    pub action: String,
    /// How the call ended.
    pub outcome: Outcome,
}

/// Appends [`Event`]s to the telemetry file when enabled.
pub struct Telemetry {
    path: Option<PathBuf>,
}

impl Telemetry {
    /// From the config: enabled, at `data_dir/telemetry.jsonl`, exactly when
    /// `[runtime] telemetry` is true.
    pub fn from_config(config: &Config) -> Telemetry {
        let path = config.runtime.telemetry.then(|| config.data_dir().join("telemetry.jsonl"));
        Telemetry { path }
    }

    /// A recorder that never writes anything.
    pub fn disabled() -> Telemetry {
        Telemetry { path: None }
    }

    /// Where events are appended, when enabled.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Appends one line for `event`. When disabled this is `Ok(())` and
    /// touches nothing on disk: no file, no directory.
    pub fn record(&self, event: &Event) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        // One object with exactly the four fields, so the strings are escaped
        // the same way `serde_json` reads them back; ends with one newline.
        let line = json!({
            "ts": event.ts_ms,
            "client": event.client.as_str(),
            "action": event.action.as_str(),
            "outcome": event.outcome.as_str(),
        });
        let mut body = serde_json::to_string(&line).expect("objects built by `json!` always serialize to a string");
        body.push('\n');
        file.write_all(body.as_bytes())
    }
}

/// Why reading the telemetry file failed.
#[derive(Debug)]
pub enum TelemetryError {
    /// The file could not be read.
    Io(std::io::Error),
    /// A line is not a valid event.
    BadLine {
        /// The 1-based line number.
        line: usize,
        /// What was wrong with it.
        reason: String,
    },
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelemetryError::Io(e) => write!(f, "telemetry file: {e}"),
            TelemetryError::BadLine { line, reason } => {
                write!(f, "telemetry file: line {line}: {reason}")
            }
        }
    }
}

impl std::error::Error for TelemetryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TelemetryError::Io(e) => Some(e),
            TelemetryError::BadLine { .. } => None,
        }
    }
}

/// Reads the events recorded at `path`, in file order. A missing file is `Ok`
/// and empty: nothing was recorded yet.
pub fn load(path: &Path) -> Result<Vec<Event>, TelemetryError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(TelemetryError::Io(e)),
    };
    let mut events = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let event = event_from_line(line).map_err(|reason| TelemetryError::BadLine { line: i + 1, reason })?;
        events.push(event);
    }
    Ok(events)
}

/// Parses one file line into an [`Event`]; the error is the reason.
fn event_from_line(line: &str) -> Result<Event, String> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("not valid JSON: {e}"))?;
    let obj = value.as_object().ok_or_else(|| "not a JSON object".to_string())?;

    const KEYS: [&str; 4] = ["ts", "client", "action", "outcome"];
    let missing = KEYS.iter().copied().filter(|k| !obj.contains_key(*k)).collect::<Vec<_>>();
    let extra = obj.keys().filter(|k| !KEYS.contains(&k.as_str())).cloned().collect::<Vec<_>>();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(format!("wrong keys: missing {missing:?}, extra {extra:?} (want exactly {KEYS:?})"));
    }

    let ts_ms = obj["ts"].as_u64().ok_or_else(|| "\"ts\" is not a non-negative integer".to_string())?;
    let client = obj["client"].as_str().ok_or_else(|| "\"client\" is not a string".to_string())?.to_string();
    let action = obj["action"].as_str().ok_or_else(|| "\"action\" is not a string".to_string())?.to_string();
    let outcome = Outcome::parse(obj["outcome"].as_str().ok_or_else(|| "\"outcome\" is not a string".to_string())?)
        .ok_or_else(|| "\"outcome\" is not one of approved, denied, timeout, auto".to_string())?;
    Ok(Event { ts_ms, client, action, outcome })
}

/// The per-client summary over the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStats {
    /// The client name.
    pub client: String,
    /// All events, whatever the outcome.
    pub calls: u64,
    /// The events the user was asked about.
    pub prompts: u64,
    /// The events the user approved.
    pub approved: u64,
    /// Distinct clock hours (`ts_ms / 3_600_000`) with at least one event.
    pub active_hours: u64,
}

impl ClientStats {
    /// Prompts divided by active hours; `0.0` without active hours.
    pub fn prompts_per_active_hour(&self) -> f64 {
        if self.active_hours == 0 { 0.0 } else { self.prompts as f64 / self.active_hours as f64 }
    }

    /// Approved divided by prompts; `None` without prompts.
    pub fn approval_rate(&self) -> Option<f64> {
        if self.prompts == 0 { None } else { Some(self.approved as f64 / self.prompts as f64) }
    }
}

/// The whole summary: one [`ClientStats`] per client, and the actions asked
/// about most.
#[derive(Debug, Clone, PartialEq)]
pub struct Stats {
    /// One entry per client, sorted by client name.
    pub clients: Vec<ClientStats>,
    /// Prompts per action, most first (ties by name), at most five.
    pub top_actions: Vec<(String, u64)>,
}

/// Sums the events in `[now_ms − days·24h, now_ms]`, in name order, so the
/// summary is the same on every run.
pub fn stats(events: &[Event], now_ms: u64, days: u64) -> Stats {
    let cutoff = now_ms.saturating_sub(days.saturating_mul(86_400_000));
    let mut per_client: BTreeMap<String, (u64, u64, u64, BTreeSet<u64>)> = BTreeMap::new();
    let mut prompted: BTreeMap<String, u64> = BTreeMap::new();

    for e in events {
        if e.ts_ms < cutoff || e.ts_ms > now_ms {
            continue;
        }
        let (calls, prompts, approved, hours) = per_client.entry(e.client.clone()).or_default();
        *calls += 1;
        if e.outcome.is_prompt() {
            *prompts += 1;
            *prompted.entry(e.action.clone()).or_default() += 1;
        }
        if e.outcome == Outcome::Approved {
            *approved += 1;
        }
        hours.insert(e.ts_ms / 3_600_000);
    }

    let clients = per_client
        .into_iter()
        .map(|(client, (calls, prompts, approved, hours))| ClientStats {
            client,
            calls,
            prompts,
            approved,
            active_hours: hours.len() as u64,
        })
        .collect();
    let mut top_actions = prompted.into_iter().filter(|(_, n)| *n > 0).collect::<Vec<_>>();
    top_actions.sort_by(|(a, na), (b, nb)| nb.cmp(na).then_with(|| a.cmp(b)));
    top_actions.truncate(5);
    Stats { clients, top_actions }
}

/// Renders a [`Stats`] exactly the way the future `fewshot stats` command
/// will print it: two-space indent, one-decimal rates, the approval rate as a
/// whole percent or `-` when there were no prompts.
pub fn to_text(stats: &Stats, days: u64) -> String {
    let mut out = if days == 1 { String::from("last 1 day\n") } else { format!("last {days} days\n") };
    if stats.clients.is_empty() {
        out.push_str("no calls recorded\n");
        return out;
    }
    for c in &stats.clients {
        let rate = c.prompts_per_active_hour();
        let percent =
            c.approval_rate().map(|r| format!("{}%", (r * 100.0).round() as i64)).unwrap_or_else(|| "-".into());
        let client = c.client.clone();
        let calls = c.calls;
        let prompts = c.prompts;
        let active_hours = c.active_hours;
        out.push_str(&format!(
            "{client}: {calls} calls, {prompts} prompts in {active_hours} active hours ({rate:.1}/hour), {percent} approved\n"
        ));
    }
    if !stats.top_actions.is_empty() {
        out.push_str("most prompted:\n");
        for (action, count) in &stats.top_actions {
            out.push_str(&format!("  {action}  {count}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts_ms: u64, client: &str, action: &str, outcome: Outcome) -> Event {
        Event { ts_ms, client: client.into(), action: action.into(), outcome }
    }

    #[test]
    fn outcome_names_round_trip_and_unknown_names_parse_to_none() {
        for o in [Outcome::Approved, Outcome::Denied, Outcome::Timeout, Outcome::Auto] {
            assert_eq!(Outcome::parse(o.as_str()), Some(o), "{o:?}");
        }
        assert_eq!(Outcome::parse("yes"), None);
        assert_eq!(Outcome::parse("APPROVED"), None);
    }

    #[test]
    fn is_prompt_is_true_for_everything_but_auto() {
        for o in [Outcome::Approved, Outcome::Denied, Outcome::Timeout] {
            assert!(o.is_prompt(), "{o:?}");
        }
        assert!(!Outcome::Auto.is_prompt());
    }

    #[test]
    fn stats_counts_all_fields_and_breaks_action_ties_by_name() {
        let now = 90_000_000_000u64;
        let h = 3_600_000u64;
        let events = vec![
            ev(now, "zz", "fs.write", Outcome::Approved),
            ev(now - h, "zz", "fs.write", Outcome::Denied),
            ev(now - 2 * h, "zz", "fs.delete", Outcome::Timeout),
            ev(now - 2 * h + 60_000, "zz", "fs.delete", Outcome::Approved),
            ev(now - h + 1_000, "zz", "notes.append", Outcome::Auto),
            ev(now, "al", "notes.append", Outcome::Auto),
            ev(now - h, "al", "notes.append", Outcome::Auto),
        ];
        let s = stats(&events, now, 7);

        let [auto_only, mixed] = s.clients.as_slice() else { panic!("expected two clients, got {:?}", s.clients) };
        // Auto events count as calls and active hours, never as prompts.
        assert_eq!(auto_only, &ClientStats { client: "al".into(), calls: 2, prompts: 0, approved: 0, active_hours: 2 });
        assert_eq!(auto_only.prompts_per_active_hour(), 0.0);
        assert_eq!(auto_only.approval_rate(), None);

        assert_eq!(mixed, &ClientStats { client: "zz".into(), calls: 5, prompts: 4, approved: 2, active_hours: 3 });
        assert_eq!(mixed.prompts_per_active_hour(), 4.0 / 3.0);
        assert_eq!(mixed.approval_rate(), Some(0.5));

        // fs.delete and fs.write are tied at two prompts; by name, fs.delete is first.
        assert_eq!(s.top_actions, vec![("fs.delete".into(), 2), ("fs.write".into(), 2)]);
        assert!(!s.top_actions.iter().any(|(a, _)| a == "notes.append"), "actions with no prompts stay out");
    }

    #[test]
    fn stats_counts_only_events_inside_the_window() {
        let now = 90_000_000_000u64;
        let cutoff = now - 7 * 86_400_000;
        let events = vec![
            ev(cutoff - 1, "c", "fs.write", Outcome::Approved), // older than the window
            ev(cutoff, "c", "fs.write", Outcome::Approved),     // boundary, in
            ev(now + 1, "c", "fs.write", Outcome::Approved),    // after now, out
            ev(now, "c", "fs.write", Outcome::Approved),        // boundary, in
        ];
        let s = stats(&events, now, 7);
        let [c] = s.clients.as_slice() else { panic!("expected one client, got {:?}", s.clients) };
        assert_eq!(c.calls, 2);
        assert_eq!(c.prompts, 2);
        assert_eq!(c.approved, 2);
        assert_eq!(s.top_actions, vec![("fs.write".into(), 2)]);

        // A ridiculous span of days must not overflow; it widens to all history.
        let wide = stats(&events, now, u64::MAX);
        let [w] = wide.clients.as_slice() else { panic!("expected one client, got {:?}", wide.clients) };
        assert_eq!(w.calls, 3, "with a zero cutoff the oldest event is in");
        assert_eq!(w.prompts, 3);
    }

    #[test]
    fn to_text_matches_the_exact_layout() {
        let s = Stats {
            clients: vec![ClientStats {
                client: "claude-code".into(),
                calls: 12,
                prompts: 4,
                approved: 3,
                active_hours: 3,
            }],
            top_actions: vec![("fs.write".into(), 3), ("fs.delete".into(), 1)],
        };
        assert_eq!(
            to_text(&s, 7),
            "last 7 days\nclaude-code: 12 calls, 4 prompts in 3 active hours (1.3/hour), 75% approved\nmost prompted:\n  fs.write  3\n  fs.delete  1\n"
        );
    }

    #[test]
    fn to_text_empty_is_just_the_header_and_a_notice() {
        let empty = Stats { clients: Vec::new(), top_actions: Vec::new() };
        assert_eq!(to_text(&empty, 7), "last 7 days\nno calls recorded\n");
        assert_eq!(to_text(&empty, 1), "last 1 day\nno calls recorded\n");
    }

    #[test]
    fn to_text_omits_the_most_prompted_block_and_dashes_without_prompts() {
        let s = Stats {
            clients: vec![ClientStats { client: "al".into(), calls: 2, prompts: 0, approved: 0, active_hours: 2 }],
            top_actions: Vec::new(),
        };
        assert_eq!(to_text(&s, 30), "last 30 days\nal: 2 calls, 0 prompts in 2 active hours (0.0/hour), - approved\n");
    }
}
