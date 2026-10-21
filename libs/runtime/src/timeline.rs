//! The audit timeline (T6a): gate entries as a human-readable log.
//!
//! Pure functions with no I/O: [`render`] turns entries into lines,
//! [`format_time`] turns Unix milliseconds into a UTC wall time without any
//! date crate, [`to_text`] joins lines into printable text, and the filters
//! keep a session's or a day's lines. The `fewshot audit` command (T6b) and
//! the approval app's Audit tab render through these same functions.

use fewshot_gate::{ApprovalError, AuditEntry, AuditKind, Reason};

/// One rendered line of the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The entry's `at_ms`.
    pub at_ms: u64,
    /// The entry's session id.
    pub session: u64,
    /// The human-readable text for that entry.
    pub text: String,
}

/// Renders `entries`, one [`Line`] per entry in the same order. `action_name`
/// resolves an action id to its name (pass a lookup over a registry); an
/// id it returns `None` for shows as `action <id>`.
pub fn render(entries: &[AuditEntry], action_name: impl Fn(u32) -> Option<String>) -> Vec<Line> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let name = e
            .action
            .map(|a| action_name(a.0).unwrap_or_else(|| format!("action {}", a.0)))
            .unwrap_or_else(|| "-".into());
        let d8 = e.digest.map(|d| hex8(&d.0)).unwrap_or_else(|| "-".into());
        let text = match e.kind {
            AuditKind::SessionOpened => "session opened".to_string(),
            AuditKind::SessionClosed => "session closed".to_string(),
            AuditKind::Refused(r) => {
                if e.action.is_some() {
                    format!("refused {}: {}", name, reason_text(r))
                } else {
                    format!("refused: {}", reason_text(r))
                }
            }
            AuditKind::ApprovalRequested(_) => format!("asked you to approve {} ({})", name, d8),
            AuditKind::Queued => format!("queued {} until commit ({})", name, d8),
            AuditKind::EffectStarted => format!("started {} ({})", name, d8),
            AuditKind::EffectSucceeded => format!("done {} ({})", name, d8),
            AuditKind::EffectReturned(h) => format!("done {}, returned data {} ({})", name, hex8(&h), d8),
            AuditKind::EffectFailed => format!("failed {} ({})", name, d8),
            AuditKind::OutboxDropped(n) => format!("dropped {} queued effect(s) unrun", n),
        };
        out.push(Line { at_ms: e.at_ms, session: e.session.0, text });
    }
    out
}

/// Formats Unix milliseconds as UTC `YYYY-MM-DD HH:MM:SS`, using Howard
/// Hinnant's `civil_from_days` instead of a date crate.
pub fn format_time(at_ms: u64) -> String {
    let days = at_ms / 86_400_000;
    let secs = (at_ms % 86_400_000) / 1_000;
    let (hour, min, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// Joins rendered lines into printable text, one
/// `<time>  s<session>  <text>` line each.
pub fn to_text(lines: &[Line]) -> String {
    lines.iter().map(|l| format!("{}  s{}  {}\n", format_time(l.at_ms), l.session, l.text)).collect()
}

/// Keeps only the lines of one session.
pub fn filter_session(mut lines: Vec<Line>, session: u64) -> Vec<Line> {
    lines.retain(|l| l.session == session);
    lines
}

/// Keeps only the lines whose [`format_time`] date is `day` (`YYYY-MM-DD`).
pub fn filter_day(mut lines: Vec<Line>, day: &str) -> Vec<Line> {
    lines.retain(|l| format_time(l.at_ms).get(..10) == Some(day));
    lines
}

/// The first eight lowercase hex characters of a digest.
fn hex8(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(8);
    for b in bytes.iter().take(4) {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// User-facing text for a refusal. Exhaustive over [`Reason`] and
/// [`ApprovalError`]: a new variant fails to compile here until mapped.
fn reason_text(r: Reason) -> &'static str {
    match r {
        Reason::UnknownSession => "unknown session",
        Reason::UnknownAction => "unknown action",
        Reason::MissingCapability => "not allowed",
        Reason::WrongArity => "wrong number of arguments",
        Reason::UnknownHandle => "value from another session",
        Reason::EgressNotCleared => "data not cleared to leave the device",
        Reason::ApprovalInvalid(a) => match a {
            ApprovalError::UnknownNonce => "approval not issued for this call",
            ApprovalError::Reused => "approval already used",
            ApprovalError::Expired => "approval expired",
            ApprovalError::BadSignature => "approval not signed by the approval app",
            ApprovalError::DigestMismatch => "approval did not match the call",
        },
    }
}

/// Inverse of proleptic-Gregorian day counting: `days` since 1970-01-01 into
/// `(year, month 1-12, day 1-31)`. Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let mut y = yoe + era * 400;
    if m <= 2 {
        y += 1;
    }
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fewshot_gate::{ActionId, Digest, Nonce};
    use fewshot_labeld::SessionId;

    #[test]
    fn format_time_known_instants_are_exact() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00");
        assert_eq!(format_time(951_782_400_000), "2000-02-29 00:00:00");
        assert_eq!(format_time(1_760_918_400_000), "2025-10-20 00:00:00");
        assert_eq!(format_time(4_102_444_799_000), "2099-12-31 23:59:59");
    }

    fn entry(kind: AuditKind, action: Option<ActionId>, digest: Option<Digest>) -> AuditEntry {
        AuditEntry {
            seq: 0,
            at_ms: 1_000,
            session: SessionId(1),
            action,
            digest,
            kind,
            prev: [0u8; 32],
            hash: [0u8; 32],
        }
    }

    #[test]
    fn every_kind_and_reason_renders_brace_free_text() {
        let name = |id: u32| (id == 1).then(|| "doc.fetch".into());
        let approval_errors = [
            ApprovalError::UnknownNonce,
            ApprovalError::Reused,
            ApprovalError::Expired,
            ApprovalError::BadSignature,
            ApprovalError::DigestMismatch,
        ];
        let mut reasons = vec![
            Reason::UnknownSession,
            Reason::UnknownAction,
            Reason::MissingCapability,
            Reason::WrongArity,
            Reason::UnknownHandle,
            Reason::EgressNotCleared,
        ];
        reasons.extend(approval_errors.map(Reason::ApprovalInvalid));
        let mut kinds = vec![
            AuditKind::SessionOpened,
            AuditKind::ApprovalRequested(Nonce(42)),
            AuditKind::EffectStarted,
            AuditKind::Queued,
            AuditKind::EffectSucceeded,
            AuditKind::EffectReturned([0x5c; 32]),
            AuditKind::EffectFailed,
            AuditKind::OutboxDropped(u32::MAX),
            AuditKind::SessionClosed,
        ];
        kinds.extend(reasons.into_iter().map(AuditKind::Refused));
        for kind in kinds {
            // with and without an action and a digest; and one action the
            // lookup does not know.
            for (action, digest) in
                [(None, None), (Some(ActionId(1)), Some(Digest([0xfe; 32]))), (Some(ActionId(999)), None)]
            {
                let text = render(&[entry(kind, action, digest)], name)[0].text.clone();
                assert!(!text.contains('{'), "{kind:?} -> {text:?}");
            }
        }
    }

    #[test]
    fn unknown_action_ids_render_with_their_number() {
        let name = |id: u32| (id == 7).then(|| "doc.fetch".into());
        let known = entry(AuditKind::EffectSucceeded, Some(ActionId(7)), None);
        let unknown = entry(AuditKind::EffectSucceeded, Some(ActionId(42)), None);
        let refused = entry(AuditKind::Refused(Reason::WrongArity), Some(ActionId(42)), None);
        let lines = render(&[known, unknown, refused], name);
        assert!(lines[0].text.contains("done doc.fetch"), "{}", lines[0].text);
        assert!(lines[1].text.contains("action 42"), "{}", lines[1].text);
        assert!(lines[2].text.starts_with("refused action 42:"), "{}", lines[2].text);
    }

    #[test]
    fn filters_keep_only_matching_lines() {
        let lines = vec![
            Line { at_ms: 0, session: 1, text: "a".into() },
            Line { at_ms: 951_782_400_000, session: 2, text: "b".into() },
            Line { at_ms: 1_760_918_400_000, session: 1, text: "c".into() },
        ];
        let by_session = filter_session(lines.clone(), 1);
        assert_eq!(by_session.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), vec!["a", "c"]);
        let by_day = filter_day(lines, "2025-10-20");
        assert_eq!(by_day.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), vec!["c"]);
    }

    #[test]
    fn to_text_layout_is_time_then_session_then_text() {
        let lines = vec![Line { at_ms: 0, session: 3, text: "session opened".into() }];
        assert_eq!(to_text(&lines), "1970-01-01 00:00:00  s3  session opened\n");
    }
}
