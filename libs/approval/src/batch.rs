//! Batching: related requests from one session become one decision
//! (ARCHITECTURE §6.1). Pure logic; the caller passes the time in.

use crate::WireItem;
use std::collections::BTreeMap;

/// Most items in one batch.
pub const MAX_BATCH: usize = 20;

/// Groups items by session until a session has been quiet for the window.
#[derive(Debug)]
pub struct Batcher {
    window_ms: u64,
    open: BTreeMap<u64, Open>,
    full: Vec<(u64, Vec<WireItem>)>,
}

#[derive(Debug)]
struct Open {
    last_ms: u64,
    items: Vec<WireItem>,
}

impl Batcher {
    /// A batcher that waits `window_ms` after a session's last item.
    pub fn new(window_ms: u64) -> Self {
        Batcher { window_ms, open: BTreeMap::new(), full: Vec::new() }
    }

    /// Adds an item to its session's open batch. A full batch is closed and
    /// becomes due at once.
    pub fn push(&mut self, item: WireItem, now_ms: u64) {
        let session = item.session;
        let open = self.open.entry(session).or_insert_with(|| Open { last_ms: now_ms, items: Vec::new() });
        if open.items.len() == MAX_BATCH {
            let items = std::mem::take(&mut open.items);
            self.full.push((session, items));
        }
        open.last_ms = now_ms;
        open.items.push(item);
    }

    /// Removes and returns every batch that is due: full ones first, then each
    /// session quiet for the window, in session order.
    pub fn due(&mut self, now_ms: u64) -> Vec<(u64, Vec<WireItem>)> {
        let mut out = std::mem::take(&mut self.full);
        let quiet: Vec<u64> = self
            .open
            .iter()
            .filter(|(_, o)| now_ms.saturating_sub(o.last_ms) >= self.window_ms)
            .map(|(&s, _)| s)
            .collect();
        for s in quiet {
            let o = self.open.remove(&s).expect("listed above");
            out.push((s, o.items));
        }
        out
    }

    /// Whether anything is waiting.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty() && self.full.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(session: u64, nonce: u64) -> WireItem {
        WireItem {
            digest: "00".repeat(32),
            nonce,
            session,
            action: 1,
            action_name: "notes.append".into(),
            args: vec![],
            context_integrity: "user".into(),
            context_secrecy: 0,
            context_below_floor: false,
            text: String::new(),
        }
    }

    fn nonces(batch: &[WireItem]) -> Vec<u64> {
        batch.iter().map(|i| i.nonce).collect()
    }

    #[test]
    fn items_close_together_form_one_batch() {
        let mut b = Batcher::new(2_000);
        b.push(item(1, 1), 0);
        b.push(item(1, 2), 1_000);
        assert!(b.due(2_500).is_empty(), "the window restarts at each push");
        let due = b.due(3_000);
        assert_eq!(due.len(), 1);
        assert_eq!(nonces(&due[0].1), [1, 2]);
        assert!(b.is_empty());
    }

    #[test]
    fn sessions_are_batched_separately() {
        let mut b = Batcher::new(2_000);
        b.push(item(2, 1), 0);
        b.push(item(1, 2), 0);
        let due = b.due(2_000);
        assert_eq!(due.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn nothing_is_due_inside_the_window() {
        let mut b = Batcher::new(2_000);
        b.push(item(1, 1), 0);
        assert!(b.due(1_999).is_empty());
        assert!(!b.is_empty());
    }

    #[test]
    fn batches_hold_at_most_twenty_items() {
        let mut b = Batcher::new(2_000);
        for n in 0..21 {
            b.push(item(1, n), 0);
        }
        let first = b.due(0);
        assert_eq!(first.len(), 1, "the full batch is due at once");
        assert_eq!(first[0].1.len(), MAX_BATCH);
        let rest = b.due(2_000);
        assert_eq!(nonces(&rest[0].1), [20]);
    }
}
