//! Requests waiting for the user, and turning decisions into signed answers.
//! All approval logic lives here so it is tested without a window.

use fewshot_approval::{WireAnswer, WireDecision, WireError, WireRequest, approve_item};
use fewshot_gate::Approver;
use std::sync::mpsc::Sender;

/// How long a signed approval stays valid.
pub const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;

/// One request from a runtime, with the user's choices so far.
pub struct Pending {
    /// The request as received.
    pub request: WireRequest,
    /// `Some(true)` approved, `Some(false)` denied, `None` undecided; one per item.
    pub choices: Vec<Option<bool>>,
    reply: Sender<WireAnswer>,
}

/// Every request waiting for the user. Holds the signing key.
pub struct Inbox {
    approver: Approver,
    pending: Vec<Pending>,
}

impl Inbox {
    /// An empty inbox that signs with `approver`.
    pub fn new(approver: Approver) -> Self {
        Inbox { approver, pending: Vec::new() }
    }

    /// Adds a request; its answer goes to `reply` once every item is decided.
    pub fn add(&mut self, request: WireRequest, reply: Sender<WireAnswer>) {
        if request.items.is_empty() {
            let _ = reply.send(WireAnswer { id: request.id, decisions: Vec::new() });
            return;
        }
        let choices = vec![None; request.items.len()];
        self.pending.push(Pending { request, choices, reply });
    }

    /// Requests still waiting, oldest first.
    pub fn pending(&self) -> &[Pending] {
        &self.pending
    }

    /// Records the user's choice for one item, and answers the request once
    /// every item has a choice.
    pub fn decide(&mut self, request: usize, item: usize, approve: bool, now_ms: u64) -> Result<(), WireError> {
        let Some(p) = self.pending.get_mut(request) else { return Ok(()) };
        if let Some(c) = p.choices.get_mut(item) {
            *c = Some(approve);
        }
        self.finish(request, now_ms)
    }

    /// Records the same choice for every undecided item of a request.
    pub fn decide_all(&mut self, request: usize, approve: bool, now_ms: u64) -> Result<(), WireError> {
        let Some(p) = self.pending.get_mut(request) else { return Ok(()) };
        for c in p.choices.iter_mut().filter(|c| c.is_none()) {
            *c = Some(approve);
        }
        self.finish(request, now_ms)
    }

    fn finish(&mut self, request: usize, now_ms: u64) -> Result<(), WireError> {
        if self.pending[request].choices.iter().any(Option::is_none) {
            return Ok(());
        }
        let p = self.pending.remove(request);
        let decisions = p
            .request
            .items
            .iter()
            .zip(&p.choices)
            .map(|(item, choice)| match choice {
                Some(true) => approve_item(&self.approver, item, now_ms + APPROVAL_TTL_MS),
                _ => Ok(WireDecision::Denied { digest: item.digest.clone(), nonce: item.nonce }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The runtime may have given up waiting; nothing else to do then.
        let _ = p.reply.send(WireAnswer { id: p.request.id, decisions });
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use fewshot_approval::WireItem;
    use std::sync::mpsc::channel;

    pub(crate) fn item(nonce: u64) -> WireItem {
        WireItem {
            digest: format!("{nonce:064x}"),
            nonce,
            session: 1,
            action: 6,
            action_name: "notes.append".into(),
            args: vec![],
            context_integrity: "user".into(),
            context_secrecy: 0,
            context_below_floor: false,
            text: "Add text (text from literal:c). Approve only if you asked for this.".into(),
        }
    }

    fn request(id: u64, n: u64) -> WireRequest {
        WireRequest { id, client: "claude-code".into(), items: (1..=n).map(item).collect() }
    }

    #[test]
    fn an_answer_waits_for_every_item() {
        let mut inbox = Inbox::new(Approver::from_secret([7; 32]));
        let (tx, rx) = channel();
        inbox.add(request(1, 2), tx);
        inbox.decide(0, 0, true, 1_000).unwrap();
        assert!(rx.try_recv().is_err());
        assert_eq!(inbox.pending().len(), 1);
        inbox.decide(0, 1, false, 1_000).unwrap();
        let answer = rx.try_recv().unwrap();
        assert!(inbox.pending().is_empty());
        let signed = answer.decisions[0].to_signed().unwrap().unwrap();
        assert_eq!(signed.nonce.0, 1);
        assert_eq!(signed.expires_at_ms, 1_000 + APPROVAL_TTL_MS);
        assert_eq!(answer.decisions[1], WireDecision::Denied { digest: item(2).digest, nonce: 2 });
    }

    #[test]
    fn decide_all_fills_only_undecided_items() {
        let mut inbox = Inbox::new(Approver::from_secret([7; 32]));
        let (tx, rx) = channel();
        inbox.add(request(4, 3), tx);
        inbox.decide(0, 1, false, 0).unwrap();
        inbox.decide_all(0, true, 0).unwrap();
        let d = rx.try_recv().unwrap().decisions;
        assert!(matches!(d[0], WireDecision::Approved { .. }));
        assert!(matches!(d[1], WireDecision::Denied { .. }));
        assert!(matches!(d[2], WireDecision::Approved { .. }));
    }

    #[test]
    fn an_empty_request_is_answered_at_once() {
        let mut inbox = Inbox::new(Approver::from_secret([7; 32]));
        let (tx, rx) = channel();
        inbox.add(request(9, 0), tx);
        assert_eq!(rx.try_recv().unwrap(), WireAnswer { id: 9, decisions: vec![] });
        assert!(inbox.pending().is_empty());
    }
}
