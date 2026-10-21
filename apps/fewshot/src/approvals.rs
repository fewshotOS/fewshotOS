//! Asking the approval app (T5) for a decision, blocking until it answers.
//!
//! The server holds no signing key: it sends the gate's request, rendered
//! through the fixed templates, and gets back a signature or a refusal.

use fewshot_approval::{Message, WireAnswer, WireItem, WireRequest, connect, socket_name};
use fewshot_gate::SignedApproval;
use std::sync::mpsc;
use std::time::Duration;

/// What became of one approval request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The user approved; retry the call with this.
    Approved(SignedApproval),
    /// The user declined.
    Denied,
    /// No answer within the timeout.
    Timeout,
    /// The approval app could not be reached or answered nonsense.
    Unavailable(String),
}

/// Something that can ask the user. [`SocketApprovals`] in production.
pub trait Approvals {
    /// Asks about one item for `client` and waits for the answer.
    fn ask(&mut self, client: &str, item: WireItem) -> Answer;
}

/// Asks the approval app over its local socket, one request per item.
///
/// Calls are answered one at a time, so there is nothing to batch: each
/// `tools/call` blocks until its own approval is decided.
pub struct SocketApprovals {
    name: String,
    timeout: Duration,
    next_id: u64,
}

impl SocketApprovals {
    /// The current user's approval app, waiting at most `timeout` per request.
    pub fn new(timeout: Duration) -> Self {
        SocketApprovals::with_name(socket_name(), timeout)
    }

    /// An approval app listening on `name` (tests use their own name).
    pub fn with_name(name: impl Into<String>, timeout: Duration) -> Self {
        SocketApprovals { name: name.into(), timeout, next_id: 1 }
    }
}

/// How to start the approval app, for error messages.
pub const START_HINT: &str = "start the approval app with `fewshot-approve` and try again";

impl Approvals for SocketApprovals {
    fn ask(&mut self, client: &str, item: WireItem) -> Answer {
        let id = self.next_id;
        self.next_id += 1;
        let digest = item.digest.clone();
        let request = WireRequest { id, client: client.into(), items: vec![item] };
        let name = self.name.clone();
        // The socket read cannot time out on every platform, so the exchange
        // runs on its own thread. On a timeout that thread is left to end
        // when the approval app answers or closes.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(exchange(&name, request));
        });
        let answer = match rx.recv_timeout(self.timeout) {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => return Answer::Unavailable(e),
            Err(_) => return Answer::Timeout,
        };
        if answer.id != id || answer.decisions.len() != 1 {
            return Answer::Unavailable("the approval app answered a different request".into());
        }
        let decision = &answer.decisions[0];
        if decision.digest() != digest {
            return Answer::Unavailable("the approval app answered about a different call".into());
        }
        match decision.to_signed() {
            Ok(Some(a)) => Answer::Approved(a),
            Ok(None) => Answer::Denied,
            Err(e) => Answer::Unavailable(e.to_string()),
        }
    }
}

/// Connects, exchanges `Hello`, sends the request and waits for its answer.
fn exchange(name: &str, request: WireRequest) -> Result<WireAnswer, String> {
    let mut conn = connect(name).map_err(|e| format!("the approval app is not running ({e}); {START_HINT}"))?;
    match conn.recv().map_err(|e| e.to_string())? {
        Message::Hello { version: 1 } => {}
        other => return Err(format!("unexpected first message from the approval app: {other:?}")),
    }
    conn.send(&Message::Hello { version: 1 }).map_err(|e| e.to_string())?;
    conn.send(&Message::Request(request)).map_err(|e| e.to_string())?;
    loop {
        match conn.recv().map_err(|e| e.to_string())? {
            Message::Answer(a) => return Ok(a),
            Message::Hello { .. } => {}
            Message::Request(_) => return Err("the approval app sent a request".into()),
        }
    }
}
