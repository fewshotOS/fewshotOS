//! Accepts runtime connections and feeds their requests to the [`Inbox`].

use crate::inbox::Inbox;
use fewshot_approval::{Connection, Message, Server, TransportError};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

/// Protocol version sent in `Hello`.
pub const VERSION: u32 = 1;

/// Serves `server` forever, one thread per connection. `notify` is called
/// whenever a request arrives (the window uses it to repaint).
pub fn serve(server: Server, inbox: Arc<Mutex<Inbox>>, notify: impl Fn() + Send + Clone + 'static) {
    loop {
        match server.accept() {
            Ok(conn) => {
                let (inbox, notify) = (inbox.clone(), notify.clone());
                std::thread::spawn(move || {
                    if let Err(e) = handle(conn, &inbox, &notify) {
                        eprintln!("fewshot-approve: connection closed: {e}");
                    }
                });
            }
            Err(e) => eprintln!("fewshot-approve: accept failed: {e}"),
        }
    }
}

fn handle(mut conn: Connection, inbox: &Mutex<Inbox>, notify: &impl Fn()) -> Result<(), TransportError> {
    conn.send(&Message::Hello { version: VERSION })?;
    loop {
        let msg = match conn.recv() {
            Ok(m) => m,
            // The runtime hung up between requests: a normal close.
            Err(TransportError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        match msg {
            Message::Request(req) => {
                let (tx, rx) = channel();
                inbox.lock().expect("inbox lock").add(req, tx);
                notify();
                // Blocks until the user has decided every item.
                let Ok(answer) = rx.recv() else { return Ok(()) };
                conn.send(&Message::Answer(answer))?;
            }
            Message::Hello { .. } => {}
            Message::Answer(_) => eprintln!("fewshot-approve: ignoring an answer sent to the approval app"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox::tests::item;
    use fewshot_approval::{WireDecision, WireRequest, connect};
    use fewshot_gate::Approver;

    #[test]
    fn a_runtime_gets_signed_decisions_over_the_socket() {
        let name = format!("fewshot-approve-test-{}", std::process::id());
        let server = Server::bind(&name).unwrap();
        let inbox = Arc::new(Mutex::new(Inbox::new(Approver::from_secret([7; 32]))));
        let shared = inbox.clone();
        std::thread::spawn(move || serve(server, shared, || {}));

        let mut conn = connect(&name).unwrap();
        assert_eq!(conn.recv().unwrap(), Message::Hello { version: VERSION });
        conn.send(&Message::Request(WireRequest { id: 5, client: "c".into(), items: vec![item(1), item(2)] })).unwrap();

        // Stand in for the user.
        loop {
            let mut inbox = inbox.lock().unwrap();
            if !inbox.pending().is_empty() {
                inbox.decide(0, 0, true, 0).unwrap();
                inbox.decide(0, 1, false, 0).unwrap();
                break;
            }
            drop(inbox);
            std::thread::yield_now();
        }
        let Message::Answer(answer) = conn.recv().unwrap() else { panic!("expected an answer") };
        assert_eq!(answer.id, 5);
        assert!(answer.decisions[0].to_signed().unwrap().is_some());
        assert!(matches!(answer.decisions[1], WireDecision::Denied { nonce: 2, .. }));
    }
}
