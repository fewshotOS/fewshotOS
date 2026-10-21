//! Length-prefixed JSON frames over a local socket (a Unix domain socket,
//! or a named pipe on Windows).
//!
//! On a host OS any process running as the user can connect here; the socket
//! carries requests and signatures, never the signing key
//! (docs/LIMITATIONS.md).

use crate::Message;
use interprocess::local_socket::{GenericFilePath, GenericNamespaced, ListenerOptions, Name, Stream, prelude::*};
use std::fmt;
use std::io::{self, Read, Write};

/// Largest frame accepted.
pub const MAX_FRAME: usize = 1 << 20;

/// Why a frame could not be sent or received.
#[derive(Debug)]
pub enum TransportError {
    /// The socket failed.
    Io(io::Error),
    /// A frame exceeds [`MAX_FRAME`].
    TooLarge(usize),
    /// A frame is not a valid [`Message`].
    Json(serde_json::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "approval socket: {e}"),
            TransportError::TooLarge(n) => write!(f, "approval socket: frame of {n} bytes exceeds {MAX_FRAME}"),
            TransportError::Json(e) => write!(f, "approval socket: bad message: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// Writes one frame: a 4-byte big-endian length, then the JSON.
pub fn write_frame<W: Write>(w: &mut W, msg: &Message) -> Result<(), TransportError> {
    let body = serde_json::to_vec(msg).map_err(TransportError::Json)?;
    if body.len() > MAX_FRAME {
        return Err(TransportError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame written by [`write_frame`].
pub fn read_frame<R: Read>(r: &mut R) -> Result<Message, TransportError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(TransportError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(TransportError::Json)
}

/// The socket name for the current user.
pub fn socket_name() -> String {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "default".into());
    format!("fewshot-approval-{user}")
}

fn to_name(name: &str) -> io::Result<Name<'static>> {
    if GenericNamespaced::is_supported() {
        name.to_string().to_ns_name::<GenericNamespaced>()
    } else {
        std::env::temp_dir().join(format!("{name}.sock")).to_fs_name::<GenericFilePath>()
    }
}

/// One connection, either side.
pub struct Connection(Stream);

impl Connection {
    /// Sends a message.
    pub fn send(&mut self, msg: &Message) -> Result<(), TransportError> {
        write_frame(&mut self.0, msg)
    }

    /// Waits for the next message.
    pub fn recv(&mut self) -> Result<Message, TransportError> {
        read_frame(&mut self.0)
    }
}

/// The approval app's listening socket.
pub struct Server(interprocess::local_socket::Listener);

impl Server {
    /// Listens on `name`.
    pub fn bind(name: &str) -> Result<Server, TransportError> {
        Ok(Server(ListenerOptions::new().name(to_name(name)?).try_overwrite(true).create_sync()?))
    }

    /// Waits for the next connection.
    pub fn accept(&self) -> Result<Connection, TransportError> {
        Ok(Connection(self.0.accept()?))
    }
}

/// Connects to the approval app listening on `name`.
pub fn connect(name: &str) -> Result<Connection, TransportError> {
    Ok(Connection(Stream::connect(to_name(name)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WireAnswer, WireDecision, WireRequest};
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Message::Hello { version: 1 }).unwrap();
        write_frame(&mut buf, &Message::Answer(WireAnswer { id: 3, decisions: vec![] })).unwrap();
        let mut r = Cursor::new(buf);
        assert_eq!(read_frame(&mut r).unwrap(), Message::Hello { version: 1 });
        assert_eq!(read_frame(&mut r).unwrap(), Message::Answer(WireAnswer { id: 3, decisions: vec![] }));
    }

    #[test]
    fn oversize_frames_are_refused_before_reading() {
        let mut r = Cursor::new(((MAX_FRAME + 1) as u32).to_be_bytes().to_vec());
        assert!(matches!(read_frame(&mut r), Err(TransportError::TooLarge(_))));
    }

    #[test]
    fn a_request_and_answer_cross_a_real_socket() {
        let name = format!("fewshot-approval-test-{}-{}", std::process::id(), line!());
        let server = Server::bind(&name).unwrap();
        let handle = std::thread::spawn(move || {
            let mut conn = server.accept().unwrap();
            let Message::Request(req) = conn.recv().unwrap() else { panic!("expected a request") };
            let decisions =
                req.items.iter().map(|i| WireDecision::Denied { digest: i.digest.clone(), nonce: i.nonce }).collect();
            conn.send(&Message::Answer(WireAnswer { id: req.id, decisions })).unwrap();
        });
        let mut conn = connect(&name).unwrap();
        conn.send(&Message::Request(WireRequest { id: 7, client: "test".into(), items: vec![] })).unwrap();
        assert_eq!(conn.recv().unwrap(), Message::Answer(WireAnswer { id: 7, decisions: vec![] }));
        handle.join().unwrap();
    }
}
