//! The headless half of the approval app (R3/T5a; the window is T5b).
//!
//! The wire protocol between the runtime and the approval app, the fixed
//! plain-language templates, request batching, the socket transport and the
//! approval key. Models never write approval text, and only the approval app
//! calls [`load_or_create`] or [`approve_item`].

mod batch;
mod keys;
mod templates;
mod transport;
mod wire;

pub use batch::{Batcher, MAX_BATCH};
pub use keys::{KeyError, default_dir, load_or_create, load_public};
pub use templates::{render_refusal, render_request};
pub use transport::{Connection, MAX_FRAME, Server, TransportError, connect, read_frame, socket_name, write_frame};
pub use wire::{
    Message, WireAnswer, WireArg, WireDecision, WireError, WireItem, WireRequest, approve_item, integrity_from_name,
    integrity_name,
};
