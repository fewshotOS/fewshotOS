//! The `fewshot` command (R3): `fewshot mcp` serves one MCP client over
//! stdio on the Fewshot runtime.
//!
//! This crate holds no approval signing key. Approvals come from the separate
//! approval app (`fewshot-approve`) over its local socket; a source test checks
//! that nothing here or in `fewshot-runtime` can sign one.

pub mod approvals;
pub mod mcp;

pub use approvals::{Answer, Approvals, SocketApprovals};
pub use mcp::Server;
