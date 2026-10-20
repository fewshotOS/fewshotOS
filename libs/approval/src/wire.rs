//! Messages between the runtime and the approval app.
//!
//! These are wire copies of gate types: the gate stays `no_std` and
//! serde-free, so the conversions are written here and checked to be exact
//! inverses.

use fewshot_gate::{ActionId, ApprovalRequest, Approver, ArgSummary, Digest, Nonce, SignedApproval};
use fewshot_labeld::{Integrity, Label, Secrecy, SessionId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// One argument, as the approval app shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireArg {
    /// Parameter name.
    pub param: String,
    /// Where the value came from.
    pub origin: String,
    /// Integrity name, e.g. `untrusted_web`.
    pub integrity: String,
    /// Secrecy tag bits.
    pub secrecy: u64,
    /// Whether this argument is why approval is needed.
    pub below_floor: bool,
}

/// One invocation awaiting approval, with its fixed-template text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireItem {
    /// Invocation digest, 64 lowercase hex digits.
    pub digest: String,
    /// The gate's nonce for this request.
    pub nonce: u64,
    /// Requesting session.
    pub session: u64,
    /// Action id.
    pub action: u32,
    /// Action name, e.g. `fs.write`.
    pub action_name: String,
    /// Per-argument facts.
    pub args: Vec<WireArg>,
    /// Integrity name of the session's principal label.
    pub context_integrity: String,
    /// Secrecy bits of the session's principal label.
    pub context_secrecy: u64,
    /// Whether the context is why approval is needed.
    pub context_below_floor: bool,
    /// Plain-language text from [`crate::render_request`].
    pub text: String,
}

/// A batch of items from one client, shown as one decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRequest {
    /// Request id, echoed in the answer.
    pub id: u64,
    /// Client name, e.g. `claude-code`.
    pub client: String,
    /// The items, each signed separately if approved.
    pub items: Vec<WireItem>,
}

/// The user's decision on one item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WireDecision {
    /// Signed over the item's digest, nonce and expiry.
    Approved {
        /// Approved digest, 64 hex digits.
        digest: String,
        /// The request's nonce.
        nonce: u64,
        /// Not valid after this time.
        expires_at_ms: u64,
        /// Ed25519 signature, 128 hex digits.
        signature: String,
    },
    /// The user declined.
    Denied {
        /// Declined digest.
        digest: String,
        /// The request's nonce.
        nonce: u64,
    },
}

/// The answer to a [`WireRequest`]: one decision per item, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAnswer {
    /// The request's id.
    pub id: u64,
    /// One decision per item.
    pub decisions: Vec<WireDecision>,
}

/// Everything that crosses the socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// First message on a connection, from either side.
    Hello {
        /// Protocol version, currently 1.
        version: u32,
    },
    /// From the runtime: items to decide.
    Request(WireRequest),
    /// From the approval app: the decisions.
    Answer(WireAnswer),
}

/// A wire value did not convert back to a gate value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError(pub String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "approval wire: {}", self.0)
    }
}

impl std::error::Error for WireError {}

/// The wire name of an integrity level.
pub fn integrity_name(i: Integrity) -> &'static str {
    match i {
        Integrity::UntrustedWeb => "untrusted_web",
        Integrity::UntrustedLegacy => "untrusted_legacy",
        Integrity::ThirdParty => "third_party",
        Integrity::Bounded => "bounded",
        Integrity::SystemApp => "system_app",
        Integrity::User => "user",
    }
}

/// The integrity level of a wire name.
pub fn integrity_from_name(name: &str) -> Result<Integrity, WireError> {
    Ok(match name {
        "untrusted_web" => Integrity::UntrustedWeb,
        "untrusted_legacy" => Integrity::UntrustedLegacy,
        "third_party" => Integrity::ThirdParty,
        "bounded" => Integrity::Bounded,
        "system_app" => Integrity::SystemApp,
        "user" => Integrity::User,
        other => return Err(WireError(format!("unknown integrity {other:?}"))),
    })
}

impl WireItem {
    /// The wire form of a gate request.
    pub fn from_request(req: &ApprovalRequest, action_name: &str, text: String) -> WireItem {
        WireItem {
            digest: hex(&req.digest.0),
            nonce: req.nonce.0,
            session: req.session.0,
            action: req.action.0,
            action_name: action_name.into(),
            args: req
                .args
                .iter()
                .map(|a| WireArg {
                    param: a.param.clone(),
                    origin: a.origin.clone(),
                    integrity: integrity_name(a.label.integrity).into(),
                    secrecy: a.label.secrecy.bits(),
                    below_floor: a.below_floor,
                })
                .collect(),
            context_integrity: integrity_name(req.context.integrity).into(),
            context_secrecy: req.context.secrecy.bits(),
            context_below_floor: req.context_below_floor,
            text,
        }
    }

    /// The gate request this item was made from.
    pub fn to_request(&self) -> Result<ApprovalRequest, WireError> {
        let args = self
            .args
            .iter()
            .map(|a| {
                Ok(ArgSummary {
                    param: a.param.clone(),
                    label: Label::new(Secrecy::from_bits(a.secrecy), integrity_from_name(&a.integrity)?),
                    origin: a.origin.clone(),
                    below_floor: a.below_floor,
                })
            })
            .collect::<Result<_, WireError>>()?;
        Ok(ApprovalRequest {
            digest: Digest(unhex(&self.digest)?),
            nonce: Nonce(self.nonce),
            session: SessionId(self.session),
            action: ActionId(self.action),
            args,
            context: Label::new(
                Secrecy::from_bits(self.context_secrecy),
                integrity_from_name(&self.context_integrity)?,
            ),
            context_below_floor: self.context_below_floor,
        })
    }
}

impl WireDecision {
    /// The wire form of a signed approval.
    pub fn approved(a: &SignedApproval) -> WireDecision {
        WireDecision::Approved {
            digest: hex(&a.digest.0),
            nonce: a.nonce.0,
            expires_at_ms: a.expires_at_ms,
            signature: hex(&a.signature),
        }
    }

    /// The signed approval, or `None` if the user declined.
    pub fn to_signed(&self) -> Result<Option<SignedApproval>, WireError> {
        match self {
            WireDecision::Denied { .. } => Ok(None),
            WireDecision::Approved { digest, nonce, expires_at_ms, signature } => Ok(Some(SignedApproval {
                digest: Digest(unhex(digest)?),
                nonce: Nonce(*nonce),
                expires_at_ms: *expires_at_ms,
                signature: unhex(signature)?,
            })),
        }
    }

    /// The digest this decision is about.
    pub fn digest(&self) -> &str {
        match self {
            WireDecision::Approved { digest, .. } | WireDecision::Denied { digest, .. } => digest,
        }
    }
}

/// Signs `item` as approved. Only the approval app holds an [`Approver`].
pub fn approve_item(approver: &Approver, item: &WireItem, expires_at_ms: u64) -> Result<WireDecision, WireError> {
    Ok(WireDecision::approved(&approver.approve(&item.to_request()?, expires_at_ms)))
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exactly `N` bytes from hex.
pub(crate) fn unhex<const N: usize>(s: &str) -> Result<[u8; N], WireError> {
    if s.len() != 2 * N || !s.is_ascii() {
        return Err(WireError(format!("expected {} hex digits, got {s:?}", 2 * N)));
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| WireError(e.to_string()))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            digest: Digest([0xa5; 32]),
            nonce: Nonce(9),
            session: SessionId(4),
            action: ActionId(3),
            args: vec![
                ArgSummary {
                    param: "path".into(),
                    label: Label::new(Secrecy::from_bits(0b110), Integrity::ThirdParty),
                    origin: "literal:claude-code".into(),
                    below_floor: true,
                },
                ArgSummary {
                    param: "content".into(),
                    label: Label::new(Secrecy::EMPTY, Integrity::UntrustedWeb),
                    origin: "action:http.get".into(),
                    below_floor: false,
                },
            ],
            context: Label::new(Secrecy::from_bits(1), Integrity::UntrustedWeb),
            context_below_floor: true,
        }
    }

    #[test]
    fn items_round_trip_exactly() {
        let req = request();
        let item = WireItem::from_request(&req, "fs.write", "text".into());
        assert_eq!(item.to_request().unwrap(), req);
        let json = serde_json::to_string(&Message::Request(WireRequest {
            id: 1,
            client: "c".into(),
            items: vec![item.clone()],
        }))
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Message>(&json).unwrap(),
            Message::Request(WireRequest { id: 1, client: "c".into(), items: vec![item] })
        );
    }

    #[test]
    fn every_integrity_name_round_trips() {
        for i in [
            Integrity::UntrustedWeb,
            Integrity::UntrustedLegacy,
            Integrity::ThirdParty,
            Integrity::Bounded,
            Integrity::SystemApp,
            Integrity::User,
        ] {
            assert_eq!(integrity_from_name(integrity_name(i)), Ok(i));
        }
        assert!(integrity_from_name("root").is_err());
    }

    #[test]
    fn decisions_round_trip() {
        let a = SignedApproval { digest: Digest([1; 32]), nonce: Nonce(2), expires_at_ms: 3, signature: [4; 64] };
        let d = WireDecision::approved(&a);
        assert_eq!(d.to_signed().unwrap(), Some(a));
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"decision\":\"approved\""));
        assert_eq!(serde_json::from_str::<WireDecision>(&json).unwrap(), d);
        assert_eq!(WireDecision::Denied { digest: hex(&[1; 32]), nonce: 2 }.to_signed().unwrap(), None);
    }

    #[test]
    fn bad_hex_is_an_error() {
        let mut item = WireItem::from_request(&request(), "fs.write", String::new());
        item.digest = "zz".repeat(32);
        assert!(item.to_request().is_err());
        item.digest = "é".repeat(32);
        assert!(item.to_request().is_err());
    }
}
