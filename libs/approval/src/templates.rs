//! Fixed plain-language text for approvals and refusals (ARCHITECTURE §6.1).
//!
//! Every sentence here is fixed and filled only from gate data: parameter
//! names, origins and labels. The gate sends no argument values, and models
//! never write approval text.

use fewshot_gate::{ActionSpec, ApprovalError, ApprovalRequest, Reason, Refusal};

/// The approval text for one request.
pub fn render_request(req: &ApprovalRequest, spec: &ActionSpec) -> String {
    let arg = |name: &str| {
        req.args
            .iter()
            .find(|a| a.param == name)
            .map(|a| {
                let untrusted = if a.below_floor { " — untrusted" } else { "" };
                format!("{} from {}{untrusted}", a.param, a.origin)
            })
            .unwrap_or_else(|| name.to_string())
    };
    let mut text = match spec.name.as_str() {
        "fs.write" => format!("Overwrite a file ({}) with new content ({}).", arg("path"), arg("content")),
        "fs.restore" => format!("Restore a file ({}) from a saved copy.", arg("path")),
        "fs.delete" => format!("Move a file ({}) to the Fewshot trash.", arg("path")),
        "notes.append" => format!("Add text ({}) to your Fewshot notes.", arg("text")),
        "http.get" => format!("Fetch a web page ({}).", arg("url")),
        "fs.read" => format!("Read a file ({}).", arg("path")),
        "fs.list" => format!("List a folder ({}).", arg("dir")),
        other => {
            let args: Vec<String> = spec.params.iter().map(|p| arg(&p.name)).collect();
            format!("Run {other} with {}.", args.join(", "))
        }
    };
    if req.context_below_floor {
        text.push_str(" This request came after the agent read untrusted content.");
    }
    text.push_str(" Approve only if you asked for this.");
    text
}

/// The text for a refusal. `action_name` is `None` when the action is unknown.
pub fn render_refusal(refusal: &Refusal, action_name: Option<&str>) -> String {
    let action = action_name.unwrap_or("this action");
    match refusal.reason {
        Reason::UnknownSession => "This agent's session has ended, so nothing ran.".into(),
        Reason::UnknownAction => format!("{action} does not exist, so nothing ran."),
        Reason::MissingCapability => format!("This agent is not allowed to use {action}."),
        Reason::WrongArity => format!("{action} was called with the wrong number of values, so nothing ran."),
        Reason::UnknownHandle => format!("{action} was given a value from another session, so nothing ran."),
        Reason::EgressNotCleared => format!("{action} would send data that is not allowed to leave this device."),
        Reason::ApprovalInvalid(e) => match e {
            ApprovalError::UnknownNonce | ApprovalError::DigestMismatch => {
                "The approval did not match this exact request, so nothing ran.".into()
            }
            ApprovalError::Reused => "That approval was already used, so nothing ran.".into(),
            ApprovalError::Expired => "That approval expired before it was used, so nothing ran.".into(),
            ApprovalError::BadSignature => "That approval was not signed by the Fewshot approval app.".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fewshot_gate::{ActionId, ArgSummary, Digest, Effect, Grantor, Nonce, Param};
    use fewshot_labeld::{Integrity, Label, Secrecy, SessionId};

    fn spec(name: &str, params: &[&str]) -> ActionSpec {
        ActionSpec {
            id: ActionId(1),
            name: name.into(),
            effect: Effect::LocalReversible,
            integrity_floor: Integrity::SystemApp,
            egress_clearance: Secrecy::EMPTY,
            params: params.iter().map(|p| Param::open(*p)).collect(),
            draft_for: None,
            compensation: None,
            output: None,
        }
    }

    fn request(params: &[&str], below: bool, context_below: bool) -> ApprovalRequest {
        ApprovalRequest {
            digest: Digest([0; 32]),
            nonce: Nonce(1),
            session: SessionId(1),
            action: ActionId(1),
            args: params
                .iter()
                .map(|p| ArgSummary {
                    param: (*p).into(),
                    label: Label::new(Secrecy::EMPTY, Integrity::ThirdParty),
                    origin: "literal:claude-code".into(),
                    below_floor: below,
                })
                .collect(),
            context: Label::TOP,
            context_below_floor: context_below,
        }
    }

    #[test]
    fn built_in_actions_use_their_templates() {
        for (name, params, starts) in [
            ("fs.write", &["path", "content"][..], "Overwrite a file (path from literal:claude-code)"),
            ("fs.restore", &["path", "content"][..], "Restore a file"),
            ("fs.delete", &["path"][..], "Move a file"),
            ("notes.append", &["text"][..], "Add text"),
            ("http.get", &["url"][..], "Fetch a web page"),
            ("fs.read", &["path"][..], "Read a file"),
            ("fs.list", &["dir"][..], "List a folder"),
        ] {
            let text = render_request(&request(params, false, false), &spec(name, params));
            assert!(text.starts_with(starts), "{name}: {text}");
            assert!(text.ends_with("Approve only if you asked for this."));
            assert!(!text.contains('{'));
        }
    }

    #[test]
    fn untrusted_arguments_and_context_are_called_out() {
        let text = render_request(&request(&["text"], true, true), &spec("notes.append", &["text"]));
        assert!(text.contains("text from literal:claude-code — untrusted"));
        assert!(text.contains("after the agent read untrusted content"));
    }

    #[test]
    fn other_actions_list_every_parameter() {
        let text = render_request(&request(&["to", "body"], false, false), &spec("mail.send", &["to", "body"]));
        assert!(text.starts_with("Run mail.send with to from literal:claude-code, body from literal:claude-code."));
    }

    #[test]
    fn every_refusal_has_text() {
        let mut reasons = vec![
            Reason::UnknownSession,
            Reason::UnknownAction,
            Reason::MissingCapability,
            Reason::WrongArity,
            Reason::UnknownHandle,
            Reason::EgressNotCleared,
        ];
        reasons.extend(
            [
                ApprovalError::UnknownNonce,
                ApprovalError::Reused,
                ApprovalError::Expired,
                ApprovalError::BadSignature,
                ApprovalError::DigestMismatch,
            ]
            .map(Reason::ApprovalInvalid),
        );
        for reason in reasons {
            let r = Refusal { reason, detail: String::new(), remedy: String::new(), grantor: Grantor::None };
            for name in [Some("fs.write"), None] {
                let text = render_refusal(&r, name);
                assert!(!text.is_empty() && !text.contains('{'), "{reason:?}");
            }
        }
    }
}
