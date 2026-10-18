//! The planner: turns a user request into a plan, never seeing untrusted bytes.

use crate::{Chat, ChatRequest, HttpChat, OllamaConfig};
use fewshot_executor::{Planner, PlannerError, PlannerInput};
use fewshot_gate::{Effect, ParamKind, Registry};
use fewshot_plan::{PLAN_JSON_SCHEMA, Plan, PlanError};
use serde_json::Value;
use std::fmt::Write as _;

/// Retries after a plan fails to parse or validate.
const RETRIES: usize = 2;

/// The planner's system prompt: the plan DSL.
pub const PLANNER_SYSTEM: &str = r#"You write plans for a personal agent. Reply with one JSON object {"steps":[...]} and nothing else.

Steps:
- {"op":"let","var":V,"text":T}
  Binds V to the literal text T. Use it for values the user gave you: addresses, messages, names.
- {"op":"call","action":ID,"args":[V,...]}
  Calls action ID with one variable per parameter, in parameter order.
- {"op":"read","var":V,"input":X,"schema":{"kind":"text","max_len":N}}
  A reader extracts at most N bytes of text from X into V.
- {"op":"read","var":V,"input":X,"schema":{"kind":"choice","options":[...]}}
  A reader picks one of the options based on X, into V.
- {"op":"for_each","var":V,"list":L,"max":N,"body":[...]}
  Runs body once per item of list L, at most N times (N from 1 to 64), with V bound to the item.
- {"op":"if","var":V,"equals":T,"then":[...],"otherwise":[...]}
  Runs then if V's value is exactly T, otherwise runs otherwise.
- {"op":"checkpoint"}
  Commits the effects so far before continuing.

Rules:
- You never see what inputs contain, only their names and descriptions. To use their content, read them.
- Bind every variable before using it, and bind each name only once. Names bound inside a body or branch exist only there.
- Call only the listed actions, with exactly one argument per parameter.
- For a parameter that lists options, fill it from a choice read with exactly those options, or from a let with one of them.
- Use the simplest plan that does what the user asked, and nothing they did not ask for.
- If a previous attempt failed, the error says which step was wrong. Fix that step."#;

/// Renders what the planner sees as its user message.
pub fn render_input(input: &PlannerInput, error: Option<&str>) -> String {
    let mut s = format!("User request:\n{}\n\nActions:\n", input.request());
    for a in input.actions() {
        let effect = match a.effect {
            Effect::Read => "read only",
            Effect::LocalReversible => "local, reversible",
            Effect::LocalIrreversible => "local, irreversible",
            Effect::External => "external",
        };
        let params: Vec<String> = a
            .params
            .iter()
            .map(|p| match &p.kind {
                ParamKind::Open => p.name.clone(),
                ParamKind::Choice(opts) => {
                    let opts: Vec<String> = opts.iter().map(|o| format!("{:?}", String::from_utf8_lossy(o))).collect();
                    format!("{} (one of {})", p.name, opts.join(", "))
                }
            })
            .collect();
        let _ = writeln!(s, "- id {}: {} ({effect}); params: {}", a.id.0, a.name, params.join(", "));
    }
    s.push_str("\nInputs:\n");
    if input.inputs().is_empty() {
        s.push_str("(none)\n");
    }
    for i in input.inputs() {
        let kind = if i.list { "list" } else { "value" };
        let _ = writeln!(s, "- {} ({kind}): {}", i.var, i.description);
    }
    for f in input.feedback().into_iter().chain(error) {
        let _ = write!(s, "\nPrevious attempt failed: {f}\n");
    }
    s
}

/// A [`Planner`] backed by an Ollama model, constrained to the plan schema.
pub struct OllamaPlanner<C = HttpChat> {
    chat: C,
    model: String,
    registry: Registry,
    format: Value,
}

impl OllamaPlanner<HttpChat> {
    /// A planner over HTTP. Plans are validated against `registry`.
    pub fn from_config(config: &OllamaConfig, registry: Registry) -> Self {
        OllamaPlanner::new(HttpChat::new(config), config.planner_model.clone(), registry)
    }
}

impl<C: Chat> OllamaPlanner<C> {
    /// A planner over any [`Chat`].
    pub fn new(chat: C, model: impl Into<String>, registry: Registry) -> Self {
        let format = serde_json::from_str(PLAN_JSON_SCHEMA).expect("PLAN_JSON_SCHEMA is valid JSON");
        OllamaPlanner { chat, model: model.into(), registry, format }
    }

    /// The underlying chat client.
    pub fn chat(&mut self) -> &mut C {
        &mut self.chat
    }

    /// Only the actions the planner was offered, so a plan calling any other fails validation.
    fn offered(&self, input: &PlannerInput) -> Registry {
        let mut r = Registry::new();
        for a in self.registry.iter().filter(|a| input.actions().iter().any(|s| s.id == a.id)) {
            r.register(a.clone()).expect("ids are unique in the source registry");
        }
        r
    }
}

impl<C: Chat> Planner for OllamaPlanner<C> {
    fn plan(&mut self, input: &PlannerInput) -> Result<Plan, PlannerError> {
        let registry = self.offered(input);
        let names: Vec<&str> = input.inputs().iter().map(|i| i.var.as_str()).collect();
        let mut error: Option<PlanError> = None;
        for _ in 0..=RETRIES {
            let user = render_input(input, error.as_ref().map(|e| e.to_string()).as_deref());
            let req = ChatRequest { model: &self.model, system: PLANNER_SYSTEM, user: &user, format: &self.format };
            let reply = self.chat.chat(&req).map_err(PlannerError::Backend)?;
            match fewshot_plan::parse(&reply).and_then(|p| fewshot_plan::validate(&p, &registry, &names).map(|()| p)) {
                Ok(plan) => return Ok(plan),
                Err(e) => error = Some(e),
            }
        }
        Err(PlannerError::Invalid(error.expect("the loop runs at least once")))
    }
}
