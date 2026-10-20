//! The planner: turns a user request into a plan, never seeing untrusted bytes.

use crate::{Chat, ChatRequest, HttpChat, OllamaConfig};
use fewshot_executor::{Planner, PlannerError, PlannerInput};
use fewshot_gate::{Effect, ParamKind, Registry};
use fewshot_plan::{Plan, PlanError, Step};
use serde_json::{Value, json};
use std::fmt::Write as _;

/// Retries after a plan fails to parse, validate or lint.
const RETRIES: usize = 2;

/// The planner's system prompt: the plan DSL and one worked example.
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

Example. Request: "Put each receipt into the food folder or the travel folder."
Action: id 9, receipts.file (folder: one of "food","travel"). Inputs: receipts (list).
{"steps":[{"op":"for_each","var":"receipt","list":"receipts","max":64,"body":[{"op":"read","var":"folder","input":"receipt","schema":{"kind":"choice","options":["food","travel"]}},{"op":"call","action":9,"args":["folder"]}]}]}

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
            Effect::Fetch => "remote read",
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

/// Check a plan that already passed [`fewshot_plan::validate`], for things a
/// model can do better even when the plan is valid: a plan that calls no
/// action when actions were offered, and `let`s that nobody reads.
/// `offered_actions` is how many actions the planner was offered.
pub fn lint(plan: &Plan, offered_actions: usize) -> Result<(), String> {
    if offered_actions > 0 && !has_call(&plan.steps) {
        return Err("the plan calls no action; the request needs at least one call".to_string());
    }
    lint_steps(&plan.steps)
}

/// Whether `steps`, at any depth, contain a `call`.
fn has_call(steps: &[Step]) -> bool {
    steps.iter().any(|s| match s {
        Step::Call { .. } => true,
        Step::ForEach { body, .. } => has_call(body),
        Step::If { then, otherwise, .. } => has_call(then) || has_call(otherwise),
        _ => false,
    })
}

/// Reject a `let` that no later step in the same block reads.
fn lint_steps(steps: &[Step]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        match step {
            Step::Let { var, .. } if !used_after(steps, i, var) => {
                return Err(format!("`{var}` is bound but never used; remove it"));
            }
            Step::ForEach { body, .. } => lint_steps(body)?,
            Step::If { then, otherwise, .. } => {
                lint_steps(then)?;
                lint_steps(otherwise)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Whether `var` is read by a step after index `i` of `steps`, including
/// inside blocks that later step holds.
fn used_after(steps: &[Step], i: usize, var: &str) -> bool {
    steps[i + 1..].iter().any(|s| reads(s, var))
}

/// Whether `step` reads `var` itself, or anywhere in a block it holds.
fn reads(step: &Step, var: &str) -> bool {
    match step {
        Step::Call { args, .. } => args.iter().any(|a| a == var),
        Step::Read { input, .. } => input == var,
        Step::ForEach { list, body, .. } => list == var || body.iter().any(|s| reads(s, var)),
        Step::If { var: name, then, otherwise, .. } => {
            name == var || then.iter().any(|s| reads(s, var)) || otherwise.iter().any(|s| reads(s, var))
        }
        _ => false,
    }
}

/// A failed attempt: a plan that did not parse or validate, or one the linter
/// rejected.
enum Fail {
    /// The plan did not parse or validate.
    Invalid(PlanError),
    /// The plan validated but the linter rejected it.
    Lint(String),
}

impl Fail {
    /// The text fed back to the model on the next attempt.
    fn message(&self) -> String {
        match self {
            Fail::Invalid(e) => e.to_string(),
            Fail::Lint(m) => m.clone(),
        }
    }
}

/// The `format` sent to Ollama: a JSON object holding a `steps` array, no
/// more. Ollama orders each object's properties alphabetically when it turns
/// a schema into a grammar, so under [`fewshot_plan::PLAN_JSON_SCHEMA`] only
/// `let` and `checkpoint` (where `op` sorts first) can follow the `{"op":`
/// a model writes first, and plans never contain a call. Step shapes are
/// checked by `validate` and [`lint`] instead, with errors fed back.
pub const PLANNER_FORMAT: &str = r#"{"type":"object","required":["steps"],"properties":{"steps":{"type":"array","maxItems":32,"items":{"type":"object"}}}}"#;

/// The planner's sampling options, with a repeat penalty against long
/// degenerate step-repetition loops.
fn planner_options(config: &OllamaConfig) -> Value {
    json!({ "temperature": config.temperature, "seed": config.seed, "repeat_penalty": 1.1, "num_predict": 2048 })
}

/// A [`Planner`] backed by an Ollama model; its plans are validated and linted.
pub struct OllamaPlanner<C = HttpChat> {
    chat: C,
    model: String,
    registry: Registry,
    format: Value,
    options: Value,
}

impl OllamaPlanner<HttpChat> {
    /// A planner over HTTP. Plans are validated against `registry`.
    pub fn from_config(config: &OllamaConfig, registry: Registry) -> Self {
        OllamaPlanner::with_config(HttpChat::new(config), config.planner_model.clone(), registry, config)
    }
}

impl<C: Chat> OllamaPlanner<C> {
    /// A planner over any [`Chat`], with the default sampling options.
    pub fn new(chat: C, model: impl Into<String>, registry: Registry) -> Self {
        OllamaPlanner::with_config(chat, model, registry, &OllamaConfig::default())
    }

    fn with_config(chat: C, model: impl Into<String>, registry: Registry, config: &OllamaConfig) -> Self {
        let format = serde_json::from_str(PLANNER_FORMAT).expect("PLANNER_FORMAT is valid JSON");
        OllamaPlanner { chat, model: model.into(), registry, format, options: planner_options(config) }
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
        let offered = input.actions().len();
        let mut error: Option<Fail> = None;
        for _ in 0..=RETRIES {
            let user = render_input(input, error.as_ref().map(Fail::message).as_deref());
            let req = ChatRequest {
                model: &self.model,
                system: PLANNER_SYSTEM,
                user: &user,
                format: &self.format,
                options: &self.options,
            };
            let reply = self.chat.chat(&req).map_err(PlannerError::Backend)?;
            let plan = match fewshot_plan::parse(&reply)
                .and_then(|p| fewshot_plan::validate(&p, &registry, &names).map(|()| p))
            {
                Ok(plan) => plan,
                Err(e) => {
                    error = Some(Fail::Invalid(e));
                    continue;
                }
            };
            match lint(&plan, offered) {
                Ok(()) => return Ok(plan),
                Err(message) => error = Some(Fail::Lint(message)),
            }
        }
        Err(match error.expect("the loop runs at least once") {
            Fail::Invalid(e) => PlannerError::Invalid(e),
            Fail::Lint(message) => PlannerError::Lint(message),
        })
    }
}
