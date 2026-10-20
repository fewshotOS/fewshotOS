//! The plan DSL (docs/ARCHITECTURE.md §5.3).
//!
//! A [`Plan`] is JSON so a local model can produce it under a JSON-schema
//! constraint (see [`PLAN_JSON_SCHEMA`]); there is no text syntax. [`parse`]
//! turns model output into the [`Plan`] AST, and [`validate`] statically
//! rejects plans that reference unknown actions, mismatch arities, use or
//! rebind variables incorrectly, loop too far, nest too deep, or grow past
//! the step budget. Errors carry the step they point at (for example
//! `steps[2].body[0]: unknown variable "x"`) so a model can read the message
//! and repair its plan.
//!
//! `ForEach` bodies and `If` branches are blocks: names bound inside one
//! (including the loop variable) are visible only within it, and may not
//! shadow a name from an enclosing scope.
//!
//! Nothing in this crate executes a plan: it only shapes and checks it.
#![no_std]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use fewshot_gate::{ActionId, Registry};
use serde::{Deserialize, Serialize};

/// Largest allowed `ForEach.max`.
pub const MAX_LOOP: u32 = 64;
/// Maximum number of `ForEach`/`If` blocks a step may be nested inside.
pub const MAX_DEPTH: usize = 4;
/// Maximum total number of steps in a plan, with each loop counted once.
pub const MAX_STEPS: usize = 256;
/// Maximum steps in one block: the top-level `steps`, or a `body`,
/// `then` or `otherwise` list.
pub const MAX_BLOCK_STEPS: usize = 32;

/// A plan: an ordered list of steps to run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The steps, in the order they run.
    pub steps: Vec<Step>,
}

/// One step of a plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    /// Bind a planner-written literal. Its label is the planner's input label
    /// (see T3).
    Let {
        /// Name to bind.
        var: String,
        /// The literal text being bound.
        text: String,
    },
    /// Invoke a registered action. `args` are variable names, in parameter
    /// order.
    Call {
        /// Id of the registered action.
        action: u32,
        /// Argument variable names, in parameter order.
        args: Vec<String>,
    },
    /// Ask a quarantined reader to extract a value into `var` from `input`.
    Read {
        /// Name to bind the extracted value under.
        var: String,
        /// Variable to read the value from.
        input: String,
        /// Shape the extracted value must have.
        schema: Schema,
    },
    /// Run `body` once per element of the list variable `list`, at most `max`
    /// times.
    ForEach {
        /// Name to bind each list element under, inside `body`.
        var: String,
        /// Variable holding the list to iterate.
        list: String,
        /// Upper bound on iterations; `1..=MAX_LOOP`.
        max: u32,
        /// Steps to run once per element.
        body: Vec<Step>,
    },
    /// Run `then` if `var`'s bytes equal `equals`, otherwise `otherwise`.
    If {
        /// Variable whose value is tested.
        var: String,
        /// Bytes it must equal for the `then` branch.
        equals: String,
        /// Steps to run when it matches.
        then: Vec<Step>,
        /// Steps to run when it does not.
        otherwise: Vec<Step>,
    },
    /// Commit the outbox so far (approvals collected), then continue.
    Checkpoint,
}

/// The shape a [`Step::Read`] result must have.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schema {
    /// Free text, at most `max_len` bytes.
    Text {
        /// Upper bound on the result length, in bytes.
        max_len: u32,
    },
    /// One of these options. A certified reader may endorse the result to
    /// `Bounded` (T3).
    Choice {
        /// The allowed options.
        options: Vec<String>,
    },
}

/// A reason a plan could not be parsed or validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The JSON did not decode into a [`Plan`].
    Json {
        /// The underlying decode error.
        message: String,
    },
    /// A `Call` referenced an action id that is not registered.
    UnknownAction {
        /// The offending step, e.g. `steps[2]`.
        path: String,
        /// The action id that was not found.
        action: u32,
    },
    /// A `Call` passed a different number of arguments than the action's
    /// parameters.
    Arity {
        /// The offending step.
        path: String,
        /// The action id being called.
        action: u32,
        /// How many arguments the action expects.
        expected: usize,
        /// How many arguments the plan supplied.
        got: usize,
    },
    /// A step referenced a variable that is not in scope.
    UndefinedVariable {
        /// The offending step.
        path: String,
        /// The variable that is not in scope.
        var: String,
    },
    /// A step bound a variable that is already in scope.
    RebindingVariable {
        /// The offending step.
        path: String,
        /// The variable that is already bound.
        var: String,
    },
    /// A `ForEach.max` was `0` or above [`MAX_LOOP`].
    ForEachMax {
        /// The offending step.
        path: String,
        /// The out-of-bounds `max`.
        max: u32,
    },
    /// A step is nested inside more than [`MAX_DEPTH`] `ForEach`/`If` blocks.
    TooDeep {
        /// The first step past the depth limit.
        path: String,
        /// How many blocks it is nested inside.
        depth: usize,
    },
    /// A block holds more steps than its limit allows: more than
    /// [`MAX_BLOCK_STEPS`] in one block, or more than [`MAX_STEPS`] in the
    /// whole plan.
    TooManySteps {
        /// The offending block, e.g. `steps` or `steps[1].body`.
        path: String,
        /// How many steps the block has.
        count: usize,
        /// The limit that the block exceeded.
        limit: usize,
    },
    /// A `Schema::Choice` had no options or duplicated ones.
    BadChoice {
        /// The offending step.
        path: String,
        /// The offending options.
        options: Vec<String>,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Json { message } => write!(f, "plan is not valid JSON: {message}"),
            PlanError::UnknownAction { path, action } => {
                write!(f, "{path}: unknown action {action}")
            }
            PlanError::Arity { path, action, expected, got } => {
                write!(f, "{path}: action {action} takes {expected} argument(s), got {got}")
            }
            PlanError::UndefinedVariable { path, var } => {
                write!(f, "{path}: unknown variable \"{var}\"")
            }
            PlanError::RebindingVariable { path, var } => {
                write!(f, "{path}: variable \"{var}\" is already in scope; use a new name")
            }
            PlanError::ForEachMax { path, max } => {
                write!(f, "{path}: ForEach.max must be in 1..={MAX_LOOP}, got {max}")
            }
            PlanError::TooDeep { path, depth } => {
                write!(f, "{path}: loops and branches are nested {depth} deep, but the limit is {MAX_DEPTH}")
            }
            PlanError::TooManySteps { path, count, limit } => {
                write!(f, "{path}: has {count} steps, but the limit is {limit}")
            }
            PlanError::BadChoice { path, options } => {
                write!(f, "{path}: a Choice must list at least one option, each exactly once; got {options:?}")
            }
        }
    }
}

/// Parse model-produced `json` into a [`Plan`].
pub fn parse(json: &str) -> Result<Plan, PlanError> {
    serde_json::from_str(json).map_err(|e| PlanError::Json { message: e.to_string() })
}

/// Validate `plan` against `registry`. `inputs` names the variables the host
/// pre-binds for the session; those already exist, so a plan must not rebind
/// them, but it may read them.
pub fn validate(plan: &Plan, registry: &Registry, inputs: &[&str]) -> Result<(), PlanError> {
    let total = count_steps(&plan.steps);
    if total > MAX_STEPS {
        return Err(PlanError::TooManySteps { path: "plan".into(), count: total, limit: MAX_STEPS });
    }

    let mut scope: BTreeSet<String> = inputs.iter().map(|s| s.to_string()).collect();
    validate_steps(&plan.steps, registry, &mut scope, 0, "steps")
}

/// Count the total number of steps in `steps`, recursing into bodies and
/// branches, with each loop counted once (not once per element).
fn count_steps(steps: &[Step]) -> usize {
    steps
        .iter()
        .map(|s| {
            1 + match s {
                Step::ForEach { body, .. } => count_steps(body),
                Step::If { then, otherwise, .. } => count_steps(then) + count_steps(otherwise),
                _ => 0,
            }
        })
        .sum()
}

/// Walk `steps` nested inside `depth` blocks (top level is `0`), updating
/// `scope`, reporting errors relative to the `prefix` path so far. Blocks
/// are checked against a copy of `scope`, so their bindings do not escape.
fn validate_steps(
    steps: &[Step],
    registry: &Registry,
    scope: &mut BTreeSet<String>,
    depth: usize,
    prefix: &str,
) -> Result<(), PlanError> {
    if depth > MAX_DEPTH && !steps.is_empty() {
        return Err(PlanError::TooDeep { path: format!("{prefix}[0]"), depth });
    }
    if steps.len() > MAX_BLOCK_STEPS {
        return Err(PlanError::TooManySteps { path: prefix.to_string(), count: steps.len(), limit: MAX_BLOCK_STEPS });
    }

    for (i, step) in steps.iter().enumerate() {
        let path = format!("{prefix}[{i}]");

        match step {
            Step::Let { var, .. } => {
                if !scope.insert(var.clone()) {
                    return Err(PlanError::RebindingVariable { path, var: var.clone() });
                }
            }

            Step::Call { action, args } => {
                let spec = match registry.get(ActionId(*action)) {
                    Some(spec) => spec,
                    None => return Err(PlanError::UnknownAction { path, action: *action }),
                };
                if args.len() != spec.params.len() {
                    return Err(PlanError::Arity {
                        path,
                        action: *action,
                        expected: spec.params.len(),
                        got: args.len(),
                    });
                }
                for a in args {
                    if !scope.contains(a) {
                        return Err(PlanError::UndefinedVariable { path, var: a.clone() });
                    }
                }
            }

            Step::Read { var, input, schema } => {
                if !scope.contains(input) {
                    return Err(PlanError::UndefinedVariable { path, var: input.clone() });
                }
                if let Schema::Choice { options } = schema {
                    let mut seen: BTreeSet<&str> = BTreeSet::new();
                    for o in options {
                        if !seen.insert(o.as_str()) {
                            return Err(PlanError::BadChoice { path, options: options.clone() });
                        }
                    }
                    if options.is_empty() {
                        return Err(PlanError::BadChoice { path, options: options.clone() });
                    }
                }
                if !scope.insert(var.clone()) {
                    return Err(PlanError::RebindingVariable { path, var: var.clone() });
                }
            }

            Step::ForEach { var, list, max, body } => {
                if *max == 0 || *max > MAX_LOOP {
                    return Err(PlanError::ForEachMax { path, max: *max });
                }
                if !scope.contains(list) {
                    return Err(PlanError::UndefinedVariable { path, var: list.clone() });
                }
                let mut inner = scope.clone();
                if !inner.insert(var.clone()) {
                    return Err(PlanError::RebindingVariable { path, var: var.clone() });
                }
                validate_steps(body, registry, &mut inner, depth + 1, &format!("{path}.body"))?;
            }

            Step::If { var, then, otherwise, .. } => {
                if !scope.contains(var) {
                    return Err(PlanError::UndefinedVariable { path, var: var.clone() });
                }
                validate_steps(then, registry, &mut scope.clone(), depth + 1, &format!("{path}.then"))?;
                validate_steps(otherwise, registry, &mut scope.clone(), depth + 1, &format!("{path}.otherwise"))?;
            }

            Step::Checkpoint => {}
        }
    }

    Ok(())
}

/// JSON Schema for [`Plan`], for handing to Ollama as `format`.
pub const PLAN_JSON_SCHEMA: &str = r##"{
  "title": "fewshot plan",
  "type": "object",
  "required": ["steps"],
  "properties": {
    "steps": { "type": "array", "maxItems": 32, "items": { "$ref": "#/$defs/step" } }
  },
  "additionalProperties": false,
  "$defs": {
    "step": {
      "oneOf": [
        {
          "type": "object",
          "required": ["op", "var", "text"],
          "properties": {
            "op": { "const": "let" },
            "var": { "type": "string" },
            "text": { "type": "string" }
          },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": ["op", "action", "args"],
          "properties": {
            "op": { "const": "call" },
            "action": { "type": "integer", "minimum": 0 },
            "args": { "type": "array", "items": { "type": "string" } }
          },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": ["op", "var", "input", "schema"],
          "properties": {
            "op": { "const": "read" },
            "var": { "type": "string" },
            "input": { "type": "string" },
            "schema": { "$ref": "#/$defs/schema" }
          },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": ["op", "var", "list", "max", "body"],
          "properties": {
            "op": { "const": "for_each" },
            "var": { "type": "string" },
            "list": { "type": "string" },
            "max": { "type": "integer", "minimum": 1, "maximum": 64 },
            "body": { "type": "array", "maxItems": 32, "items": { "$ref": "#/$defs/step" } }
          },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": ["op", "var", "equals", "then", "otherwise"],
          "properties": {
            "op": { "const": "if" },
            "var": { "type": "string" },
            "equals": { "type": "string" },
            "then": { "type": "array", "maxItems": 32, "items": { "$ref": "#/$defs/step" } },
            "otherwise": { "type": "array", "maxItems": 32, "items": { "$ref": "#/$defs/step" } }
          },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": ["op"],
          "properties": { "op": { "const": "checkpoint" } },
          "additionalProperties": false
        }
      ]
    },
    "schema": {
      "oneOf": [
        {
          "type": "object",
          "required": ["kind", "max_len"],
          "properties": { "kind": { "const": "text" }, "max_len": { "type": "integer", "minimum": 0 } },
          "additionalProperties": false
        },
        {
          "type": "object",
          "required": ["kind", "options"],
          "properties": {
            "kind": { "const": "choice" },
            "options": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string" } }
          },
          "additionalProperties": false
        }
      ]
    }
  }
}"##;

#[cfg(test)]
mod tests {
    use super::*;
    use fewshot_gate::{ActionSpec, Effect, Param};
    use fewshot_labels::{Integrity, Secrecy};

    /// A tiny registry: `1` is a two-parameter action, `2` a one-parameter one.
    fn mk_registry() -> Registry {
        let mut r = Registry::new();
        r.register(ActionSpec {
            id: ActionId(1),
            name: "mail.send".into(),
            effect: Effect::External,
            integrity_floor: Integrity::User,
            egress_clearance: Secrecy::EMPTY,
            params: alloc::vec![Param::open("to"), Param::open("body")],
            draft_for: None,
            compensation: None,
        })
        .unwrap();
        r.register(ActionSpec {
            id: ActionId(2),
            name: "notes.append".into(),
            effect: Effect::LocalReversible,
            integrity_floor: Integrity::User,
            egress_clearance: Secrecy::EMPTY,
            params: alloc::vec![Param::open("text")],
            draft_for: None,
            compensation: None,
        })
        .unwrap();
        r
    }

    #[test]
    fn round_trip() {
        let plan = Plan {
            steps: alloc::vec![
                Step::Let { var: "x".into(), text: "hello".into() },
                Step::Call { action: 1, args: alloc::vec!["x".into(), "x".into()] },
                Step::Checkpoint,
            ],
        };
        let json = serde_json::to_string(&plan).unwrap();
        let back = parse(&json).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn rejects_unknown_action() {
        let plan = Plan { steps: alloc::vec![Step::Call { action: 99, args: alloc::vec!["a".into(), "b".into()] }] };
        let err = validate(&plan, &mk_registry(), &["a", "b"]).unwrap_err();
        assert!(matches!(err, PlanError::UnknownAction { action: 99, .. }), "{err:?}");
    }

    #[test]
    fn rejects_wrong_arity() {
        let plan = Plan {
            steps: alloc::vec![Step::Call { action: 1, args: alloc::vec!["a".into(), "b".into(), "c".into()] }],
        };
        let err = validate(&plan, &mk_registry(), &["a", "b", "c"]).unwrap_err();
        assert!(matches!(err, PlanError::Arity { expected: 2, got: 3, .. }), "{err:?}");
    }

    #[test]
    fn rejects_undefined_variable() {
        let plan = Plan { steps: alloc::vec![Step::Call { action: 1, args: alloc::vec!["a".into(), "ghost".into()] }] };
        let err = validate(&plan, &mk_registry(), &["a"]).unwrap_err();
        match &err {
            PlanError::UndefinedVariable { var, .. } => assert_eq!(var, "ghost"),
            other => panic!("expected UndefinedVariable, got {other:?}"),
        }
    }

    #[test]
    fn rejects_rebinding() {
        let plan = Plan {
            steps: alloc::vec![
                Step::Let { var: "x".into(), text: "a".into() },
                Step::Let { var: "x".into(), text: "b".into() },
            ],
        };
        match validate(&plan, &mk_registry(), &[]).unwrap_err() {
            PlanError::RebindingVariable { var, .. } => assert_eq!(var, "x"),
            other => panic!("expected RebindingVariable, got {other:?}"),
        }
    }

    #[test]
    fn rejects_rebinding_host_input() {
        let plan = Plan { steps: alloc::vec![Step::Let { var: "inbox".into(), text: "a".into() }] };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::RebindingVariable { var, .. } => assert_eq!(var, "inbox"),
            other => panic!("expected RebindingVariable, got {other:?}"),
        }
    }

    #[test]
    fn rejects_for_each_max_zero() {
        let plan = Plan {
            steps: alloc::vec![Step::ForEach { var: "e".into(), list: "inbox".into(), max: 0, body: Vec::new() }],
        };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::ForEachMax { max, .. } => assert_eq!(max, 0),
            other => panic!("expected ForEachMax, got {other:?}"),
        }
    }

    fn for_each(var: &str, list: &str, max: u32, body: Vec<Step>) -> Step {
        Step::ForEach { var: var.into(), list: list.into(), max, body }
    }

    #[test]
    fn rejects_for_each_max_above_max_loop() {
        let plan = Plan { steps: alloc::vec![for_each("e", "inbox", MAX_LOOP + 1, Vec::new())] };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::ForEachMax { max, .. } => assert_eq!(max, MAX_LOOP + 1),
            other => panic!("expected ForEachMax, got {other:?}"),
        }
    }

    #[test]
    fn accepts_for_each_max_equal_to_max_loop() {
        let plan = Plan { steps: alloc::vec![for_each("e", "inbox", MAX_LOOP, Vec::new())] };
        assert!(validate(&plan, &mk_registry(), &["inbox"]).is_ok());
    }

    /// `n` nested loops around a checkpoint, each over `inbox`.
    fn nested(n: usize) -> Step {
        (0..n).fold(Step::Checkpoint, |inner, i| for_each(&format!("i{i}"), "inbox", 1, alloc::vec![inner]))
    }

    #[test]
    fn rejects_too_deep() {
        let plan = Plan { steps: alloc::vec![nested(MAX_DEPTH + 1)] };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::TooDeep { depth, .. } => assert_eq!(depth, MAX_DEPTH + 1),
            other => panic!("expected TooDeep, got {other:?}"),
        }
    }

    #[test]
    fn accepts_max_depth() {
        let plan = Plan { steps: alloc::vec![nested(MAX_DEPTH)] };
        assert!(validate(&plan, &mk_registry(), &["inbox"]).is_ok());
    }

    #[test]
    fn loop_bindings_do_not_escape() {
        let plan = Plan {
            steps: alloc::vec![
                for_each("e", "inbox", 3, alloc::vec![Step::Let { var: "x".into(), text: "a".into() }]),
                Step::Call { action: 2, args: alloc::vec!["x".into()] },
            ],
        };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::UndefinedVariable { path, var } => assert_eq!((path.as_str(), var.as_str()), ("steps[1]", "x")),
            other => panic!("expected UndefinedVariable, got {other:?}"),
        }
    }

    #[test]
    fn loop_variable_is_scoped_to_the_body() {
        let plan = Plan {
            steps: alloc::vec![
                for_each("e", "inbox", 3, alloc::vec![Step::Call { action: 2, args: alloc::vec!["e".into()] }]),
                Step::Call { action: 2, args: alloc::vec!["e".into()] },
            ],
        };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::UndefinedVariable { path, .. } => assert_eq!(path, "steps[1]"),
            other => panic!("expected UndefinedVariable, got {other:?}"),
        }
    }

    #[test]
    fn sibling_blocks_may_reuse_names() {
        let body = || alloc::vec![Step::Let { var: "x".into(), text: "a".into() }];
        let plan = Plan {
            steps: alloc::vec![
                for_each("e", "inbox", 3, body()),
                for_each("e", "inbox", 3, body()),
                Step::If { var: "inbox".into(), equals: "".into(), then: body(), otherwise: body() },
            ],
        };
        assert_eq!(validate(&plan, &mk_registry(), &["inbox"]), Ok(()));
    }

    #[test]
    fn branch_bindings_do_not_escape() {
        let plan = Plan {
            steps: alloc::vec![
                Step::If {
                    var: "inbox".into(),
                    equals: "".into(),
                    then: alloc::vec![Step::Let { var: "x".into(), text: "a".into() }],
                    otherwise: Vec::new(),
                },
                Step::Call { action: 2, args: alloc::vec!["x".into()] },
            ],
        };
        assert!(matches!(validate(&plan, &mk_registry(), &["inbox"]), Err(PlanError::UndefinedVariable { .. })));
    }

    #[test]
    fn blocks_may_not_shadow() {
        let plan = Plan {
            steps: alloc::vec![Step::Let { var: "x".into(), text: "a".into() }, for_each("x", "inbox", 3, Vec::new()),],
        };
        assert!(matches!(validate(&plan, &mk_registry(), &["inbox"]), Err(PlanError::RebindingVariable { .. })));
    }

    #[test]
    fn json_schema_is_valid_json_and_matches_the_wire_format() {
        let schema: serde_json::Value = serde_json::from_str(PLAN_JSON_SCHEMA).unwrap();
        let ops = schema["$defs"]["step"]["oneOf"].as_array().unwrap();
        let names: Vec<&str> = ops.iter().map(|o| o["properties"]["op"]["const"].as_str().unwrap()).collect();
        assert_eq!(names, ["let", "call", "read", "for_each", "if", "checkpoint"]);
        assert_eq!(schema["$defs"]["step"]["oneOf"][3]["properties"]["max"]["maximum"], MAX_LOOP);
        assert_eq!(schema["properties"]["steps"]["maxItems"], MAX_BLOCK_STEPS);
        assert_eq!(schema["$defs"]["step"]["oneOf"][3]["properties"]["body"]["maxItems"], MAX_BLOCK_STEPS);
        assert_eq!(schema["$defs"]["step"]["oneOf"][4]["properties"]["then"]["maxItems"], MAX_BLOCK_STEPS);
        assert_eq!(schema["$defs"]["step"]["oneOf"][4]["properties"]["otherwise"]["maxItems"], MAX_BLOCK_STEPS);
        let sample = Plan {
            steps: alloc::vec![
                Step::Read {
                    var: "r".into(),
                    input: "inbox".into(),
                    schema: Schema::Choice { options: alloc::vec!["a".into()] }
                },
                for_each("e", "inbox", 2, alloc::vec![Step::Checkpoint]),
                Step::If { var: "r".into(), equals: "a".into(), then: Vec::new(), otherwise: Vec::new() },
            ],
        };
        let json = serde_json::to_value(&sample).unwrap();
        assert_eq!(json["steps"][1]["op"], "for_each");
        assert_eq!(json["steps"][0]["schema"]["kind"], "choice");
    }

    #[test]
    fn rejects_more_than_32_steps_in_one_block() {
        let steps = (0..MAX_BLOCK_STEPS + 1).map(|_| Step::Checkpoint).collect();
        let plan = Plan { steps };
        match validate(&plan, &mk_registry(), &[]).unwrap_err() {
            PlanError::TooManySteps { path, count, limit } => {
                assert_eq!(path, "steps");
                assert_eq!(count, MAX_BLOCK_STEPS + 1);
                assert_eq!(limit, MAX_BLOCK_STEPS);
            }
            other => panic!("expected TooManySteps, got {other:?}"),
        }
    }

    #[test]
    fn accepts_32_steps_in_one_block() {
        let steps = (0..MAX_BLOCK_STEPS).map(|_| Step::Checkpoint).collect();
        let plan = Plan { steps };
        assert!(validate(&plan, &mk_registry(), &[]).is_ok());
    }

    #[test]
    fn rejects_more_than_32_steps_in_a_nested_block() {
        let body = (0..MAX_BLOCK_STEPS + 1).map(|_| Step::Checkpoint).collect();
        let plan = Plan { steps: alloc::vec![for_each("e", "inbox", 1, body)] };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::TooManySteps { path, count, limit } => {
                assert_eq!(path, "steps[0].body");
                assert_eq!(count, MAX_BLOCK_STEPS + 1);
                assert_eq!(limit, MAX_BLOCK_STEPS);
            }
            other => panic!("expected TooManySteps, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_choice() {
        let plan = Plan {
            steps: alloc::vec![Step::Read {
                var: "r".into(),
                input: "inbox".into(),
                schema: Schema::Choice { options: Vec::new() }
            }],
        };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::BadChoice { .. } => {}
            other => panic!("expected BadChoice, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_choice() {
        let plan = Plan {
            steps: alloc::vec![Step::Read {
                var: "r".into(),
                input: "inbox".into(),
                schema: Schema::Choice { options: alloc::vec!["a".into(), "b".into(), "a".into()] },
            }],
        };
        match validate(&plan, &mk_registry(), &["inbox"]).unwrap_err() {
            PlanError::BadChoice { .. } => {}
            other => panic!("expected BadChoice, got {other:?}"),
        }
    }

    #[test]
    fn parses_rejects_garbage() {
        match parse("definitely not json").unwrap_err() {
            PlanError::Json { .. } => {}
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn error_message_names_the_step_path() {
        // steps[1] is a ForEach whose body[0] calls an unknown variable.
        let plan = Plan {
            steps: alloc::vec![
                Step::Checkpoint,
                Step::ForEach {
                    var: "e".into(),
                    list: "inbox".into(),
                    max: 1,
                    body: alloc::vec![Step::Call { action: 1, args: alloc::vec!["nope".into(), "also".into()] }],
                },
            ],
        };
        let err = validate(&plan, &mk_registry(), &["inbox"]).unwrap_err();
        assert!(err.to_string().starts_with("steps[1].body[0]: "), "{}", err.to_string());
    }

    // --- property tests: validate never panics on arbitrary plans ---

    use proptest::prelude::*;
    use proptest::string::string_regex;

    /// A small random identifier: one to three lowercase alphanumerics.
    fn arb_ident() -> impl Strategy<Value = String> {
        string_regex("[a-z][a-z0-9]{0,2}").unwrap()
    }

    fn arb_schema() -> impl Strategy<Value = Schema> {
        prop_oneof![
            any::<u32>().prop_map(|max_len| Schema::Text { max_len }),
            proptest::collection::vec(any::<String>(), 0..=4).prop_map(|options| Schema::Choice { options }),
        ]
    }

    /// A step with at most `depth` further levels of nesting below it.
    fn arb_step(depth: usize) -> BoxedStrategy<Step> {
        let leaves: BoxedStrategy<Step> = prop_oneof![
            (arb_ident(), any::<String>()).prop_map(|(var, text)| Step::Let { var, text }),
            (any::<u32>(), proptest::collection::vec(any::<String>(), 0..=3))
                .prop_map(|(action, args)| Step::Call { action, args }),
            (arb_ident(), any::<String>(), arb_schema()).prop_map(|(var, input, schema)| Step::Read {
                var,
                input,
                schema
            }),
            Just(Step::Checkpoint),
        ]
        .boxed();

        if depth == 0 {
            leaves
        } else {
            prop_oneof![
                leaves,
                (arb_ident(), any::<String>(), any::<u32>(), proptest::collection::vec(arb_step(depth - 1), 0..=2))
                    .prop_map(|(var, list, max, body)| Step::ForEach { var, list, max, body }),
                (
                    arb_ident(),
                    any::<String>(),
                    proptest::collection::vec(arb_step(depth - 1), 0..=2),
                    proptest::collection::vec(arb_step(depth - 1), 0..=2)
                )
                    .prop_map(|(var, equals, then, otherwise)| Step::If {
                        var,
                        equals,
                        then,
                        otherwise
                    }),
            ]
            .boxed()
        }
    }

    proptest! {
        #[test]
        fn validate_never_panics(plan in proptest::collection::vec(arb_step(4), 0..=4).prop_map(|steps| Plan { steps })) {
            let _ = validate(&plan, &mk_registry(), &[]);
        }
    }
}
